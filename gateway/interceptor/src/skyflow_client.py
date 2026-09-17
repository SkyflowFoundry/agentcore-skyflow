"""Synchronous Skyflow Detect client, stdlib only.

Ported from the Context Forge plugin's async httpx client. Lambda handlers are
synchronous and the interceptor ships without third-party dependencies, so this
uses urllib.request with the same retry/backoff behaviour.

Endpoints:
    POST {vault_url}/v1/detect/deidentify/string
    POST {vault_url}/v1/detect/reidentify/string
    POST {vault_url}/v2/detect/deidentify/file
    GET  {vault_url}/v2/detect/runs/{run_id}?vaultId=...

The file endpoints are v2 because only v2 accepts `dataSource: PRESIGNED_URL`.
That is what lets a signed URL from S3 or Box be handed straight to Skyflow:
the file bytes never pass through this Lambda, so neither the 6 MB synchronous
invocation limit nor the payload size of the object applies. v2 is in beta and
feature-flagged per vault.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = (429, 500, 502, 503, 504)

#: File formats for which `VAULT_TOKEN` de-identification is supported, per the
#: Detect v2 spec. Every other format — notably PDF, images and audio — can only
#: be de-identified one way, so a re-identify round trip is impossible for them.
VAULT_TOKEN_FORMATS = frozenset(
    {"txt", "json", "csv", "xml", "jsonl", "docx", "xlsx", "pptx"}
)

#: Terminal run states. QUEUED and IN_PROGRESS mean keep polling.
RUN_SUCCESS = "SUCCESS"
RUN_FAILED = "FAILED"
RUN_TERMINAL = frozenset({RUN_SUCCESS, RUN_FAILED, "UNKNOWN"})


class SkyflowError(RuntimeError):
    """Non-retryable Skyflow API failure, or retries exhausted."""


@dataclass(frozen=True)
class DeidentifyResult:
    processed_text: str
    entities: list[dict[str, Any]]


@dataclass(frozen=True)
class ReidentifyResult:
    text: str


@dataclass(frozen=True)
class FileOutput:
    """One output artifact of a file run: a URL, plus what it is."""

    url: str
    file_type: str
    extension: str


@dataclass(frozen=True)
class FileRunResult:
    status: str
    outputs: tuple[FileOutput, ...] = ()
    message: str = ""

    @property
    def is_terminal(self) -> bool:
        return self.status in RUN_TERMINAL

    @property
    def succeeded(self) -> bool:
        return self.status == RUN_SUCCESS

    def first_document(self) -> FileOutput | None:
        """The de-identified file itself.

        A run also returns entity metadata as separate JSON outputs; those are
        not the document and must not be swapped in for it.
        """
        for output in self.outputs:
            if output.extension != "json" or "ENTIT" not in output.file_type.upper():
                return output
        return None


class RunTimeout(SkyflowError):
    """The run did not reach a terminal state inside the caller's deadline."""


def build_file_configuration(
    entity_types: tuple[str, ...] | list[str] = (),
    token_type: str = "counter",
    data_format: str = "",
) -> dict[str, Any]:
    """A minimal inline Detect configuration.

    Used when the policy names no `fileConfiguration` of its own. Vault tokens
    are only requested for formats that accept them — asking for VAULT_TOKEN on
    a PDF is rejected by the API — so this downgrades to counters rather than
    sending a request that cannot succeed.

    The interceptor never re-identifies a file: this is a one-way transform
    applied before the agent sees the document. Vault tokens are still worth
    requesting where supported, because they leave the original recoverable out
    of band by someone with vault permissions.
    """
    reversible = token_type == "vault_token" and data_format in VAULT_TOKEN_FORMATS
    deidentification = "VAULT_TOKEN" if reversible else "ENTITY_UNIQUE_COUNTER"
    # v2 spells entity types in upper case; the string API and our policy use
    # lower case.
    types = [e.upper() for e in entity_types] or ["ALL"]
    return {
        "detect": {
            "entities": [
                {"entityType": t, "deidentificationType": deidentification}
                for t in types
            ]
        }
    }


class SkyflowClient:
    """Thin client over the Detect string endpoints.

    `api_key` is a long-lived Skyflow API key, sent as a bearer token.
    """

    def __init__(
        self,
        vault_url: str,
        vault_id: str,
        api_key: str,
        timeout_seconds: float = 5.0,
        max_retries: int = 2,
        backoff_initial_ms: int = 100,
    ) -> None:
        self._vault_url = vault_url.rstrip("/")
        self._vault_id = vault_id
        self._api_key = api_key
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._backoff_initial_ms = backoff_initial_ms

    def deidentify(
        self,
        text: str,
        entity_types: tuple[str, ...] | list[str],
        vault_token_entity_types: tuple[str, ...] | list[str] | None = None,
    ) -> DeidentifyResult:
        body: dict[str, Any] = {"text": text, "vault_id": self._vault_id}
        if entity_types:
            body["entity_types"] = list(entity_types)
        if vault_token_entity_types:
            # Persisted, restorable tokens. Omitted entirely for counter tokens,
            # which are the API default and cannot be re-identified.
            body["token_type"] = {"vault_token": list(vault_token_entity_types)}

        data = self._post("/v1/detect/deidentify/string", body)
        return DeidentifyResult(
            processed_text=data.get("processed_text", text),
            entities=data.get("entities", []),
        )

    def reidentify(self, text: str) -> ReidentifyResult:
        body = {"text": text, "vault_id": self._vault_id}
        data = self._post("/v1/detect/reidentify/string", body)
        return ReidentifyResult(text=data.get("text", text))

    # ------------------------------------------------------------ files (v2)

    def deidentify_file_url(
        self,
        file_url: str,
        data_format: str,
        configuration: dict[str, Any],
    ) -> str:
        """Submit a signed URL for de-identification. Returns a run id.

        Skyflow fetches the file itself, so the URL must still be valid when it
        does — a short presigned expiry is the likeliest cause of a failed run.

        `configuration` is an inline Detect configuration, passed through
        essentially as given so the policy can express any Detect option
        without this client modelling each one. Configurations are deliberately
        inline rather than referenced by `configurationId`: a vault-stored
        config would have to be updated and rolled out separately from the code
        and policy that depend on it.
        """
        body: dict[str, Any] = {
            "dataSource": "PRESIGNED_URL",
            "value": file_url,
            "dataFormat": data_format,
            "configuration": {"vaultId": self._vault_id, **configuration},
        }

        data = self._post("/v2/detect/deidentify/file", body)
        run_id = data.get("runId")
        if not run_id:
            raise SkyflowError("Skyflow accepted the file but returned no runId")
        return run_id

    def get_run(self, run_id: str) -> FileRunResult:
        """Current state of a file run."""
        path = f"/v2/detect/runs/{urllib.parse.quote(run_id, safe='')}"
        query = urllib.parse.urlencode({"vaultId": self._vault_id})
        data = self._get(f"{path}?{query}")
        outputs = tuple(
            FileOutput(
                url=item.get("processedFile", ""),
                file_type=item.get("processedFileType", "") or "",
                extension=item.get("processedFileExtension", "") or "",
            )
            for item in data.get("output") or []
            if item.get("processedFile")
        )
        return FileRunResult(
            status=(data.get("status") or "UNKNOWN").upper(),
            outputs=outputs,
            message=data.get("message", "") or "",
        )

    def wait_for_run(
        self,
        run_id: str,
        seconds_remaining,
        reserve_seconds: float = 3.0,
        poll_initial_seconds: float = 0.5,
        poll_max_seconds: float = 3.0,
    ) -> FileRunResult:
        """Poll until the run finishes or the caller's budget runs out.

        `seconds_remaining` is a callable returning how long the caller still
        has — in Lambda, `context.get_remaining_time_in_millis() / 1000`. The
        budget belongs to the caller rather than to a fixed timeout here,
        because the real ceiling is the gateway's interceptor deadline, which
        AWS does not publish. `reserve_seconds` keeps back enough time to still
        return a response instead of being killed mid-flight.
        """
        interval = poll_initial_seconds
        while True:
            result = self.get_run(run_id)
            if result.is_terminal:
                return result

            budget = seconds_remaining() - reserve_seconds
            if budget <= interval:
                raise RunTimeout(
                    f"Skyflow run {run_id} still {result.status} with {budget:.1f}s left"
                )
            time.sleep(interval)
            interval = min(interval * 2, poll_max_seconds)

    # ----------------------------------------------------------------- http

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", path, body)

    def _get(self, path: str) -> dict[str, Any]:
        return self._request("GET", path, None)

    def _request(self, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        url = f"{self._vault_url}{path}"
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        attempts = self._max_retries + 1
        backoff_ms = self._backoff_initial_ms
        last_error: str | None = None

        for attempt in range(1, attempts + 1):
            req = urllib.request.Request(
                url,
                data=payload,
                method=method,
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                if exc.code in RETRYABLE_STATUS and attempt < attempts:
                    last_error = str(exc.code)
                    logger.warning(
                        "skyflow_retryable_status path=%s status=%d attempt=%d/%d",
                        path, exc.code, attempt, attempts,
                    )
                else:
                    # The error body is deliberately not logged or attached: it can
                    # echo the submitted text, which is the sensitive data itself.
                    raise SkyflowError(f"Skyflow {path} failed with status {exc.code}") from exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = repr(exc)
                logger.warning(
                    "skyflow_request_error path=%s attempt=%d/%d err=%s",
                    path, attempt, attempts, exc,
                )

            if attempt < attempts:
                time.sleep(backoff_ms / 1000.0)
                backoff_ms *= 2

        raise SkyflowError(f"Skyflow {path} exhausted retries: {last_error}")
