"""Synchronous Skyflow Detect client, stdlib only.

Ported from the Context Forge plugin's async httpx client. Lambda handlers are
synchronous and the interceptor ships without third-party dependencies, so this
uses urllib.request with the same retry/backoff behaviour.

Endpoints:
    POST {vault_url}/v1/detect/deidentify/string
    POST {vault_url}/v1/detect/reidentify/string
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

RETRYABLE_STATUS = (429, 500, 502, 503, 504)


class SkyflowError(RuntimeError):
    """Non-retryable Skyflow API failure, or retries exhausted."""


@dataclass(frozen=True)
class DeidentifyResult:
    processed_text: str
    entities: list[dict[str, Any]]


@dataclass(frozen=True)
class ReidentifyResult:
    text: str


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

    def _post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._vault_url}{path}"
        payload = json.dumps(body).encode("utf-8")
        attempts = self._max_retries + 1
        backoff_ms = self._backoff_initial_ms
        last_error: str | None = None

        for attempt in range(1, attempts + 1):
            req = urllib.request.Request(
                url,
                data=payload,
                method="POST",
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
