"""Shield the model: keep sensitive data out of what a model reads, and restore it in what it writes.

Inference targets reach the interceptor as HTTP payloads. A request carries its
path and a base64 body. A response carries a base64 body and no request at
all, because the gateway sends `gatewayRequest: null` on the way back. This
module handles the calls it understands and leaves everything else to the
`httpPayloads` setting.

| Path | Request | Answer |
| --- | --- | --- |
| `/v1/messages` (Anthropic Messages) | de-identified | re-identified, JSON or buffered stream |
| `/v1/messages/count_tokens` | de-identified | passed, it is a count |
| `/model/{id}/invoke` (Bedrock, Anthropic body) | de-identified | re-identified |
| `/model/{id}/invoke-with-response-stream` | de-identified | refused when the rule re-identifies, because the binary event stream is not parsed yet |
| `/v1/chat/completions` (OpenAI Chat Completions) | de-identified | re-identified, JSON or buffered stream |
| `/v1/responses` (OpenAI Responses) | de-identified | re-identified, JSON or buffered stream |
| `/v1/models` | passed | passed |
| any other `/v1/...` or `/model/...` path | refused | |

Paths arrive without the `/inference` prefix the client used, and a model id
arrives decoded, so an inference-profile ARN in an InvokeModel path carries a
`/` of its own. InvokeModel bodies are read only in Anthropic's shape. Another
model family's body, such as Llama's `prompt`, is refused rather than passed
on unread.

What the request side de-identifies is chosen by the rule's `request.parts`:
the system prompt, user and assistant turns, earlier tool calls, tool results
and attached documents and images. `model_formats` knows where each part sits
in each API's body and in each kind of answer. This module does the Skyflow
side: de-identifying what it finds, minting and recording tokens, and
restoring them in the answer.

The request side then writes a record under the gateway's `REQUEST_ID` (see
`records`) so the response side can apply the same rule and, with
`response.only: minted_for_request`, restore only the tokens this call minted.
It writes one for a refused call too, because the gateway still invokes the
response side, and without a record `httpPayloads` would replace the refusal.

The gateway buffers every inference answer before the interceptor sees it, so
a stream arrives whole and is restored in one pass.
"""

from __future__ import annotations

import base64
import copy
import json
import logging
import re
import threading
import time
import urllib.parse
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Any, Callable

import model_formats as formats
import payload as payload_utils
import settings
from model_formats import SYSTEM_NOTE, TOKEN, Refused, UnreadableAnswer  # noqa: F401 - re-exported
from policy import InferenceRule, PolicySet
from records import CallRecord, request_id
from skyflow_client import SkyflowClient, SkyflowError, build_file_configuration

logger = logging.getLogger(__name__)

OUTPUT_VERSION = "1.0"

MAX_PARALLEL_CALLS = 8
#: Seconds kept back from the Lambda budget while an attachment's run polls.
FILE_RESERVE_SECONDS = 5.0
NO_CONTEXT_BUDGET_SECONDS = 60.0

#: Largest de-identified request body, base64 encoded, that is handed back to
#: the gateway. Lambda returns at most 6 MB and the body sits inside a JSON
#: envelope, so a larger one is refused here rather than failing the Lambda.
MAX_TRANSFORMED_BODY = 5 * 1024 * 1024

#: Attachment media type to Detect `dataFormat`.
MEDIA_FORMATS = {
    "application/pdf": "pdf",
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/gif": "gif",
    "image/bmp": "bmp",
    "image/tiff": "tiff",
    "text/plain": "txt",
    "text/csv": "csv",
    "application/json": "json",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "pptx",
}
#: Formats decoded and de-identified as a string, which keeps vault tokens and
#: so lets the answer be re-identified. Every other format goes through
#: Detect's file API one way: tokens that cannot be restored, or redacted
#: regions in an image.
TEXT_FORMATS = frozenset({"txt", "csv", "json"})
#: Detect's output extension to the media type the provider expects. Built by
#: hand because `image/jpg` and `image/jpeg` share a format and the provider
#: accepts only `image/jpeg`.
MEDIA_BY_EXTENSION = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "tif": "image/tiff",
    "tiff": "image/tiff",
}

#: A decoded model id can hold a `/`, as an inference-profile ARN does.
_INVOKE = re.compile(r"^/model/(?P<model>.+)/(?P<op>invoke|invoke-with-response-stream)$")


@dataclass(frozen=True)
class Call:
    """A recognised inference call: what kind it is and which model it names."""

    kind: str
    model: str = ""

    @property
    def reads_answers(self) -> bool:
        """Whether the answer is model text that `response` rules apply to."""
        return self.kind in ("messages", "invoke", "chat", "responses")


# ------------------------------------------------------------------ routing


def classify(path: str, body: Any) -> Call | None:
    """The inference call a request path names, or None when it is not one."""
    path = (path or "").split("?", 1)[0].rstrip("/")
    if path.startswith("/inference/"):
        path = path[len("/inference"):]
    model = body.get("model", "") if isinstance(body, dict) else ""
    if path == "/v1/messages":
        return Call("messages", str(model))
    if path == "/v1/messages/count_tokens":
        return Call("count_tokens", str(model))
    if path == "/v1/models" or path.startswith("/v1/models/"):
        return Call("models")
    if path == "/v1/chat/completions":
        return Call("chat", str(model))
    if path == "/v1/responses":
        return Call("responses", str(model))
    match = _INVOKE.match(path)
    if match:
        kind = "invoke" if match.group("op") == "invoke" else "invoke_stream"
        return Call(kind, urllib.parse.unquote(match.group("model")))
    # Batches, files, legacy completions, Converse and whatever the gateway
    # adds next all carry model input this module does not read. They must not
    # fall through to `httpPayloads`, where `passthrough` would send them on.
    if path.startswith("/model/"):
        return Call("invoke_unsupported")
    if path.startswith("/v1/"):
        return Call("unsupported")
    return None


def handle(http: dict, direction: str, policy_set: PolicySet, context) -> dict | None:
    """Handle an HTTP event that is inference traffic, or return None to leave it alone."""
    try:
        if direction == "request":
            return _on_request(http.get("gatewayRequest") or {}, policy_set, context)
        return _on_response(http.get("gatewayResponse") or {}, context)
    except Exception as exc:  # noqa: BLE001 - a bug must refuse the call, not fail the Lambda
        # Only the type is logged, because an exception's message can quote
        # the body it choked on.
        logger.error("inference_fail_closed direction=%s reason=internal_error err=%s", direction, type(exc).__name__)
        kind = "messages"
        if direction == "request":
            call = classify((http.get("gatewayRequest") or {}).get("path") or "", None)
            kind = call.kind if call else kind
            _record_refusal(context, kind)
        return refusal(kind, "The interceptor could not process the model call, so it was blocked.", 502)


def _record_refusal(context, kind: str) -> None:
    """Record a refusal that came from an error, so the answer side lets it through as written."""
    try:
        store, rid = settings.record_store(), request_id(context)
        if store is not None and rid is not None:
            store.put(rid, CallRecord(kind=kind))
    except Exception as exc:  # noqa: BLE001 - the call is refused either way
        logger.error("inference_record_write_failed kind=%s err=%s", kind, type(exc).__name__)


# ------------------------------------------------------------- request side


def _on_request(request: dict, policy_set: PolicySet, context) -> dict | None:
    raw = request.get("body")
    body = None
    if raw:
        try:
            body = json.loads(base64.b64decode(raw))
        except ValueError:
            body = None
    call = classify(request.get("path") or "", body)
    if call is None:
        return None

    store = settings.record_store()
    rid = request_id(context)
    if store is None or rid is None:
        reason = "no_record_table" if store is None else "no_request_id"
        logger.error("inference_blocked kind=%s reason=%s", call.kind, reason)
        return refusal(call.kind, "Shield the model is not set up on this gateway, so the model call was blocked.", 403)

    def refuse(message: str, status: int) -> dict:
        return _refuse(store, rid, call, message, status)

    if call.kind in ("unsupported", "invoke_unsupported"):
        logger.warning("inference_blocked kind=%s reason=unknown_path", call.kind)
        return refuse("Shield the model does not recognise this model API path, so the call was blocked.", 403)

    if call.kind == "models":
        return _remember(store, rid, CallRecord(kind="models"), call) or passthrough()

    rule = policy_set.resolve_inference(call.model)
    if rule is None:
        logger.warning("inference_blocked kind=%s model=%s reason=no_rule", call.kind, call.model)
        return refuse("No shield-the-model rule covers this model, so the call was blocked.", 403)
    if call.kind == "invoke_stream" and rule.response.action == "reidentify":
        logger.warning("inference_blocked kind=%s model=%s reason=stream_not_supported", call.kind, call.model)
        return refuse(
            "Streamed InvokeModel answers cannot be re-identified yet. Use InvokeModel without "
            "streaming or the Anthropic Messages API, which can stream.",
            403,
        )

    record = CallRecord(
        kind=call.kind,
        response_action=rule.response.action if call.reads_answers else "none",
        response_parts=rule.response.parts,
        response_only=rule.response.only,
        on_error=rule.failure.on_error,
    )
    if rule.request.action == "none":
        logger.info("inference_request kind=%s model=%s action=none", call.kind, call.model)
        return _remember(store, rid, record, call) or passthrough()
    if not isinstance(body, dict):
        return refuse("The model request body is not a JSON object.", 400)
    if (rule.response.action == "reidentify" and rule.response.only == "minted_for_request"
            and formats.continues_stored_conversation(body)):
        # The earlier turns live with the provider and pass through here no
        # more, so this call mints nothing and its answer could restore none
        # of their tokens.
        logger.warning("inference_blocked kind=%s model=%s reason=stored_conversation", call.kind, call.model)
        return refuse(
            "Shield the model restores only the tokens a call mints, and a call that continues a stored "
            "conversation mints none for its earlier turns. Send the whole conversation in input instead.",
            403,
        )
    if not formats.readable(call.kind, body):
        logger.warning("inference_blocked kind=%s model=%s reason=body_unreadable", call.kind, call.model)
        return refuse(
            "Shield the model cannot read this request body. InvokeModel bodies are read only in "
            "Anthropic's shape, so the model call was blocked.",
            403,
        )

    try:
        new_body, minted, stats = deidentify_request(body, rule, settings.build_client(), context, call.kind)
    except Refused as exc:
        logger.warning("inference_blocked kind=%s model=%s reason=%s", call.kind, call.model, exc)
        return refuse(f"{exc}, so the model call was blocked.", 403)
    except SkyflowError as exc:
        # Only a Skyflow failure is the failure mode's to decide. Anything else
        # is a bug or a body this module misread, and passing the original on
        # would forward exactly what it failed to inspect.
        if rule.failure.on_error == "fail_open":
            logger.warning("inference_fail_open direction=request kind=%s model=%s err=%s", call.kind, call.model, exc)
            return _remember(store, rid, record, call) or passthrough()
        logger.error("inference_fail_closed direction=request kind=%s model=%s err=%s", call.kind, call.model, exc)
        return refuse("Sensitive-data processing failed, so the model call was blocked.", 502)

    encoded = base64.b64encode(json.dumps(new_body).encode("utf-8")).decode()
    if len(encoded) > MAX_TRANSFORMED_BODY:
        logger.warning("inference_blocked kind=%s model=%s reason=too_large bytes=%d", call.kind, call.model, len(encoded))
        return refuse("The de-identified model request is too large to hand back to the gateway.", 413)
    blocked = _remember(store, rid, replace(record, tokens=frozenset(minted)), call)
    if blocked:
        return blocked
    logger.info(
        "inference_request_transformed kind=%s model=%s strings=%d files=%d tokens=%d",
        call.kind, call.model, stats["strings"], stats["files"], len(minted),
    )
    return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {"transformedGatewayRequest": {"body": encoded}}}


def _refuse(store, rid: str, call: Call, message: str, status: int) -> dict:
    """Refuse the call and record that its answer is the refusal itself.

    The gateway still invokes the RESPONSE interceptor after the request side
    has answered. Without a record that answer would be left to
    `httpPayloads`, whose block replaces the refusal and its status with its
    own, so the caller would never see why. The record does nothing, which
    lets the refusal through as written. It holds no user data.
    """
    try:
        store.put(rid, CallRecord(kind=call.kind))
    except Exception as exc:  # noqa: BLE001 - the call is refused either way
        logger.error("inference_record_write_failed kind=%s err=%s", call.kind, type(exc).__name__)
    return refusal(call.kind, message, status)


def _remember(store, rid: str, record: CallRecord, call: Call) -> dict | None:
    """Write the call's record, or return the refusal when it cannot be written.

    Without a record the answer would be blocked anyway, after the model had
    run, so refusing now saves the model call.
    """
    try:
        store.put(rid, record)
    except Exception as exc:  # noqa: BLE001 - any storage failure means no record
        logger.error("inference_fail_closed direction=request kind=%s reason=record_write_failed err=%s",
                     call.kind, type(exc).__name__)
        return refusal(call.kind, "The interceptor could not record the model call, so it was blocked.", 503)
    return None


def deidentify_request(body: dict, rule: InferenceRule, client: SkyflowClient, context=None, kind: str = "messages"):
    """De-identify the parts of a request body that the rule names.

    `kind` is the call kind, which says which API's format the body is in.
    Returns `(new_body, minted_tokens, stats)`. The body is copied, never
    changed in place.
    """
    body = copy.deepcopy(body)
    found = formats.collect(kind, body, set(rule.request.parts))
    # Every attachment is checked before anything is sent to Skyflow, so a call
    # that will be refused for one of them mints no tokens first.
    checked = [(ref, _check_attachment(ref.source, ref.part, rule)) for ref in found.files]
    deidentifier = _Deidentifier(client, rule)

    # Each distinct string is sent once, in parallel, whatever its position.
    # A conversation repeats itself turn after turn, so this and the cache
    # are what keep a long history cheap.
    slots: list[tuple[Any, Any, str]] = []
    for holder, key in found.texts:
        value = holder.get(key)
        if isinstance(value, str) and rule.scope.value_eligible(value):
            slots.append((holder, key, value))
    trees = list(found.trees)
    # OpenAI tool-call arguments are JSON inside a string. They are parsed so
    # the scope's key globs apply, and written back as JSON once done. A string
    # that is not JSON is de-identified as text.
    encoded: list[tuple[Any, Any, dict]] = []
    for holder, key in found.json_strings:
        try:
            parsed = json.loads(holder[key])
        except ValueError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            wrapper = {key: parsed}
            encoded.append((holder, key, wrapper))
            trees.append((wrapper, key))
        elif rule.scope.value_eligible(holder[key]):
            slots.append((holder, key, holder[key]))
    for holder, key in trees:
        for path, value in payload_utils.collect_strings({key: holder[key]}, rule.scope):
            container = holder
            for step in path[:-1]:
                container = container[step]
            slots.append((container, path[-1], value))

    distinct = list(dict.fromkeys(value for _, _, value in slots))
    results = _parallel(deidentifier.text, distinct)
    minted: set[str] = set()
    for (processed, new_tokens) in results.values():
        minted |= new_tokens
    for holder, key, value in slots:
        holder[key] = results[value][0]
    for holder, key, wrapper in encoded:
        holder[key] = json.dumps(wrapper[key])

    for ref, attachment in checked:
        minted |= _deidentify_file(ref.source, ref.part, attachment, rule, client, deidentifier, context)
        if ref.commit is not None:
            ref.commit(ref.source)

    # Tokens minted inside a base64 attachment cannot be seen in the body, so
    # the minted set counts as well as tokens an earlier turn carried in.
    if rule.request.system_note and (
        minted or TOKEN.search(json.dumps(body)) or formats.continues_stored_conversation(body)
    ):
        formats.add_system_note(kind, body)

    return body, minted, {"strings": len(distinct), "files": len(checked)}


@dataclass(frozen=True)
class _Attachment:
    media: str
    data_format: str
    raw: bytes


def _check_attachment(source: dict, part: str, rule: InferenceRule) -> _Attachment:
    """Refuse an attachment that cannot be de-identified, before any Skyflow call."""
    media = str(source.get("media_type") or "").lower()
    data_format = MEDIA_FORMATS.get(media)
    if data_format is None:
        raise Refused(f"An attached {part} of type {media or 'unknown'} cannot be de-identified")
    data = source.get("data")
    if not isinstance(data, str):
        raise Refused(f"An attached {part} has no base64 data")
    try:
        raw = base64.b64decode(data, validate=True)
    except ValueError as exc:
        raise Refused(f"An attached {part} is not valid base64") from exc
    limit = rule.attachments.max_bytes
    if len(raw) > limit:
        raise Refused(f"An attached {part} is {len(raw)} bytes, over the {limit}-byte attachment limit")
    if data_format in TEXT_FORMATS:
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Refused(f"An attached {part} says it is text but is not UTF-8") from exc
    return _Attachment(media, data_format, raw)


def _deidentify_file(source: dict, part: str, attachment: _Attachment, rule: InferenceRule, client,
                     deidentifier, context) -> set[str]:
    """De-identify one checked base64 attachment in place. Returns the tokens it minted."""
    if attachment.data_format in TEXT_FORMATS:
        processed, minted = deidentifier.text(attachment.raw.decode("utf-8"))
        source["data"] = base64.b64encode(processed.encode("utf-8")).decode()
        return set(minted)

    # One way. Counter tokens take no vault destination, and PDFs and images
    # cannot carry vault tokens at all.
    data_format = attachment.data_format
    configuration = build_file_configuration(rule.entities, "counter", data_format)
    run_id = client.deidentify_file_base64(source["data"], data_format, configuration)
    logger.info("inference_file_submitted part=%s format=%s run_id=%s", part, data_format, run_id)
    run = client.wait_for_run(run_id, _remaining_seconds(context), reserve_seconds=FILE_RESERVE_SECONDS)
    if not run.succeeded:
        raise SkyflowError(f"Skyflow file run {run_id} ended {run.status}: {run.message}")
    output = run.first_document()
    if output is None:
        raise SkyflowError(f"Skyflow file run {run_id} returned no file")
    # The de-identified file is held to the same limit as the original, so a
    # request that fitted in the Lambda's 6 MB on the way in fits on the way out.
    content = client.processed_file_bytes(run, output, max_bytes=rule.attachments.max_bytes)
    source["data"] = base64.b64encode(content).decode()
    returned = MEDIA_BY_EXTENSION.get((output.extension or "").lower())
    if returned and returned != attachment.media:
        source["media_type"] = returned
    return set()


class _Deidentifier:
    """De-identifies strings for one rule, through a cache shared by warm invocations."""

    def __init__(self, client: SkyflowClient, rule: InferenceRule) -> None:
        self._client = client
        self._entities = tuple(rule.entities)
        self._vault = rule.request.token_type == "vault_token"

    def text(self, value: str) -> tuple[str, frozenset[str]]:
        key = (self._vault, self._entities, value)
        cached = _cache_get(key) if self._vault else None
        if cached is not None:
            return cached
        result = self._client.deidentify(value, self._entities, self._entities if self._vault else None)
        processed = result.processed_text
        minted = frozenset(set(TOKEN.findall(processed)) - set(TOKEN.findall(value)))
        if self._vault:
            # Vault tokens are deterministic, so a cached answer is exactly the
            # one Skyflow would give again. Counter tokens are numbered per
            # call and are never cached.
            _cache_put(key, (processed, minted))
        return processed, minted


#: Recent de-identifications, kept while the Lambda stays warm. Bounded by
#: characters as well as entries, because one text attachment can run to
#: megabytes and is resent with every turn of its conversation.
CACHE_ENTRIES = 4096
CACHE_CHARACTERS = 32 * 1024 * 1024
_cache: OrderedDict = OrderedDict()
_cache_size = 0
_cache_lock = threading.Lock()


def _entry_size(key, value) -> int:
    return len(key[-1]) + len(value[0])


def _cache_get(key):
    with _cache_lock:
        value = _cache.get(key)
        if value is not None:
            _cache.move_to_end(key)
        return value


def _cache_put(key, value) -> None:
    global _cache_size
    size = _entry_size(key, value)
    if size > CACHE_CHARACTERS:
        return
    with _cache_lock:
        old = _cache.pop(key, None)
        if old is not None:
            _cache_size -= _entry_size(key, old)
        _cache[key] = value
        _cache_size += size
        while len(_cache) > CACHE_ENTRIES or _cache_size > CACHE_CHARACTERS:
            evicted_key, evicted = _cache.popitem(last=False)
            _cache_size -= _entry_size(evicted_key, evicted)


def _cache_clear() -> None:
    global _cache_size
    with _cache_lock:
        _cache.clear()
        _cache_size = 0


def _parallel(function: Callable[[str], Any], values: list[str]) -> dict[str, Any]:
    if not values:
        return {}
    if len(values) == 1:
        return {values[0]: function(values[0])}
    with ThreadPoolExecutor(max_workers=min(len(values), MAX_PARALLEL_CALLS)) as pool:
        return dict(zip(values, pool.map(function, values)))


def _remaining_seconds(context):
    getter = getattr(context, "get_remaining_time_in_millis", None)
    if getter is None:
        deadline = time.monotonic() + NO_CONTEXT_BUDGET_SECONDS
        return lambda: deadline - time.monotonic()
    return lambda: getter() / 1000.0


# ------------------------------------------------------------ response side


def _on_response(response: dict, context) -> dict | None:
    rid = request_id(context)
    if rid is None:
        return None
    try:
        store = settings.record_store()
        record = store.get(rid) if store is not None else None
    except Exception as exc:  # noqa: BLE001 - no record means the ordinary HTTP rule decides
        logger.error("inference_record_read_failed err=%s", type(exc).__name__)
        return None
    if record is None:
        return None

    status = _status(response.get("statusCode"))
    if record.response_action != "reidentify" or status >= 400:
        logger.info("inference_response kind=%s action=none status=%s", record.kind, status)
        return passthrough()

    content_type = (response.get("contentType") or "").split(";", 1)[0].strip().lower()
    try:
        raw = response.get("body")
        if raw is None:
            raise SkyflowError("the answer body was not passed to the interceptor")
        text = base64.b64decode(raw).decode("utf-8")
        restorer = _Restorer(settings.build_client(), record)
        new_text, answer_format, count = formats.restore_answer(text, content_type, record.response_parts, restorer)
    except Exception as exc:  # noqa: BLE001 - decided by the record's failure mode
        if record.on_error == "fail_open":
            logger.warning("inference_fail_open direction=response kind=%s err=%s", record.kind, exc)
            return passthrough()
        logger.error("inference_fail_closed direction=response kind=%s err=%s", record.kind, exc)
        return refusal(record.kind, "Sensitive-data processing failed, so the answer was withheld.", 502)

    logger.info("inference_response kind=%s format=%s action=reidentify restored=%d", record.kind, answer_format, count)
    if not count:
        return passthrough()
    encoded = base64.b64encode(new_text.encode("utf-8")).decode()
    return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {"transformedGatewayResponse": {"body": encoded}}}


def _status(value) -> int:
    """The answer's status code. A missing or unreadable one is treated as success."""
    try:
        return int(value or 200)
    except (TypeError, ValueError):
        return 200


class _Restorer:
    """Re-identifies tokens in answer text, limited to minted ones when the record says so.

    Each token is re-identified once per answer and the value reused, so every
    copy of a text in a stream gets the same restored value.
    """

    def __init__(self, client: SkyflowClient, record: CallRecord) -> None:
        self._client = client
        self._only_minted = record.response_only == "minted_for_request"
        self._minted = record.tokens
        self._values: dict[str, str] = {}
        self._lock = threading.Lock()

    def _wanted(self, text: str) -> set[str]:
        found = set(TOKEN.findall(text))
        return found & self._minted if self._only_minted else found

    def pending(self, text: str) -> bool:
        """Whether a text holds a token this answer would restore."""
        return bool(self._wanted(text))

    def text(self, text: str, escape: bool = False) -> str:
        """Restore the tokens in a text. `escape` writes each value as it would sit inside a JSON string."""
        found = self._wanted(text)
        if not found:
            return text
        missing = [token for token in found if token not in self._values]
        for token, value in _parallel(lambda t: self._client.reidentify(t).text, missing).items():
            with self._lock:
                self._values[token] = value
        for token in sorted(found, key=len, reverse=True):
            value = self._values[token]
            text = text.replace(token, json.dumps(value)[1:-1] if escape else value)
        return text

    __call__ = text

    def json_string(self, value: str) -> str:
        """Restore tool-call arguments held as JSON in a string.

        Parsed when it parses, so a restored value is escaped by the encoder.
        Arguments cut short by the token limit are not JSON, and their tokens
        are replaced in place with escaped values. Arguments that were never
        JSON get plain values.
        """
        try:
            parsed = json.loads(value)
        except ValueError:
            # Cut-short JSON needs its values escaped. Free-form arguments,
            # which the request side de-identified as plain text, do not. A
            # leading `[` may be a token rather than the start of an array.
            start = value.lstrip()
            looks_like_json = start.startswith(("{", '"')) or (start.startswith("[") and not TOKEN.match(start))
            return self.text(value, escape=looks_like_json)
        new, changed = self.tree(parsed)
        return json.dumps(new) if changed else value

    def tree(self, node) -> tuple[Any, int]:
        """Re-identify every string inside a JSON value. Returns `(node, changed)`."""
        if isinstance(node, str):
            new = self.text(node)
            return new, int(new != node)
        if isinstance(node, list):
            changed = 0
            out = []
            for item in node:
                new, n = self.tree(item)
                out.append(new)
                changed += n
            return out, changed
        if isinstance(node, dict):
            changed = 0
            out = {}
            for key, item in node.items():
                new, n = self.tree(item)
                out[key] = new
                changed += n
            return out, changed
        return node, 0


# ------------------------------------------------------------------ outputs


def passthrough() -> dict:
    return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {}}


def refusal(kind: str, message: str, status: int) -> dict:
    """An error answer in the caller's dialect, so its SDK raises a typed error."""
    headers = None
    if kind.startswith("invoke"):
        body = {"message": message}
        headers = {"x-amzn-errortype": {
            400: "ValidationException", 403: "AccessDeniedException", 413: "ValidationException",
        }.get(status, "InternalServerException")}
    elif kind in ("chat", "responses"):
        body = {"error": {"message": message, "type": "skyflow_shield_the_model", "code": status}}
    else:
        error_type = {
            400: "invalid_request_error", 403: "permission_error", 413: "request_too_large",
        }.get(status, "api_error")
        body = {"type": "error", "error": {"type": error_type, "message": message}}
    out: dict = {
        "statusCode": status,
        "contentType": "application/json",
        "body": base64.b64encode(json.dumps(body).encode()).decode(),
    }
    if headers:
        out["headers"] = headers
    return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {"transformedGatewayResponse": out}}
