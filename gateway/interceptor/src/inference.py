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
| `/v1/models` | passed | passed |
| `/v1/chat/completions`, `/v1/responses` | passed only when the rule does nothing, refused otherwise | |
| any other `/v1/...` or `/model/...` path | refused | |

Paths arrive without the `/inference` prefix the client used, and a model id
arrives decoded, so an inference-profile ARN in an InvokeModel path carries a
`/` of its own. InvokeModel bodies are read only in Anthropic's shape. Another
model family's body, such as Llama's `prompt`, is refused rather than passed
on unread.

What the request side de-identifies is chosen by the rule's `request.parts`:
the system prompt, user and assistant turns, earlier tool calls, tool results
and attached documents and images. Tool definitions are never touched, and
neither are thinking blocks, whose `signature` the provider checks on the next
turn. Server-side tool blocks such as `web_search_tool_result` were produced
by the provider, so they go back as they came. Both are left alone only in an
assistant turn, which is the only place the provider puts them.

The request side then writes a record under the gateway's `REQUEST_ID` (see
`records`) so the response side can apply the same rule and, with
`response.only: minted_for_request`, restore only the tokens this call minted.
It writes one for a refused call too, because the gateway still invokes the
response side, and without a record `httpPayloads` would replace the refusal.

The gateway buffers every inference answer before the interceptor sees it, so
a stream arrives whole. A token can straddle two text deltas, so each content
block's deltas are joined, re-identified and written back as one delta.
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

import payload as payload_utils
import settings
from policy import InferenceRule, PolicySet
from records import CallRecord, request_id
from skyflow_client import SkyflowClient, SkyflowError, build_file_configuration

logger = logging.getLogger(__name__)

OUTPUT_VERSION = "1.0"

#: A Skyflow token such as `[NAME_AJbrIud]` or `[EMAIL_ADDRESS_nJFlbfH]`.
TOKEN = re.compile(r"\[[A-Z][A-Z0-9_]*_[A-Za-z0-9]+\]")

#: Added to the system prompt when the conversation carries tokens. Without it
#: a model given `[NAME_AJbrIud]` may say the name looks like a placeholder.
SYSTEM_NOTE = (
    "Some values in this conversation have been replaced with tokens in square brackets, "
    "such as [NAME_AbCdEfG]. Each token stands for one real value. Use the tokens exactly "
    "as written, including in tool calls, and do not remark on them."
)

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

#: The part of a message a text block belongs to, by the message's role.
#: A `system` message in `messages` is a mid-conversation system prompt.
ROLE_PARTS = {"user": "user", "assistant": "assistant", "system": "system"}

#: Block types that the provider produced and checks or reads back verbatim.
#: Server-tool results, whose types end in `_tool_result`, are treated alike.
UNTOUCHED_BLOCKS = frozenset({"thinking", "redacted_thinking", "server_tool_use"})

#: A decoded model id can hold a `/`, as an inference-profile ARN does.
_INVOKE = re.compile(r"^/model/(?P<model>.+)/(?P<op>invoke|invoke-with-response-stream)$")


class Refused(Exception):
    """The call carries something this rule cannot protect, so it is refused."""


@dataclass(frozen=True)
class Call:
    """A recognised inference call: what kind it is and which model it names."""

    kind: str
    model: str = ""

    @property
    def reads_answers(self) -> bool:
        """Whether the answer is model text that `response` rules apply to."""
        return self.kind in ("messages", "invoke")


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
    if path in ("/v1/chat/completions", "/v1/responses"):
        return Call("openai", str(model))
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
        return refusal("messages", "The interceptor could not process the model call, so it was blocked.", 502)


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
    if call.kind == "openai" and not rule.is_noop:
        logger.warning("inference_blocked kind=%s model=%s reason=dialect_not_supported", call.kind, call.model)
        return refuse("Shield the model does not support the OpenAI dialect yet. Use the Anthropic Messages API.", 403)
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
    if not _is_anthropic_body(call, body):
        logger.warning("inference_blocked kind=%s model=%s reason=body_not_anthropic", call.kind, call.model)
        return refuse(
            "Shield the model reads only Anthropic Messages request bodies, so the model call was blocked.",
            403,
        )

    try:
        new_body, minted, stats = deidentify_request(body, rule, settings.build_client(), context)
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


def _is_anthropic_body(call: Call, body: dict) -> bool:
    """Whether a request body is in the Anthropic Messages shape this module reads.

    Bedrock's InvokeModel takes each model family's own body: `prompt` for
    Llama, `inputText` for Titan, `message` and `chat_history` for Cohere.
    None of those are read here, so only Anthropic's, which names
    `anthropic_version`, is let through.
    """
    if not isinstance(body.get("messages"), list):
        return False
    if call.kind.startswith("invoke"):
        return "anthropic_version" in body
    return True


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


def deidentify_request(body: dict, rule: InferenceRule, client: SkyflowClient, context=None):
    """De-identify the parts of a Messages-shaped body that the rule names.

    Returns `(new_body, minted_tokens, stats)`. The body is copied, never
    changed in place.
    """
    body = copy.deepcopy(body)
    parts = set(rule.request.parts)
    texts, inputs, files = _collect(body, parts)
    # Every attachment is checked before anything is sent to Skyflow, so a call
    # that will be refused for one of them mints no tokens first.
    checked = [(source, part, _check_attachment(source, part, rule)) for source, part in files]
    deidentifier = _Deidentifier(client, rule)

    # Each distinct string is sent once, in parallel, whatever its position.
    # A conversation repeats itself turn after turn, so this and the cache
    # are what keep a long history cheap.
    slots: list[tuple[Any, Any, str]] = []
    for holder, key in texts:
        value = holder.get(key)
        if isinstance(value, str) and rule.scope.value_eligible(value):
            slots.append((holder, key, value))
    for holder, key in inputs:
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

    for source, part, attachment in checked:
        minted |= _deidentify_file(source, part, attachment, rule, client, deidentifier, context)

    if rule.request.system_note and TOKEN.search(json.dumps(body.get("messages") or [])):
        _add_system_note(body)

    return body, minted, {"strings": len(distinct), "files": len(files)}


def _collect(body: dict, parts: set[str]):
    """Find every string and file the parts name, as `(holder, key)` pairs."""
    texts: list[tuple[dict, str]] = []
    inputs: list[tuple[dict, str]] = []
    files: list[tuple[dict, str]] = []

    system = body.get("system")
    if "system" in parts:
        if isinstance(system, str):
            texts.append((body, "system"))
        elif isinstance(system, list):
            for block in system:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append((block, "text"))

    for message in body.get("messages") or []:
        if not isinstance(message, dict):
            continue
        role_part = ROLE_PARTS.get(message.get("role"), "user")
        content = message.get("content")
        if isinstance(content, str):
            if role_part in parts:
                texts.append((message, "content"))
        elif isinstance(content, list):
            for block in content:
                _collect_block(block, role_part, parts, texts, inputs, files)
    return texts, inputs, files


def _collect_block(block, text_part: str, parts: set[str], texts, inputs, files) -> None:
    if not isinstance(block, dict):
        return
    kind = block.get("type") or ""

    if kind == "text":
        if text_part in parts:
            texts.append((block, "text"))
    elif kind in UNTOUCHED_BLOCKS or (kind.endswith("_tool_result") and kind != "tool_result"):
        # The provider writes these into its own turn. Anywhere else one came
        # from the client, and skipping it would wave through whatever it holds.
        if text_part != "assistant":
            raise Refused(f"A {kind} block outside an assistant turn cannot be inspected")
        return
    elif kind == "tool_use":
        if "tool_call" in parts and isinstance(block.get("input"), (dict, list)):
            inputs.append((block, "input"))
    elif kind == "tool_result":
        content = block.get("content")
        if isinstance(content, str):
            if "tool_result" in parts:
                texts.append((block, "content"))
        elif isinstance(content, list):
            for inner in content:
                _collect_block(inner, "tool_result", parts, texts, inputs, files)
    elif kind == "search_result":
        # Part of whatever holds it: a tool result's when a tool returned it,
        # the turn's when the caller put it straight into a message.
        if text_part in parts:
            if isinstance(block.get("title"), str):
                texts.append((block, "title"))
            for inner in block.get("content") or []:
                _collect_block(inner, text_part, parts, texts, inputs, files)
    elif kind == "document":
        if "document" not in parts:
            return
        for key in ("title", "context"):
            if isinstance(block.get(key), str):
                texts.append((block, key))
        source = _source(block, "document")
        source_type = source.get("type")
        if source_type == "text":
            texts.append((source, "data"))
        elif source_type == "base64":
            files.append((source, "document"))
        elif source_type == "content":
            for inner in source.get("content") or []:
                _collect_block(inner, "document", parts | {"document"}, texts, inputs, files)
        else:
            raise Refused(f"An attached document sent as {source_type or 'an unknown source'} cannot be inspected")
    elif kind == "image":
        if "image" not in parts:
            return
        source = _source(block, "image")
        if source.get("type") != "base64":
            raise Refused("An attached image sent by reference cannot be inspected")
        files.append((source, "image"))
    else:
        raise Refused(f"A {kind or 'untyped'} content block is not supported by shield the model")


def _source(block: dict, part: str) -> dict:
    source = block.get("source")
    if not isinstance(source, dict):
        raise Refused(f"An attached {part} has no source object")
    return source


def _add_system_note(body: dict) -> None:
    system = body.get("system")
    if isinstance(system, list):
        body["system"] = system + [{"type": "text", "text": SYSTEM_NOTE}]
    elif isinstance(system, str) and system:
        body["system"] = f"{system}\n\n{SYSTEM_NOTE}"
    else:
        body["system"] = SYSTEM_NOTE


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
        if content_type == "text/event-stream":
            new_text, count = reidentify_stream(text, record.response_parts, restorer)
        elif content_type in ("application/json", ""):
            new_text, count = reidentify_json(text, record.response_parts, restorer)
        else:
            raise SkyflowError(f"cannot re-identify an answer of type {content_type}")
    except Exception as exc:  # noqa: BLE001 - decided by the record's failure mode
        if record.on_error == "fail_open":
            logger.warning("inference_fail_open direction=response kind=%s err=%s", record.kind, exc)
            return passthrough()
        logger.error("inference_fail_closed direction=response kind=%s err=%s", record.kind, exc)
        return refusal(record.kind, "Sensitive-data processing failed, so the answer was withheld.", 502)

    logger.info("inference_response kind=%s action=reidentify restored=%d", record.kind, count)
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
    """Re-identifies tokens in answer text, limited to minted ones when the record says so."""

    def __init__(self, client: SkyflowClient, record: CallRecord) -> None:
        self._client = client
        self._only_minted = record.response_only == "minted_for_request"
        self._minted = record.tokens
        self._values: dict[str, str] = {}
        self._lock = threading.Lock()

    def __call__(self, text: str) -> str:
        found = set(TOKEN.findall(text))
        if self._only_minted:
            found &= self._minted
        if not found:
            return text
        if not self._only_minted:
            return self._client.reidentify(text).text
        missing = [token for token in found if token not in self._values]
        for token, value in _parallel(lambda t: self._client.reidentify(t).text, missing).items():
            with self._lock:
                self._values[token] = value
        for token in sorted(found, key=len, reverse=True):
            text = text.replace(token, self._values[token])
        return text

    def tree(self, node) -> tuple[Any, int]:
        """Re-identify every string inside a JSON value. Returns `(node, changed)`."""
        if isinstance(node, str):
            new = self(node)
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


def reidentify_json(text: str, parts: tuple[str, ...], restore: _Restorer) -> tuple[str, int]:
    """Re-identify an Anthropic message answer. Returns `(text, blocks_changed)`."""
    doc = json.loads(text)
    if not isinstance(doc, dict):
        return text, 0
    changed = 0
    for block in doc.get("content") or []:
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        if kind == "text" and "text" in parts and isinstance(block.get("text"), str):
            new = restore(block["text"])
            if new != block["text"]:
                block["text"] = new
                changed += 1
        elif kind == "tool_use" and "tool_call" in parts:
            block["input"], n = restore.tree(block.get("input"))
            changed += n
    return (json.dumps(doc), changed) if changed else (text, 0)


def reidentify_stream(text: str, parts: tuple[str, ...], restore: _Restorer) -> tuple[str, int]:
    """Re-identify a buffered Anthropic server-sent event stream.

    Returns `(text, blocks_changed)`. Each content block's deltas are joined
    first, because a token can be split across two of them. The restored text
    goes back as the block's first delta and the block's later deltas are
    emptied, so the event sequence keeps its shape.
    """
    text = text.replace("\r\n", "\n")
    events = []
    text_deltas: dict[Any, list[int]] = {}
    json_deltas: dict[Any, list[int]] = {}
    for position, raw in enumerate(text.split("\n\n")):
        lines = raw.split("\n")
        data_line = next((i for i, line in enumerate(lines) if line.startswith("data:")), None)
        data = None
        if data_line is not None:
            try:
                data = json.loads(lines[data_line][5:].lstrip())
            except ValueError:
                data = None
        events.append([lines, data_line, data, False])
        if isinstance(data, dict) and data.get("type") == "content_block_delta":
            delta = data.get("delta") or {}
            if delta.get("type") == "text_delta":
                text_deltas.setdefault(data.get("index"), []).append(position)
            elif delta.get("type") == "input_json_delta":
                json_deltas.setdefault(data.get("index"), []).append(position)

    changed = 0

    def rewrite(positions: list[int], field: str, value: str) -> None:
        for n, position in enumerate(positions):
            events[position][2]["delta"][field] = value if n == 0 else ""
            events[position][3] = True

    if "text" in parts:
        for positions in text_deltas.values():
            joined = "".join(events[p][2]["delta"].get("text", "") for p in positions)
            new = restore(joined)
            if new != joined:
                rewrite(positions, "text", new)
                changed += 1
    if "tool_call" in parts:
        for positions in json_deltas.values():
            joined = "".join(events[p][2]["delta"].get("partial_json", "") for p in positions)
            if not joined.strip():
                continue
            try:
                arguments = json.loads(joined)
            except ValueError as exc:
                raise SkyflowError("a streamed tool call's arguments are not valid JSON") from exc
            new_arguments, n = restore.tree(arguments)
            if n:
                rewrite(positions, "partial_json", json.dumps(new_arguments))
                changed += n

    if not changed:
        return text, 0
    out = []
    for lines, data_line, data, dirty in events:
        if dirty:
            lines = list(lines)
            lines[data_line] = "data: " + json.dumps(data)
        out.append("\n".join(lines))
    return "\n\n".join(out), changed


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
    elif kind == "openai":
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
