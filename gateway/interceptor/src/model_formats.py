"""Where text sits in each model API's requests and answers.

Shield the model does the same thing whatever API a call uses. It finds the
strings and files that the policy's parts name, has Skyflow de-identify them
and writes the results back. Then it finds the text and tool-call arguments in
the answer and restores them. `inference` does the Skyflow half. This module
knows where to look in each format and nothing about Skyflow.

| Format | Request | Answer |
| --- | --- | --- |
| Anthropic Messages | `system` and `messages[].content` blocks | `content` blocks, or `content_block_delta` events |
| OpenAI Chat Completions | `messages[]` by role, content parts and `tool_calls` | `choices[].message`, or `chat.completion.chunk` events |
| OpenAI Responses | `instructions` and `input` items | `output` items, or `response.*` events |

Claude's InvokeModel body is Anthropic Messages with `anthropic_version`.

An answer's format follows the model that wrote it and not the path the
client called. Through the gateway's Bedrock connector a Messages call to
DeepSeek or Qwen comes back as a Chat Completions answer, so an answer is read
by its own shape.

Tool-call arguments are JSON in Anthropic's format and a JSON string in both
OpenAI formats. Thinking blocks are never touched, because the provider checks
their signature. OpenAI-style reasoning text carries no signature, so it is
de-identified and restored like any other text.
"""

from __future__ import annotations

import json
import mimetypes
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

#: A Skyflow token such as `[NAME_AJbrIud]` or `[EMAIL_ADDRESS_nJFlbfH]`.
TOKEN = re.compile(r"\[[A-Z][A-Z0-9_]*_[A-Za-z0-9]+\]")

#: Added to the system prompt when the conversation carries tokens. Without it
#: a model given `[NAME_AJbrIud]` may say the name looks like a placeholder.
SYSTEM_NOTE = (
    "Some values in this conversation have been replaced with tokens in square brackets, "
    "such as [NAME_AbCdEfG]. Each token stands for one real value. Use the tokens exactly "
    "as written, including in tool calls, and do not remark on them."
)

ANTHROPIC = "anthropic"
CHAT = "chat"
RESPONSES = "responses"

#: The format of each call kind's request body.
REQUEST_FORMATS = {
    "messages": ANTHROPIC,
    "count_tokens": ANTHROPIC,
    "invoke": ANTHROPIC,
    "invoke_stream": ANTHROPIC,
    "chat": CHAT,
    "responses": RESPONSES,
}


class Refused(Exception):
    """The call carries something this rule cannot protect, so it is refused."""


class UnreadableAnswer(Exception):
    """An answer in a shape this module does not know carries tokens to restore."""


@dataclass
class FileRef:
    """A base64 attachment and how to write its de-identified form back.

    `source` holds `media_type` and `data`. For Anthropic it is the request's
    own source object. For a data URL it is a stand-in, and `commit` writes the
    result back into the URL.
    """

    source: dict
    part: str
    commit: Callable[[dict], None] | None = None


@dataclass
class Found:
    """What a request holds under the parts a rule names, as `(holder, key)` pairs."""

    #: Strings de-identified whole.
    texts: list[tuple[Any, Any]] = field(default_factory=list)
    #: JSON values whose strings are de-identified, as Anthropic tool-call input.
    trees: list[tuple[Any, Any]] = field(default_factory=list)
    #: JSON held in a string, as OpenAI tool-call arguments.
    json_strings: list[tuple[Any, Any]] = field(default_factory=list)
    files: list[FileRef] = field(default_factory=list)


class Restore(Protocol):
    """What the answer side needs from `inference` to restore tokens."""

    def text(self, value: str) -> str: ...

    def tree(self, node: Any) -> tuple[Any, int]: ...

    def json_string(self, value: str) -> str: ...

    def pending(self, value: str) -> bool: ...


# ------------------------------------------------------------- requests


def readable(kind: str, body: dict) -> bool:
    """Whether a request body is in the shape its path promises.

    Bedrock's InvokeModel takes each model family's own body: `prompt` for
    Llama, `inputText` for Titan, `message` and `chat_history` for Cohere.
    None of those are read here, so only Anthropic's, which names
    `anthropic_version`, is let through.
    """
    fmt = REQUEST_FORMATS.get(kind)
    if fmt == ANTHROPIC:
        if not isinstance(body.get("messages"), list):
            return False
        return "anthropic_version" in body if kind.startswith("invoke") else True
    if fmt == CHAT:
        return isinstance(body.get("messages"), list)
    if fmt == RESPONSES:
        return isinstance(body.get("input"), (str, list))
    return False


def collect(kind: str, body: dict, parts: set[str]) -> Found:
    """Find everything in a request body that the parts name. Raises Refused."""
    found = Found()
    {ANTHROPIC: _anthropic_request, CHAT: _chat_request, RESPONSES: _responses_request}[
        REQUEST_FORMATS[kind]
    ](body, parts, found)
    return found


def add_system_note(kind: str, body: dict) -> None:
    """Tell the model what the tokens are, in the format's own system prompt."""
    fmt = REQUEST_FORMATS[kind]
    if fmt == ANTHROPIC:
        system = body.get("system")
        if isinstance(system, list):
            body["system"] = system + [{"type": "text", "text": SYSTEM_NOTE}]
        elif isinstance(system, str) and system:
            body["system"] = f"{system}\n\n{SYSTEM_NOTE}"
        else:
            body["system"] = SYSTEM_NOTE
    elif fmt == CHAT:
        messages = body["messages"]
        first = messages[0] if messages and isinstance(messages[0], dict) else None
        if first is not None and first.get("role") in ("system", "developer"):
            content = first.get("content")
            if isinstance(content, str):
                first["content"] = f"{content}\n\n{SYSTEM_NOTE}" if content else SYSTEM_NOTE
                return
            if isinstance(content, list):
                first["content"] = content + [{"type": "text", "text": SYSTEM_NOTE}]
                return
        messages.insert(0, {"role": "system", "content": SYSTEM_NOTE})
    elif fmt == RESPONSES:
        instructions = body.get("instructions")
        if isinstance(instructions, str) and instructions:
            body["instructions"] = f"{instructions}\n\n{SYSTEM_NOTE}"
        elif not instructions:
            body["instructions"] = SYSTEM_NOTE


# -------------------------------------------------- Anthropic Messages request

#: The part of a message a text block belongs to, by the message's role.
#: A `system` message in `messages` is a mid-conversation system prompt.
_ANTHROPIC_ROLE_PARTS = {"user": "user", "assistant": "assistant", "system": "system"}

#: Block types that the provider produced and checks or reads back verbatim.
#: Server-tool results, whose types end in `_tool_result`, are treated alike.
_UNTOUCHED_BLOCKS = frozenset({"thinking", "redacted_thinking", "server_tool_use"})


def _anthropic_request(body: dict, parts: set[str], found: Found) -> None:
    system = body.get("system")
    if "system" in parts:
        if isinstance(system, str):
            found.texts.append((body, "system"))
        elif isinstance(system, list):
            for block in system:
                if isinstance(block, dict) and block.get("type") == "text":
                    found.texts.append((block, "text"))

    for message in body.get("messages") or []:
        if not isinstance(message, dict):
            continue
        role_part = _ANTHROPIC_ROLE_PARTS.get(message.get("role"), "user")
        content = message.get("content")
        if isinstance(content, str):
            if role_part in parts:
                found.texts.append((message, "content"))
        elif isinstance(content, list):
            for block in content:
                _anthropic_block(block, role_part, parts, found)


def _anthropic_block(block, text_part: str, parts: set[str], found: Found) -> None:
    if not isinstance(block, dict):
        return
    kind = block.get("type") or ""

    if kind == "text":
        if text_part in parts:
            found.texts.append((block, "text"))
    elif kind in _UNTOUCHED_BLOCKS or (kind.endswith("_tool_result") and kind != "tool_result"):
        # The provider writes these into its own turn. Anywhere else one came
        # from the client, and skipping it would wave through whatever it holds.
        if text_part != "assistant":
            raise Refused(f"A {kind} block outside an assistant turn cannot be inspected")
        return
    elif kind == "tool_use":
        if "tool_call" in parts and isinstance(block.get("input"), (dict, list)):
            found.trees.append((block, "input"))
    elif kind == "tool_result":
        content = block.get("content")
        if isinstance(content, str):
            if "tool_result" in parts:
                found.texts.append((block, "content"))
        elif isinstance(content, list):
            for inner in content:
                _anthropic_block(inner, "tool_result", parts, found)
    elif kind == "search_result":
        # Part of whatever holds it: a tool result's when a tool returned it,
        # the turn's when the caller put it straight into a message.
        if text_part in parts:
            if isinstance(block.get("title"), str):
                found.texts.append((block, "title"))
            for inner in block.get("content") or []:
                _anthropic_block(inner, text_part, parts, found)
    elif kind == "document":
        if "document" not in parts:
            return
        for key in ("title", "context"):
            if isinstance(block.get(key), str):
                found.texts.append((block, key))
        source = _source(block, "document")
        source_type = source.get("type")
        if source_type == "text":
            found.texts.append((source, "data"))
        elif source_type == "base64":
            found.files.append(FileRef(source, "document"))
        elif source_type == "content":
            for inner in source.get("content") or []:
                _anthropic_block(inner, "document", parts | {"document"}, found)
        else:
            raise Refused(f"An attached document sent as {source_type or 'an unknown source'} cannot be inspected")
    elif kind == "image":
        if "image" not in parts:
            return
        source = _source(block, "image")
        if source.get("type") != "base64":
            raise Refused("An attached image sent by reference cannot be inspected")
        found.files.append(FileRef(source, "image"))
    else:
        raise Refused(f"A {kind or 'untyped'} content block is not supported by shield the model")


def _source(block: dict, part: str) -> dict:
    source = block.get("source")
    if not isinstance(source, dict):
        raise Refused(f"An attached {part} has no source object")
    return source


# ----------------------------------------------- OpenAI Chat Completions request

#: The part each Chat Completions role's content belongs to.
_CHAT_ROLE_PARTS = {
    "system": "system",
    "developer": "system",
    "user": "user",
    "assistant": "assistant",
    "tool": "tool_result",
    "function": "tool_result",
}

#: Assistant message fields that hold text besides `content`. Mantle returns
#: reasoning as `reasoning`. Some providers call it `reasoning_content`.
_CHAT_TEXT_FIELDS = ("content", "reasoning", "reasoning_content", "refusal")


def _chat_request(body: dict, parts: set[str], found: Found) -> None:
    if body.get("prediction") is not None:
        raise Refused("A predicted output cannot be inspected")
    for message in body["messages"]:
        if not isinstance(message, dict):
            raise Refused("A chat message that is not an object cannot be inspected")
        role = message.get("role")
        part = _CHAT_ROLE_PARTS.get(role)
        if part is None:
            raise Refused(f"A chat message with role {role!r} cannot be inspected")
        content = message.get("content")
        if isinstance(content, str):
            if part in parts:
                found.texts.append((message, "content"))
        elif isinstance(content, list):
            for item in content:
                _chat_content_part(item, part, parts, found)
        elif content is not None:
            raise Refused(f"A {role} message's content cannot be inspected")
        if role != "assistant":
            continue
        if "assistant" in parts:
            for key in _CHAT_TEXT_FIELDS[1:]:
                if isinstance(message.get(key), str):
                    found.texts.append((message, key))
        if "tool_call" in parts:
            for call in message.get("tool_calls") or []:
                if not isinstance(call, dict):
                    continue
                function = call.get("function")
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    found.json_strings.append((function, "arguments"))
                custom = call.get("custom")
                if isinstance(custom, dict) and isinstance(custom.get("input"), str):
                    found.texts.append((custom, "input"))
            legacy = message.get("function_call")
            if isinstance(legacy, dict) and isinstance(legacy.get("arguments"), str):
                found.json_strings.append((legacy, "arguments"))


def _chat_content_part(item, part: str, parts: set[str], found: Found) -> None:
    if not isinstance(item, dict):
        raise Refused("A content part that is not an object cannot be inspected")
    kind = item.get("type")
    if kind == "text":
        if part in parts and isinstance(item.get("text"), str):
            found.texts.append((item, "text"))
    elif kind == "refusal":
        if part in parts and isinstance(item.get("refusal"), str):
            found.texts.append((item, "refusal"))
    elif kind == "image_url":
        if "image" not in parts:
            return
        image = item.get("image_url")
        if isinstance(image, dict) and isinstance(image.get("url"), str):
            found.files.append(_data_url(image, "url", "image"))
        elif isinstance(image, str):
            found.files.append(_data_url(item, "image_url", "image"))
        else:
            raise Refused("An attached image has no URL")
    elif kind == "file":
        if "document" not in parts:
            return
        _openai_file(item.get("file"), "file_data", "file_id", found)
    elif kind == "input_audio":
        raise Refused("Attached audio cannot be inspected")
    else:
        raise Refused(f"A {kind or 'untyped'} content part is not supported by shield the model")


# ------------------------------------------------------ OpenAI Responses request

_RESPONSES_ROLE_PARTS = {"user": "user", "assistant": "assistant", "system": "system", "developer": "system"}


def _responses_request(body: dict, parts: set[str], found: Found) -> None:
    if body.get("prompt") is not None:
        # A stored prompt's variables are filled in on the provider's side,
        # where nothing here can read them.
        raise Refused("A stored prompt cannot be inspected")
    instructions = body.get("instructions")
    if isinstance(instructions, str):
        if "system" in parts:
            found.texts.append((body, "instructions"))
    elif instructions is not None:
        raise Refused("Instructions that are not a string cannot be inspected")
    given = body["input"]
    if isinstance(given, str):
        if "user" in parts:
            found.texts.append((body, "input"))
        return
    for item in given:
        _responses_item(item, parts, found)


def _responses_item(item, parts: set[str], found: Found) -> None:
    if not isinstance(item, dict):
        raise Refused("An input item that is not an object cannot be inspected")
    kind = item.get("type") or ("message" if "role" in item else None)
    if kind == "message":
        role = item.get("role")
        part = _RESPONSES_ROLE_PARTS.get(role)
        if part is None:
            raise Refused(f"A message with role {role!r} cannot be inspected")
        _responses_content(item, "content", part, parts, found)
    elif kind == "function_call":
        if "tool_call" in parts and isinstance(item.get("arguments"), str):
            found.json_strings.append((item, "arguments"))
    elif kind == "custom_tool_call":
        if "tool_call" in parts and isinstance(item.get("input"), str):
            found.texts.append((item, "input"))
    elif kind in ("function_call_output", "custom_tool_call_output"):
        _responses_content(item, "output", "tool_result", parts, found)
    elif kind == "reasoning":
        # Plain reasoning text the model wrote and will read again. Its
        # `encrypted_content`, when there is any, stays as it came.
        if "assistant" in parts:
            for key in ("content", "summary"):
                for piece in item.get(key) or []:
                    if isinstance(piece, dict) and isinstance(piece.get("text"), str):
                        found.texts.append((piece, "text"))
    elif kind == "item_reference":
        return
    else:
        raise Refused(f"A {kind or 'untyped'} input item is not supported by shield the model")


def _responses_content(holder: dict, key: str, part: str, parts: set[str], found: Found) -> None:
    content = holder.get(key)
    if isinstance(content, str):
        if part in parts:
            found.texts.append((holder, key))
        return
    if content is None:
        return
    if not isinstance(content, list):
        raise Refused(f"Content of type {type(content).__name__} cannot be inspected")
    for piece in content:
        if not isinstance(piece, dict):
            raise Refused("A content part that is not an object cannot be inspected")
        kind = piece.get("type")
        if kind in ("input_text", "output_text", "text"):
            if part in parts and isinstance(piece.get("text"), str):
                found.texts.append((piece, "text"))
        elif kind == "refusal":
            if part in parts and isinstance(piece.get("refusal"), str):
                found.texts.append((piece, "refusal"))
        elif kind == "input_image":
            if "image" not in parts:
                continue
            if not isinstance(piece.get("image_url"), str):
                raise Refused("An attached image sent by file id cannot be inspected")
            found.files.append(_data_url(piece, "image_url", "image"))
        elif kind == "input_file":
            if "document" in parts:
                _openai_file(piece, "file_data", "file_id", found)
        else:
            raise Refused(f"A {kind or 'untyped'} content part is not supported by shield the model")


# ------------------------------------------------------- OpenAI attachments

_DATA_URL = re.compile(r"^data:(?P<media>[^;,]+)(?:;[^;,]*)*;base64,(?P<data>.*)$", re.DOTALL)


def _data_url(holder: dict, key: str, part: str) -> FileRef:
    """A base64 data URL as an attachment. A URL to fetch is refused."""
    match = _DATA_URL.match(holder[key])
    if not match:
        raise Refused(f"An attached {part} sent by URL cannot be inspected")
    source = {"media_type": match.group("media").lower(), "data": match.group("data")}

    def commit(result: dict) -> None:
        holder[key] = f"data:{result['media_type']};base64,{result['data']}"

    return FileRef(source, part, commit)


def _openai_file(file, data_key: str, id_key: str, found: Found) -> None:
    """An attached file in either OpenAI format: a data URL, or base64 named by its filename."""
    if not isinstance(file, dict):
        raise Refused("An attached document has no file object")
    if isinstance(file.get("filename"), str):
        found.texts.append((file, "filename"))
    data = file.get(data_key)
    if not isinstance(data, str):
        what = "file id" if file.get(id_key) else "URL" if file.get("file_url") else "unknown source"
        raise Refused(f"An attached document sent by {what} cannot be inspected")
    if data.startswith("data:"):
        found.files.append(_data_url(file, data_key, "document"))
        return
    media = mimetypes.guess_type(str(file.get("filename") or ""))[0]
    if media is None:
        raise Refused("An attached document without a data URL or a known filename cannot be inspected")
    source = {"media_type": media, "data": data}

    def commit(result: dict) -> None:
        file[data_key] = result["data"]

    found.files.append(FileRef(source, "document", commit))


# ---------------------------------------------------------------- answers


def restore_answer(text: str, content_type: str, parts, restore: Restore) -> tuple[str, str | None, int]:
    """Restore the tokens in an answer. Returns `(text, format, places_changed)`.

    The format is read from the answer itself. An answer in no known shape is
    passed as it came when it carries nothing to restore, and raises
    UnreadableAnswer when it does, so tokens are never left in place silently.
    """
    parts = set(parts)
    if content_type == "text/event-stream":
        text = text.replace("\r\n", "\n")
        events = _parse_sse(text)
        fmt = _stream_format(events)
        changed = _STREAMS[fmt](events, parts, restore) if fmt else 0
        new = _render_sse(events) if changed else text
    else:
        try:
            doc = json.loads(text)
        except ValueError:
            doc = None
        fmt = _json_format(doc)
        changed = _DOCUMENTS[fmt](doc, parts, restore) if fmt else 0
        new = json.dumps(doc) if changed else text
    if fmt is None and restore.pending(text):
        raise UnreadableAnswer(f"an answer of type {content_type or 'unknown'} in an unrecognised shape carries tokens")
    return new, fmt, changed


def _json_format(doc) -> str | None:
    if not isinstance(doc, dict):
        return None
    if isinstance(doc.get("choices"), list):
        return CHAT
    if doc.get("object") == "response" or isinstance(doc.get("output"), list):
        return RESPONSES
    if isinstance(doc.get("content"), list):
        return ANTHROPIC
    return None


_ANTHROPIC_EVENTS = frozenset({
    "message_start", "content_block_start", "content_block_delta", "content_block_stop",
    "message_delta", "message_stop", "ping",
})


def _stream_format(events) -> str | None:
    for event in events:
        data = event.data
        if not isinstance(data, dict):
            continue
        kind = data.get("type")
        if isinstance(kind, str) and kind.startswith("response."):
            return RESPONSES
        if "choices" in data or data.get("object") == "chat.completion.chunk":
            return CHAT
        if kind in _ANTHROPIC_EVENTS:
            return ANTHROPIC
    return None


def _restore_field(holder, key, restore_fn: Callable[[str], str]) -> int:
    """Restore one string field in place. Returns 1 when it changed."""
    if not isinstance(holder, dict) or not isinstance(holder.get(key), str):
        return 0
    new = restore_fn(holder[key])
    if new == holder[key]:
        return 0
    holder[key] = new
    return 1


def _rejoin(pieces: list, key: str, restore_fn: Callable[[str], str]) -> int:
    """Restore text spread across stream deltas.

    A token can be split across two deltas, so the deltas are joined first.
    The restored text goes back as the first delta and the later ones are
    emptied, which keeps the stream's events and their order as they were.
    """
    joined = "".join(holder[key] for _, holder in pieces)
    new = restore_fn(joined)
    if new == joined:
        return 0
    for n, (event, holder) in enumerate(pieces):
        holder[key] = new if n == 0 else ""
        event.dirty = True
    return 1


# ---------------------------------------------------- server-sent events


@dataclass
class _Event:
    lines: list[str]
    data_line: int | None
    data: Any
    dirty: bool = False


def _parse_sse(text: str) -> list[_Event]:
    events = []
    for raw in text.split("\n\n"):
        lines = raw.split("\n")
        data_line = next((i for i, line in enumerate(lines) if line.startswith("data:")), None)
        data = None
        if data_line is not None:
            try:
                data = json.loads(lines[data_line][5:].lstrip())
            except ValueError:
                data = None
        events.append(_Event(lines, data_line, data))
    return events


def _render_sse(events: list[_Event]) -> str:
    out = []
    for event in events:
        lines = event.lines
        if event.dirty:
            lines = list(lines)
            lines[event.data_line] = "data: " + json.dumps(event.data)
        out.append("\n".join(lines))
    return "\n\n".join(out)


# ------------------------------------------------------ Anthropic answers


def _anthropic_document(doc: dict, parts: set[str], restore: Restore) -> int:
    changed = 0
    for block in doc.get("content") or []:
        if not isinstance(block, dict):
            continue
        kind = block.get("type")
        if kind == "text" and "text" in parts:
            changed += _restore_field(block, "text", restore.text)
        elif kind == "tool_use" and "tool_call" in parts:
            new, n = restore.tree(block.get("input"))
            if n:
                block["input"] = new
                changed += 1
    return changed


def _anthropic_stream(events: list[_Event], parts: set[str], restore: Restore) -> int:
    texts: dict[Any, list] = defaultdict(list)
    arguments: dict[Any, list] = defaultdict(list)
    for event in events:
        data = event.data
        if not isinstance(data, dict) or data.get("type") != "content_block_delta":
            continue
        delta = data.get("delta")
        if not isinstance(delta, dict):
            continue
        if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
            texts[data.get("index")].append((event, delta))
        elif delta.get("type") == "input_json_delta" and isinstance(delta.get("partial_json"), str):
            arguments[data.get("index")].append((event, delta))
    changed = 0
    if "text" in parts:
        for pieces in texts.values():
            changed += _rejoin(pieces, "text", restore.text)
    if "tool_call" in parts:
        for pieces in arguments.values():
            changed += _rejoin(pieces, "partial_json", restore.json_string)
    return changed


# ----------------------------------------------- Chat Completions answers


def _chat_document(doc: dict, parts: set[str], restore: Restore) -> int:
    changed = 0
    for choice in doc.get("choices") or []:
        message = choice.get("message") if isinstance(choice, dict) else None
        if not isinstance(message, dict):
            continue
        if "text" in parts:
            for key in _CHAT_TEXT_FIELDS:
                changed += _restore_field(message, key, restore.text)
            if isinstance(message.get("content"), list):
                for piece in message["content"]:
                    if isinstance(piece, dict) and piece.get("type") in ("text", "output_text"):
                        changed += _restore_field(piece, "text", restore.text)
        if "tool_call" in parts:
            for call in message.get("tool_calls") or []:
                if isinstance(call, dict):
                    changed += _restore_field(call.get("function"), "arguments", restore.json_string)
                    changed += _restore_field(call.get("custom"), "input", restore.text)
            changed += _restore_field(message.get("function_call"), "arguments", restore.json_string)
    return changed


def _chat_stream(events: list[_Event], parts: set[str], restore: Restore) -> int:
    texts: dict[Any, list] = defaultdict(list)
    arguments: dict[Any, list] = defaultdict(list)
    for event in events:
        data = event.data
        if not isinstance(data, dict):
            continue
        for choice in data.get("choices") or []:
            delta = choice.get("delta") if isinstance(choice, dict) else None
            if not isinstance(delta, dict):
                continue
            index = choice.get("index", 0)
            for key in _CHAT_TEXT_FIELDS:
                if isinstance(delta.get(key), str):
                    texts[(index, key)].append((event, delta))
            for call in delta.get("tool_calls") or []:
                function = call.get("function") if isinstance(call, dict) else None
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    arguments[(index, call.get("index", 0))].append((event, function))
            legacy = delta.get("function_call")
            if isinstance(legacy, dict) and isinstance(legacy.get("arguments"), str):
                arguments[(index, "function_call")].append((event, legacy))
    changed = 0
    if "text" in parts:
        for (_, key), pieces in texts.items():
            changed += _rejoin(pieces, key, restore.text)
    if "tool_call" in parts:
        for pieces in arguments.values():
            changed += _rejoin(pieces, "arguments", restore.json_string)
    return changed


# ------------------------------------------------------ Responses answers

#: Content part types that hold text, and the field that holds it.
_RESPONSES_TEXT_PARTS = {
    "output_text": "text",
    "text": "text",
    "reasoning_text": "text",
    "summary_text": "text",
    "refusal": "refusal",
}

#: Stream events whose `delta` adds to a text or to tool-call arguments:
#: the response part they belong to, and whether the text is JSON.
_RESPONSES_DELTAS = {
    "response.output_text.delta": ("text", False),
    "response.refusal.delta": ("text", False),
    "response.reasoning_text.delta": ("text", False),
    "response.reasoning_summary_text.delta": ("text", False),
    "response.function_call_arguments.delta": ("tool_call", True),
    "response.custom_tool_call_input.delta": ("tool_call", False),
}

#: Stream events that repeat a finished text in full: the field that holds it,
#: the response part, and whether it is JSON.
_RESPONSES_DONE = {
    "response.output_text.done": ("text", "text", False),
    "response.refusal.done": ("refusal", "text", False),
    "response.reasoning_text.done": ("text", "text", False),
    "response.reasoning_summary_text.done": ("text", "text", False),
    "response.function_call_arguments.done": ("arguments", "tool_call", True),
    "response.custom_tool_call_input.done": ("input", "tool_call", False),
}


def _responses_document(doc: dict, parts: set[str], restore: Restore) -> int:
    changed = 0
    for item in doc.get("output") or []:
        changed += _responses_output_item(item, parts, restore)
    if "text" in parts:
        changed += _restore_field(doc, "output_text", restore.text)
    return changed


def _responses_output_item(item, parts: set[str], restore: Restore) -> int:
    if not isinstance(item, dict):
        return 0
    kind = item.get("type")
    changed = 0
    if kind == "message" and "text" in parts:
        for piece in item.get("content") or []:
            changed += _responses_text_part(piece, restore)
    elif kind == "reasoning" and "text" in parts:
        for key in ("content", "summary"):
            for piece in item.get(key) or []:
                changed += _responses_text_part(piece, restore)
    elif kind == "function_call" and "tool_call" in parts:
        changed += _restore_field(item, "arguments", restore.json_string)
    elif kind == "custom_tool_call" and "tool_call" in parts:
        changed += _restore_field(item, "input", restore.text)
    return changed


def _responses_text_part(piece, restore: Restore) -> int:
    if not isinstance(piece, dict):
        return 0
    key = _RESPONSES_TEXT_PARTS.get(piece.get("type"))
    return _restore_field(piece, key, restore.text) if key else 0


def _responses_stream(events: list[_Event], parts: set[str], restore: Restore) -> int:
    """Restore a Responses stream.

    Text arrives in deltas and then again in full, in the `.done` event and in
    every event that carries the finished part, item or response. Each copy is
    restored on its own. The restorer gives the same value for the same token
    every time, so all the copies agree.
    """
    deltas: dict[Any, list] = defaultdict(list)
    changed = 0
    for event in events:
        data = event.data
        if not isinstance(data, dict):
            continue
        kind = data.get("type")
        if kind in _RESPONSES_DELTAS:
            part, _ = _RESPONSES_DELTAS[kind]
            if part in parts and isinstance(data.get("delta"), str):
                key = (kind, data.get("item_id"), data.get("output_index"),
                       data.get("content_index"), data.get("summary_index"))
                deltas[key].append((event, data))
            continue
        before = changed
        if kind in _RESPONSES_DONE:
            key, part, is_json = _RESPONSES_DONE[kind]
            if part in parts:
                changed += _restore_field(data, key, restore.json_string if is_json else restore.text)
        if "text" in parts:
            changed += _responses_text_part(data.get("part"), restore)
        changed += _responses_output_item(data.get("item"), parts, restore)
        if isinstance(data.get("response"), dict):
            changed += _responses_document(data["response"], parts, restore)
        if changed != before:
            event.dirty = True
    for (kind, *_), pieces in deltas.items():
        is_json = _RESPONSES_DELTAS[kind][1]
        changed += _rejoin(pieces, "delta", restore.json_string if is_json else restore.text)
    return changed


_DOCUMENTS = {ANTHROPIC: _anthropic_document, CHAT: _chat_document, RESPONSES: _responses_document}
_STREAMS = {ANTHROPIC: _anthropic_stream, CHAT: _chat_stream, RESPONSES: _responses_stream}
