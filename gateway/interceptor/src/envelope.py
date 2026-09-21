"""Decode MCP text content blocks so the transforms operate on real structure.

An MCP tool result does not carry its payload as structured JSON. It carries a
JSON *string* inside a text content block:

    {"content": [{"type": "text", "text": "{\\"url\\": \\"https://...\\"}"}]}

String redaction is fine with that: the whole blob is one string and Skyflow
scans it as such. File handling is not, because swapping a file URL requires
the URL to be a field value rather than a substring of one. Without this module
a policy field path such as `content[*].text.url` can never match and a URL
pattern never matches either, so a presigned URL reaches the agent untouched.

The handler therefore decodes only around the file swap and re-encodes before
string redaction runs, so redaction still sees each block as the one string the
agent will read. Decoding it for redaction too would split the block into
fields, and `scope` rules written for prose (a minimum length, excluded keys)
would then skip short values such as a name or a phone number.
"""

from __future__ import annotations

import copy
import json
from typing import Any

CONTENT_KEY = "content"
TEXT_KEY = "text"
TEXT_TYPE = "text"

Path = tuple


def decode_text_blocks(node: Any) -> tuple[Any, tuple[Path, ...]]:
    """Return a copy of `node` with JSON text blocks parsed into objects.

    Returns the new node and the paths that were decoded. Only a block that
    parses to an object or an array is decoded because re-encoding a scalar
    would change a plain string into a quoted one.
    """
    if not isinstance(node, dict):
        return node, ()

    blocks = node.get(CONTENT_KEY)
    if not isinstance(blocks, list):
        return node, ()

    decoded: list[Path] = []
    result = copy.deepcopy(node)

    for index, block in enumerate(result[CONTENT_KEY]):
        if not isinstance(block, dict) or block.get("type") != TEXT_TYPE:
            continue
        text = block.get(TEXT_KEY)
        if not isinstance(text, str):
            continue
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            continue
        if not isinstance(parsed, (dict, list)):
            continue
        block[TEXT_KEY] = parsed
        decoded.append((CONTENT_KEY, index, TEXT_KEY))

    if not decoded:
        return node, ()
    return result, tuple(decoded)


def encode_text_blocks(node: Any, paths: tuple[Path, ...]) -> Any:
    """Re-serialize every path that `decode_text_blocks` parsed."""
    if not paths:
        return node

    result = copy.deepcopy(node)
    for path in paths:
        target = result
        for step in path[:-1]:
            target = target[step]
        value = target[path[-1]]
        if isinstance(value, (dict, list)):
            # ensure_ascii off: the default would turn "Café" into "Caf\u00e9"
            # in the text the model reads. The JSON is equivalent either way,
            # but the agent sees the string, not the parsed value.
            target[path[-1]] = json.dumps(value, ensure_ascii=False)
    return result
