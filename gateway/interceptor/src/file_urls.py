"""Finding file references in an MCP payload, and naming their format.

Field-path parsing lives in `policy`, not here, so a malformed path is rejected
when the policy loads rather than when a request arrives.

Deliberately independent of `payload.collect_strings`, which applies the
redaction `Scope`. Scope excludes the key `url` and imposes a minimum length —
both correct for text, both exactly wrong here, since the value we are looking
for usually lives under a key called `url` and is a long opaque string.
"""

from __future__ import annotations

import logging
from urllib.parse import unquote, urlsplit

from policy import FILE_FORMATS, WILDCARD, FileRule, parse_field_path

logger = logging.getLogger(__name__)

def resolve_field_paths(node, paths: tuple[str, ...]) -> list[tuple[tuple, str]]:
    """Return `(path, value)` for every string the given field paths reach.

    A path that matches nothing is not an error. Tools legitimately return
    responses with no attachment, and a rule naming a field should not turn
    those into failures.
    """
    found: list[tuple[tuple, str]] = []

    def descend(value, segments: tuple, prefix: tuple) -> None:
        if not segments:
            if isinstance(value, str):
                found.append((prefix, value))
            return
        head, rest = segments[0], segments[1:]
        if head is WILDCARD or head == WILDCARD:
            if isinstance(value, list):
                for index, child in enumerate(value):
                    descend(child, rest, prefix + (index,))
        elif isinstance(head, int):
            if isinstance(value, list) and -len(value) <= head < len(value):
                descend(value[head], rest, prefix + (head,))
        elif isinstance(value, dict) and head in value:
            descend(value[head], rest, prefix + (head,))

    for path in paths:
        descend(node, parse_field_path(path), ())
    return found


def warn_unhandled_matches(node, rule: FileRule, handled: set) -> list[tuple]:
    """Log any pattern-matching URLs the named fields did not cover.

    A rule that names fields stops scanning, so a tool quietly changing its
    response shape would let files through in silence. This turns that into a
    warning rather than nothing at all. It never acts on what it finds — acting
    would defeat the point of naming fields.

    Does nothing when the rule has no patterns to match against: there would be
    nothing to compare, and a rule that names fields is not obliged to also
    carry patterns.
    """
    if not rule.url_patterns:
        return []
    missed = [path for path, _ in collect_file_urls(node, rule) if path not in handled]
    if missed:
        logger.warning(
            "file_url_outside_named_fields count=%d paths=%s",
            len(missed),
            [".".join(str(p) for p in path) for path in missed],
        )
    return missed


def collect_file_urls(node, rule: FileRule) -> list[tuple[tuple, str]]:
    """Return `(path, url)` for every string matching the rule's patterns.

    Order is document order, so `maxFiles` truncates predictably rather than
    picking an arbitrary subset.
    """
    found: list[tuple[tuple, str]] = []

    def walk(value, path: tuple) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, path + (key,))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, path + (index,))
        elif isinstance(value, str) and rule.matches_url(value):
            found.append((path, value))

    walk(node, ())
    return found


def data_format_for(url: str) -> str | None:
    """Detect's `dataFormat` for a URL, from the extension in its path.

    Query and fragment are stripped first: a presigned URL carries signature
    parameters after the path, and `...invoice.pdf?X-Amz-Algorithm=...` must
    still read as a PDF.
    """
    path = unquote(urlsplit(url).path)
    _, _, tail = path.rpartition("/")
    _, dot, extension = tail.rpartition(".")
    if not dot:
        return None
    extension = extension.lower()
    return extension if extension in FILE_FORMATS else None
