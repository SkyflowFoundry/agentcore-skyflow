"""Finding file references in an MCP payload, and naming their format.

Deliberately independent of `payload.collect_strings`, which applies the
redaction `Scope`. Scope excludes the key `url` and imposes a minimum length —
both correct for text, both exactly wrong here, since the value we are looking
for usually lives under a key called `url` and is a long opaque string.
"""

from __future__ import annotations

import logging
from urllib.parse import unquote, urlsplit

from policy import FILE_FORMATS, FileRule

logger = logging.getLogger(__name__)


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
