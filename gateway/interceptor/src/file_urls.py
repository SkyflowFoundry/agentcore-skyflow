"""Finding file references in an MCP payload, and naming their format.

Field-path parsing lives in `policy`, not here, so a malformed path is rejected
when the policy loads rather than when a request arrives.

Deliberately independent of `payload.collect_strings`, which applies the
redaction `Scope`. Scope excludes the key `url` and imposes a minimum length —
both correct for text, both exactly wrong here, since the value we are looking
for usually lives under a key called `url` and is a long opaque string.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import socket
import urllib.error
import urllib.request
from urllib.parse import unquote, urlsplit

from policy import FILE_FORMATS, WILDCARD, FileRule, parse_field_path, split_file_url

logger = logging.getLogger(__name__)


class UnsafeFileUrl(Exception):
    """A file URL the interceptor refuses to contact.

    Deliberately not an `OSError` or `ValueError`: the size probe treats those
    as "size unknown" and carries on, which is right for a store that refuses
    a ranged GET and wrong for an address the probe must never reach.
    """


def host_of(url: str) -> str:
    """The host of `url` for a log line, never the URL: it carries a signature."""
    try:
        return urlsplit(url).hostname or "<none>"
    except ValueError:
        return "<unparseable>"


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


def _is_public(address: str) -> bool:
    """Whether a peer address is on the public internet.

    False for loopback, link-local (the 169.254.0.0/16 metadata range),
    RFC 1918, carrier-grade NAT, multicast and the rest of what `ipaddress`
    does not call global. An IPv4 address mapped into IPv6 is judged as IPv4.
    """
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    # `is_global` alone calls multicast global. A document is never there.
    return ip.is_global and not ip.is_multicast


def _public_only_connection(address, timeout=socket.getdefaulttimeout(), source_address=None, **kwargs):
    """`socket.create_connection`, refusing any peer that is not public.

    The check is on the address actually connected to, after DNS, so a host
    that resolves to a private address, or one that changes its answer
    between a check and the connect, is caught all the same. It runs before
    TLS, so nothing beyond the TCP handshake reaches a refused peer.
    """
    sock = socket.create_connection(address, timeout, source_address, **kwargs)
    peer = sock.getpeername()[0]
    if not _is_public(peer):
        sock.close()
        raise UnsafeFileUrl(f"file host resolved to non-public address {peer}")
    return sock


class _PublicHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = _public_only_connection


class _PublicHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PublicHTTPSConnection, req, context=self._context)


def _probe_opener() -> urllib.request.OpenerDirector:
    """An opener that speaks HTTPS to public addresses and nothing else.

    Built by hand rather than with `build_opener`, which would add handlers
    for `file://`, `ftp://` and `data:` URLs, honour proxy environment
    variables, and follow redirects. A redirect is exactly how an allowed URL
    would steer the probe somewhere else, so a 3xx here is an error response
    like any other.
    """
    opener = urllib.request.OpenerDirector()
    for handler in (
        _PublicHTTPSHandler(),
        urllib.request.HTTPErrorProcessor(),
        urllib.request.HTTPDefaultErrorHandler(),
    ):
        opener.add_handler(handler)
    return opener


def content_length(url: str, timeout: float = 5.0) -> int | None:
    """Size of the document behind a signed URL, or None when it cannot be read.

    Asking costs about a second. A document too large for the vault's throughput
    burns the whole interceptor timeout and then fails anyway, so asking first
    turns that into an immediate and explicit refusal.

    This requests a single byte rather than sending a HEAD. A presigned S3 URL
    is signed for one method, so a HEAD against a URL signed for GetObject is
    rejected with 403 and the size comes back unknown. A ranged GET uses the
    same signature and the `Content-Range` header carries the total.

    Raises `UnsafeFileUrl` for anything that is not a plain `https` URL, and
    for a host whose address is not public. The caller has already checked
    the URL against `files.urlPatterns`; this holds even if it had not.
    """
    if split_file_url(url) is None:
        raise UnsafeFileUrl("file URL is not a plain https URL on the default port")

    request = urllib.request.Request(url, headers={"Range": "bytes=0-0"})
    try:
        with _probe_opener().open(request, timeout=timeout) as response:
            content_range = response.headers.get("Content-Range")
            raw_length = response.headers.get("Content-Length")
            response.read(1)
    except urllib.error.HTTPError as exc:
        # A store that refuses the probe should not block de-identification;
        # Skyflow fetches the URL itself either way. A redirect lands here too
        # and is not followed.
        exc.close()
        if 300 <= exc.code < 400:
            logger.warning("file_size_probe_redirect_not_followed host=%s status=%d", host_of(url), exc.code)
        return None
    except (urllib.error.URLError, OSError, ValueError):
        return None

    if content_range and "/" in content_range:
        total = content_range.rsplit("/", 1)[1].strip()
        if total.isdigit():
            return int(total)
    try:
        # A store that ignores Range answers with the whole body length.
        return int(raw_length)
    except (TypeError, ValueError):
        return None
