"""Making transport failures legible.

Strands reports any MCP transport failure as "Connection to the MCP server was
closed", which hides both the status code and the server's explanation. A 400
from a gateway with a precise message about a missing IAM permission is
indistinguishable from a 403, a timeout or a DNS failure. This module exists to
put the server's own words in the log.

httpx only, so it can be tested without the MCP or Strands packages.

An error body can carry credentials. AWS answers a SigV4 signature mismatch
with the canonical request it computed, which lists every signed header with
its value, `x-amz-security-token` included; an upstream may echo a bearer or
basic token it was sent; a tool error may echo an `api_key` argument. The body
is therefore masked before it is logged, so this log line can name the failure
without ever holding a token.
"""

from __future__ import annotations

import logging
import re

import httpx

logger = logging.getLogger(__name__)

#: Cap on a logged error body. Enough for a gateway's message, short enough that
#: a large one cannot flood the log.
MAX_LOGGED_ERROR_BODY = 2000

REDACTED = "<redacted>"

#: Credential-bearing patterns in free text, in the order they are applied.
#: The specific shapes go first and the `Name: value` catch-all last, so a
#: scheme word is not masked away before the credential that follows it. Every
#: quantifier runs over a class that excludes its own delimiter, so matching
#: stays linear on a hostile body.
_CREDENTIAL_PATTERNS = (
    # A JSON field whose name marks it as a secret.
    (re.compile(r'(?i)"([^"]*(?:authorization|api[_-]?key|token|secret|password|credential)[^"]*)"\s*:\s*"[^"]*"'),
     rf'"\1": "{REDACTED}"'),
    # A SigV4 Authorization value: the Credential= part names the access key
    # and the Signature= part is the signature.
    (re.compile(r"(?:AWS4-HMAC-SHA256\s+)?Credential=[^,\s]+(?:,\s*SignedHeaders=[^,\s]+)?(?:,\s*Signature=[0-9a-f]+)?"),
     f"AWS4-HMAC-SHA256 {REDACTED}"),
    # An HTTP auth scheme followed by its credential, wherever it appears.
    (re.compile(r"(?i)\b(bearer|basic|digest)\s+[A-Za-z0-9._~+/=-]{8,}"), rf"\1 {REDACTED}"),
    # A header line in `Name: value` or canonical-request `name:value` form.
    # The value runs to the end of the line or a quote, so a token cut off by
    # the length cap is still caught.
    (re.compile(r"(?i)\b(authorization|proxy-authorization|x-amz-security-token|"
                r"x-api-key|cookie|set-cookie)\s*[:=]\s*[^\n\"]+"), rf"\1: {REDACTED}"),
)


def redact_credentials(text: str) -> str:
    """Mask credential-shaped content in an error body before it is logged."""
    for pattern, replacement in _CREDENTIAL_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


async def log_http_errors(response: httpx.Response) -> None:
    """Log the status and body of a failed MCP response.

    Only error responses are read. A success may be an SSE stream the caller
    consumes incrementally, and reading it here would break that.
    """
    if response.status_code < 400:
        return
    try:
        await response.aread()
        body = redact_credentials(response.text[:MAX_LOGGED_ERROR_BODY])
    except Exception:  # noqa: BLE001 - diagnostics must never mask the real failure
        body = "<unreadable>"
    logger.error("MCP endpoint returned HTTP %s: %s", response.status_code, body)
