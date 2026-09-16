"""Making transport failures legible.

Strands reports any MCP transport failure as "Connection to the MCP server was
closed", which hides both the status code and the server's explanation. A 400
from a gateway with a precise message about a missing IAM permission is
indistinguishable from a 403, a timeout or a DNS failure. This module exists to
put the server's own words in the log.

httpx only, so it can be tested without the MCP or Strands packages.
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)

#: Cap on a logged error body. Enough for a gateway's message, short enough that
#: a large one cannot flood the log.
MAX_LOGGED_ERROR_BODY = 2000


async def log_http_errors(response: httpx.Response) -> None:
    """Log the status and body of a failed MCP response.

    Only error responses are read. A success may be an SSE stream the caller
    consumes incrementally, and reading it here would break that.
    """
    if response.status_code < 400:
        return
    try:
        await response.aread()
        body = response.text[:MAX_LOGGED_ERROR_BODY]
    except Exception:  # noqa: BLE001 - diagnostics must never mask the real failure
        body = "<unreadable>"
    logger.error("MCP endpoint returned HTTP %s: %s", response.status_code, body)
