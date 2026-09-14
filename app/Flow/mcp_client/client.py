"""MCP client wiring.

Endpoints come from the environment so the same agent can point at a local MCP
server, a third-party endpoint, or a deployed AgentCore Gateway without a code
change.

| Variable | Description |
| --- | --- |
| `MCP_ENDPOINTS` | Comma-separated streamable-HTTP MCP URLs. Unset falls back to the template example below. |
| `MCP_BEARER_TOKEN` | Bearer token sent to every endpoint in `MCP_ENDPOINTS`. Optional. |

An AgentCore Gateway is just another streamable-HTTP MCP endpoint. Point
`MCP_ENDPOINTS` at the gateway URL from `agentcore fetch access` and set
`MCP_BEARER_TOKEN` to the token it returns.
"""

import logging
import os

from mcp.client.streamable_http import streamablehttp_client
from strands.tools.mcp.mcp_client import MCPClient

logger = logging.getLogger(__name__)

# ExaAI provides information about code through web searches, crawling and code context
# searches through their platform. Requires no authentication. Template default only —
# set MCP_ENDPOINTS to replace it.
EXAMPLE_MCP_ENDPOINT = "https://mcp.exa.ai/mcp"


def _parse_endpoints() -> list[str]:
    """Read MCP_ENDPOINTS, falling back to the template example endpoint."""
    raw = os.getenv("MCP_ENDPOINTS", "").strip()
    if not raw:
        logger.warning(
            "MCP_ENDPOINTS is unset; falling back to the template example endpoint %s. "
            "Set MCP_ENDPOINTS to point at your own MCP server or AgentCore Gateway.",
            EXAMPLE_MCP_ENDPOINT,
        )
        return [EXAMPLE_MCP_ENDPOINT]
    return [url.strip() for url in raw.split(",") if url.strip()]


def _build_headers() -> dict:
    token = os.getenv("MCP_BEARER_TOKEN", "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def get_mcp_client(endpoint: str, headers: dict | None = None) -> MCPClient:
    """Return a Strands-compatible MCP client for a single streamable-HTTP endpoint."""
    headers = headers or {}
    return MCPClient(lambda: streamablehttp_client(endpoint, headers=headers))


def get_mcp_clients() -> list[MCPClient]:
    """Return one MCP client per configured endpoint."""
    headers = _build_headers()
    endpoints = _parse_endpoints()
    logger.info("Configuring %d MCP endpoint(s)", len(endpoints))
    return [get_mcp_client(endpoint, headers) for endpoint in endpoints]
