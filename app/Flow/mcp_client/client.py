"""MCP client wiring.

The agent's tools come from whatever MCP endpoints the environment advertises.
In a deployed runtime that is the AgentCore Gateway declared in
`agentcore.json`, which means every tool call and every tool response passes
through the gateway's Skyflow de-identify/re-identify interceptors without the
agent knowing about them.

`mcp_client.endpoints` documents the environment variables. Nothing here is
hardcoded to a gateway: point `MCP_ENDPOINTS` somewhere else and the same code
talks to a local server or a third-party endpoint.
"""

import logging

from mcp.client.streamable_http import streamablehttp_client
from strands.tools.mcp.mcp_client import MCPClient

from mcp_client.auth import build_auth
from mcp_client.endpoints import EXAMPLE_MCP_ENDPOINT, resolve_endpoints

logger = logging.getLogger(__name__)

__all__ = ["EXAMPLE_MCP_ENDPOINT", "build_auth", "get_mcp_client", "get_mcp_clients"]


def get_mcp_client(endpoint: str, headers: dict | None = None, auth=None) -> MCPClient:
    """Return a Strands-compatible MCP client for a single streamable-HTTP endpoint."""
    headers = headers or {}
    return MCPClient(lambda: streamablehttp_client(endpoint, headers=headers, auth=auth))


def get_mcp_clients() -> list[MCPClient]:
    """Return one MCP client per endpoint the environment advertises."""
    clients = []
    for endpoint in resolve_endpoints():
        auth, headers = build_auth(endpoint)
        logger.info(
            "MCP endpoint from %s: %s (auth=%s)", endpoint.source, endpoint.url, endpoint.auth_type
        )
        clients.append(get_mcp_client(endpoint.url, headers=headers, auth=auth))
    logger.info("Configured %d MCP endpoint(s)", len(clients))
    return clients
