"""Turning a discovered endpoint's auth type into something httpx can send.

Sits between `mcp_client.endpoints` (stdlib only) and `mcp_client.client`
(which pulls in the MCP and Strands packages), so the credential decisions can
be exercised without the agent's full dependency tree.
"""

from __future__ import annotations

import logging
import os

from mcp_client.endpoints import AUTH_AWS_IAM, AUTH_CUSTOM_JWT, Endpoint

logger = logging.getLogger(__name__)


def build_auth(endpoint: Endpoint) -> tuple[object | None, dict]:
    """Return the `(httpx auth, extra headers)` pair one endpoint needs.

    Raises rather than degrading to an unauthenticated connection: an agent
    that silently loses its tools is harder to diagnose than one that fails to
    start.
    """
    if endpoint.auth_type == AUTH_AWS_IAM:
        if not endpoint.region:
            raise RuntimeError(
                f"{endpoint.source} needs SigV4 signing but no region could be determined "
                "from its URL or from AWS_REGION"
            )
        # Imported here so an agent that only talks to unauthenticated or
        # bearer-token endpoints never pays for botocore's import.
        from mcp_client.sigv4 import SigV4Auth

        return SigV4Auth(region=endpoint.region), {}

    if endpoint.auth_type == AUTH_CUSTOM_JWT:
        token = os.environ.get("MCP_BEARER_TOKEN", "").strip()
        if not token:
            # Fetching a token from the provider named by
            # GATEWAY_<ID>_CREDENTIAL_PROVIDER is not implemented; supply the
            # token directly for now.
            logger.warning(
                "%s expects CUSTOM_JWT but MCP_BEARER_TOKEN is unset; sending no credential",
                endpoint.source,
            )
            return None, {}
        return None, {"Authorization": f"Bearer {token}"}

    return None, {}
