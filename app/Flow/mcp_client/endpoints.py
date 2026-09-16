"""Where the agent's MCP endpoints come from, and how each one authenticates.

Stdlib only. Keeping discovery free of the `mcp`, `strands` and `botocore`
imports means it can be tested without installing the agent's dependency tree.

AgentCore injects a pair of environment variables per reachable gateway at
deploy time, so the agent never hardcodes a URL:

| Variable | Set for |
| --- | --- |
| `AGENTCORE_GATEWAY_<NAME>_URL` / `_AUTH_TYPE` | Gateways declared in `agentcore.json` under `agentCoreGateways`; `<NAME>` is the gateway name upper-cased |
| `GATEWAY_<ID>_URL` / `_AUTH_TYPE` | Gateways reached through a runtime `connections` entry; `<ID>` is the connection id upper-cased |

Both forms carry the same `_AUTH_TYPE` values — `AWS_IAM`, `CUSTOM_JWT` or
`NONE` — which is how the agent knows whether to SigV4-sign, send a bearer
token, or send nothing.

Two variables override discovery, for local runs and for taking the gateway out
of the loop while debugging:

| Variable | Description |
| --- | --- |
| `MCP_ENDPOINTS` | Comma-separated MCP URLs. When set, these *replace* everything discovered. |
| `MCP_AUTH_TYPE` | Auth mode for those URLs. Defaults to `CUSTOM_JWT` when `MCP_BEARER_TOKEN` is set, else `NONE`. |
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

AUTH_AWS_IAM = "AWS_IAM"
AUTH_CUSTOM_JWT = "CUSTOM_JWT"
AUTH_NONE = "NONE"
AUTH_TYPES = (AUTH_AWS_IAM, AUTH_CUSTOM_JWT, AUTH_NONE)

# In-project gateways use the longer prefix. Sorting env keys puts it ahead of
# the bare one, so when a gateway surfaces under both, the in-project spelling
# is the one reported.
GATEWAY_ENV_PREFIXES = ("AGENTCORE_GATEWAY_", "GATEWAY_")

# ExaAI provides information about code through web searches, crawling and code
# context searches. Requires no authentication. Template default only — reached
# only when neither a gateway nor MCP_ENDPOINTS is configured.
EXAMPLE_MCP_ENDPOINT = "https://mcp.exa.ai/mcp"

# https://<id>.gateway.bedrock-agentcore.<region>.amazonaws.com/mcp
_GATEWAY_HOST_REGION = re.compile(r"\.gateway\.bedrock-agentcore\.([a-z0-9-]+)\.")


@dataclass(frozen=True)
class Endpoint:
    """One MCP endpoint and the credential it expects."""

    url: str
    auth_type: str
    #: Environment variable the endpoint came from, for log lines that have to
    #: name a misconfiguration without printing the URL.
    source: str
    #: Signing region, for AWS_IAM only.
    region: str | None = None


def signing_region(url: str) -> str | None:
    """Region to sign a gateway request for.

    Read from the host rather than `AWS_REGION`: a gateway reached through a
    `connections` entry may live in another region, and a signature is only
    valid for the region that serves the request.
    """
    match = _GATEWAY_HOST_REGION.search(url)
    if match:
        return match.group(1)
    return os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or None


def _normalize_auth(raw: str | None, source: str, default: str) -> str:
    value = (raw or "").strip().upper()
    if not value:
        return default
    if value not in AUTH_TYPES:
        logger.warning(
            "%s has unrecognised auth type %r; falling back to %s", source, value, default
        )
        return default
    return value


def discover_gateways(environ: dict | None = None) -> list[Endpoint]:
    """Return the gateways AgentCore wired into this runtime's environment."""
    environ = os.environ if environ is None else environ
    by_url: dict[str, Endpoint] = {}

    for key in sorted(environ):
        if not key.endswith("_URL"):
            continue
        prefix = next((p for p in GATEWAY_ENV_PREFIXES if key.startswith(p)), None)
        if prefix is None:
            continue

        url = (environ.get(key) or "").strip()
        if not url:
            logger.warning("%s is set but empty; skipping", key)
            continue

        token = key[len(prefix) : -len("_URL")]
        # A gateway with no _AUTH_TYPE is assumed IAM: every AgentCore deploy
        # sets the pair, so a missing one means a hand-written variable, and an
        # unsigned request to an IAM gateway fails in a way that reads as a
        # permissions bug rather than a config gap.
        auth_type = _normalize_auth(
            environ.get(f"{prefix}{token}_AUTH_TYPE"), key, AUTH_AWS_IAM
        )
        by_url.setdefault(
            url,
            Endpoint(url=url, auth_type=auth_type, source=key, region=signing_region(url)),
        )

    return list(by_url.values())


def explicit_endpoints(environ: dict | None = None) -> list[Endpoint]:
    """Return the endpoints named in MCP_ENDPOINTS, if any."""
    environ = os.environ if environ is None else environ

    raw = (environ.get("MCP_ENDPOINTS") or "").strip()
    if not raw:
        return []

    bearer = (environ.get("MCP_BEARER_TOKEN") or "").strip()
    default = AUTH_CUSTOM_JWT if bearer else AUTH_NONE
    auth_type = _normalize_auth(environ.get("MCP_AUTH_TYPE"), "MCP_AUTH_TYPE", default)

    urls = [part.strip() for part in raw.split(",")]
    return [
        Endpoint(
            url=url,
            auth_type=auth_type,
            source="MCP_ENDPOINTS",
            region=signing_region(url),
        )
        for url in urls
        if url
    ]


def resolve_endpoints(environ: dict | None = None) -> list[Endpoint]:
    """Return every MCP endpoint the agent should connect to.

    `MCP_ENDPOINTS` wins outright when set — it is an override, so it can point
    the agent straight at an upstream server and take the gateway (and its
    interceptors) out of the path.
    """
    environ = os.environ if environ is None else environ

    explicit = explicit_endpoints(environ)
    if explicit:
        logger.info("Using %d endpoint(s) from MCP_ENDPOINTS; gateway discovery skipped", len(explicit))
        return explicit

    gateways = discover_gateways(environ)
    if gateways:
        logger.info("Discovered %d gateway endpoint(s) from the environment", len(gateways))
        return gateways

    logger.warning(
        "No gateway environment variables and no MCP_ENDPOINTS; falling back to the "
        "template example endpoint %s. Deploy a gateway or set MCP_ENDPOINTS.",
        EXAMPLE_MCP_ENDPOINT,
    )
    return [Endpoint(url=EXAMPLE_MCP_ENDPOINT, auth_type=AUTH_NONE, source="fallback")]
