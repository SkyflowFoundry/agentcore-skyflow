"""Route the agent's model calls through the Skyflow gateway, so shield the model applies.

The gateway's inference target fronts Amazon Bedrock on `<gateway>/inference`,
and the gateway's interceptor de-identifies what the model reads and
re-identifies what it writes. The gateway speaks the Anthropic Messages API
rather than Bedrock's Converse API, so Flow talks to it with Strands' Anthropic
model instead of `BedrockModel`.

| Variable | Description |
| --- | --- |
| `MODEL_VIA_GATEWAY` | `0` sends model calls straight to Bedrock instead. Default `1` |
| `MODEL_GATEWAY_URL` | The gateway's MCP URL to send model calls to. Default: the first `AWS_IAM` gateway discovered |
| `MODEL_GATEWAY_TARGET` | Inference target the model id is qualified with. Default `bedrock` |
| `MODEL_MAX_TOKENS` | Longest answer in tokens. Default 4096 |

This module imports no Strands, so `tests/flow` can exercise it without the SDK.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from dataclasses import dataclass

import httpx

from mcp_client.endpoints import AUTH_AWS_IAM, discover_gateways, signing_region
from mcp_client.sigv4 import SigV4Auth

DEFAULT_TARGET = "bedrock"
DEFAULT_MAX_TOKENS = 4096
OFF = ("0", "false", "no", "off")


@dataclass(frozen=True)
class ModelGateway:
    """Where model calls go and how they are signed."""

    base_url: str
    region: str
    model: str
    max_tokens: int


def resolve(model_id: str, environ: dict | None = None) -> ModelGateway | None:
    """The gateway to send model calls to, or None to call Bedrock directly.

    None when `MODEL_VIA_GATEWAY` is off or no IAM gateway is reachable, which
    is the case in local development without a deployed gateway.
    """
    environ = os.environ if environ is None else environ
    if (environ.get("MODEL_VIA_GATEWAY") or "1").strip().lower() in OFF:
        return None
    url = (environ.get("MODEL_GATEWAY_URL") or "").strip() or _discovered(environ)
    if not url:
        return None
    region = signing_region(url)
    if not region:
        raise RuntimeError("Cannot tell which region the model gateway is in; set AWS_REGION")
    target = (environ.get("MODEL_GATEWAY_TARGET") or DEFAULT_TARGET).strip()
    return ModelGateway(
        base_url=inference_url(url),
        region=region,
        model=qualified_model(model_id, target),
        max_tokens=int(environ.get("MODEL_MAX_TOKENS") or DEFAULT_MAX_TOKENS),
    )


def _discovered(environ: dict) -> str | None:
    for endpoint in discover_gateways(environ):
        if endpoint.auth_type == AUTH_AWS_IAM:
            return endpoint.url
    return None


def inference_url(gateway_url: str) -> str:
    """The Anthropic SDK's base URL for a gateway, from the gateway's MCP URL."""
    url = gateway_url.rstrip("/")
    if url.endswith("/mcp"):
        url = url[: -len("/mcp")]
    return f"{url}/inference"


def qualified_model(model_id: str, target: str) -> str:
    """Pin the model to one inference target, as in `bedrock/<model id>`.

    Unqualified, the gateway picks among every target that serves the model,
    and picks at random when no Bedrock target is among them.
    """
    if not target or model_id.startswith(f"{target}/"):
        return model_id
    return f"{target}/{model_id}"


class GatewayModelAuth(SigV4Auth):
    """SigV4 for model calls.

    The Anthropic SDK will not start without an API key and sends it as
    `x-api-key`. The gateway authenticates by signature and forwards client
    headers to the provider, so the header is dropped before signing.
    """

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers.pop("x-api-key", None)
        yield from super().auth_flow(request)
