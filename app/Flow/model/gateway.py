"""Route the agent's model calls through the Skyflow gateway, so shield the model applies.

The gateway's inference target fronts Amazon Bedrock on `<gateway>/inference`,
and the gateway's interceptor de-identifies what the model reads and
re-identifies what it writes. The gateway speaks the Anthropic Messages API
rather than Bedrock's Converse API, so Flow talks to it with Strands' Anthropic
model instead of `BedrockModel`.

| Variable | Description |
| --- | --- |
| `MODEL_VIA_GATEWAY` | `0` sends model calls straight to Bedrock instead. Default `1` |
| `MODEL_GATEWAY_URL` | The gateway's MCP URL to send model calls to. Default: the one `AWS_IAM` gateway discovered |
| `MODEL_GATEWAY_TARGET` | Inference target the model id is qualified with. Default `bedrock` |
| `MODEL_MAX_TOKENS` | Longest answer in tokens, thinking included. Default 32000 |

With `MODEL_VIA_GATEWAY` on, a runtime that cannot tell which gateway to use
refuses to start rather than send its model calls past the shield. That is
the case with no `AWS_IAM` gateway, or with more than one and no
`MODEL_GATEWAY_URL`.

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
#: The Messages API needs a ceiling where Converse needed none. Thinking counts
#: against it, so it is set well above any answer Flow writes.
DEFAULT_MAX_TOKENS = 32000
OFF = ("0", "false", "no", "off")

#: A shielded answer is returned only once the whole of it has been generated
#: and re-identified, so a long answer can take minutes.
TIMEOUT_SECONDS = 900.0


@dataclass(frozen=True)
class ModelGateway:
    """Where model calls go and how they are signed."""

    base_url: str
    region: str
    model: str
    max_tokens: int

    def client_args(self, session=None) -> dict:
        """Keyword arguments for the Anthropic SDK client behind Strands' `AnthropicModel`.

        `session` is the botocore session to sign with, the default one when None.
        """
        return {
            "base_url": self.base_url,
            # Required by the SDK and dropped by GatewayModelAuth before signing.
            "api_key": "unused-requests-are-sigv4-signed",
            "http_client": httpx.AsyncClient(
                auth=GatewayModelAuth(self.region, session=session), timeout=TIMEOUT_SECONDS
            ),
            # The SDK retries twice by default, and each retry runs the model
            # and Skyflow again. Strands already retries a throttled call with
            # backoff, so the SDK does not retry at all.
            "max_retries": 0,
        }


def resolve(model_id: str, environ: dict | None = None) -> ModelGateway | None:
    """The gateway to send model calls to, or None when `MODEL_VIA_GATEWAY` is off.

    Raises RuntimeError when it is on and there is no single gateway to use,
    because falling back to Bedrock would skip the shield without a word.
    """
    environ = os.environ if environ is None else environ
    if (environ.get("MODEL_VIA_GATEWAY") or "1").strip().lower() in OFF:
        return None
    url = (environ.get("MODEL_GATEWAY_URL") or "").strip() or _discovered(environ)
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


def _discovered(environ: dict) -> str:
    """The one AWS_IAM gateway wired into this runtime."""
    found = [endpoint for endpoint in discover_gateways(environ) if endpoint.auth_type == AUTH_AWS_IAM]
    if len(found) == 1:
        return found[0].url
    if not found:
        raise RuntimeError(
            "Model calls go through the gateway but no AWS_IAM gateway is wired into this runtime. "
            "Set MODEL_GATEWAY_URL, or set MODEL_VIA_GATEWAY=0 to call Bedrock directly."
        )
    names = ", ".join(endpoint.source for endpoint in found)
    raise RuntimeError(f"Several AWS_IAM gateways could take model calls ({names}). Set MODEL_GATEWAY_URL to one.")


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
