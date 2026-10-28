"""Model selection.

The model id is read from the environment so it can be changed without a code
change — which model ids an account can actually reach depends on its Bedrock
model access, and the template's default is not always one of them.

Model calls go through the Skyflow gateway by default, so shield the model
keeps sensitive data out of what the model reads. See `model/gateway.py` for
the variables that control that.

| Variable | Description |
| --- | --- |
| `BEDROCK_MODEL_ID` | Bedrock model or inference-profile id. Defaults to the value below. |
"""

import os

from strands.models.bedrock import BedrockModel

from model.gateway import GatewayModelAuth, resolve

DEFAULT_MODEL_ID = "global.anthropic.claude-sonnet-5"

#: A shielded answer is returned only once the whole of it has been generated
#: and re-identified, so a long answer can take minutes.
GATEWAY_TIMEOUT_SECONDS = 300.0


def load_model():
    """The model client: Anthropic Messages through the gateway, or Bedrock directly."""
    model_id = os.getenv("BEDROCK_MODEL_ID", DEFAULT_MODEL_ID)
    gateway = resolve(model_id)
    if gateway is None:
        return BedrockModel(model_id=model_id)

    # Imported here so a deployment that calls Bedrock directly does not need
    # the Anthropic SDK at all.
    import httpx
    from strands.models.anthropic import AnthropicModel

    return AnthropicModel(
        client_args={
            "base_url": gateway.base_url,
            # Required by the SDK and dropped by GatewayModelAuth before signing.
            "api_key": "unused-requests-are-sigv4-signed",
            "http_client": httpx.AsyncClient(
                auth=GatewayModelAuth(gateway.region), timeout=GATEWAY_TIMEOUT_SECONDS
            ),
        },
        model_id=gateway.model,
        max_tokens=gateway.max_tokens,
    )
