"""Model selection.

The model id is read from the environment so it can be changed without a code
change — which model ids an account can actually reach depends on its Bedrock
model access, and the template's default is not always one of them.

Model calls go through the Skyflow gateway by default, so shield the model
keeps sensitive data out of what the model reads. See `model/gateway.py` for
the variables that control that.

| Variable | Description |
| --- | --- |
| `BEDROCK_MODEL_ID` | Bedrock model or inference-profile id. Defaults to the value below. Through the gateway it must name an Anthropic Claude model, because Flow speaks the Anthropic Messages API there. |
"""

import os

from strands.models.bedrock import BedrockModel

from model.gateway import resolve

DEFAULT_MODEL_ID = "global.anthropic.claude-sonnet-5"


def load_model():
    """The model client: Anthropic Messages through the gateway, or Bedrock directly."""
    model_id = os.getenv("BEDROCK_MODEL_ID", DEFAULT_MODEL_ID)
    gateway = resolve(model_id)
    if gateway is None:
        return BedrockModel(model_id=model_id)

    # Imported here so a deployment that calls Bedrock directly does not need
    # the Anthropic SDK at all.
    from strands.models.anthropic import AnthropicModel

    return AnthropicModel(client_args=gateway.client_args(), model_id=gateway.model, max_tokens=gateway.max_tokens)
