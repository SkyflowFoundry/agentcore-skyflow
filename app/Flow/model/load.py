"""Model selection.

The model id is read from the environment so it can be changed without a code
change — which model ids an account can actually reach depends on its Bedrock
model access, and the template's default is not always one of them.

| Variable | Description |
| --- | --- |
| `BEDROCK_MODEL_ID` | Bedrock model or inference-profile id. Defaults to the value below. |
"""

import os

from strands.models.bedrock import BedrockModel

DEFAULT_MODEL_ID = "global.anthropic.claude-sonnet-5"


def load_model() -> BedrockModel:
    """Get Bedrock model client using IAM credentials."""
    return BedrockModel(model_id=os.getenv("BEDROCK_MODEL_ID", DEFAULT_MODEL_ID))
