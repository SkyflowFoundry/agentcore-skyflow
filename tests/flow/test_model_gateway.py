"""Model calls through the Skyflow gateway, so shield the model applies.

Needs httpx and botocore, but no Strands, no AWS account and no network.

Run: python3 tests/flow/test_model_gateway.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "app" / "Flow"))

import httpx  # noqa: E402
from botocore.credentials import ReadOnlyCredentials  # noqa: E402

from model.gateway import GatewayModelAuth, inference_url, qualified_model, resolve  # noqa: E402

MCP_URL = "https://skyflowgateway-abc123.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"
MODEL = "global.anthropic.claude-sonnet-5"
INJECTED = {
    "AGENTCORE_GATEWAY_SKYFLOWGATEWAY_URL": MCP_URL,
    "AGENTCORE_GATEWAY_SKYFLOWGATEWAY_AUTH_TYPE": "AWS_IAM",
}


class FakeSession:
    def get_credentials(self):
        return self

    def get_frozen_credentials(self):
        return ReadOnlyCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI", None)


class ResolveTestCase(unittest.TestCase):
    def test_model_calls_go_through_the_gateway_by_default(self):
        gateway = resolve(MODEL, INJECTED)
        self.assertEqual(
            gateway.base_url,
            "https://skyflowgateway-abc123.gateway.bedrock-agentcore.us-east-1.amazonaws.com/inference",
        )
        self.assertEqual(gateway.region, "us-east-1")
        self.assertEqual(gateway.model, f"bedrock/{MODEL}")
        self.assertEqual(gateway.max_tokens, 4096)

    def test_it_can_be_turned_off(self):
        for value in ("0", "false", "No", "off"):
            with self.subTest(value=value):
                self.assertIsNone(resolve(MODEL, {**INJECTED, "MODEL_VIA_GATEWAY": value}))

    def test_without_a_gateway_flow_calls_bedrock_directly(self):
        """Local development without a deployed gateway keeps working."""
        self.assertIsNone(resolve(MODEL, {}))

    def test_a_gateway_without_iam_auth_is_not_used_for_models(self):
        env = {"GATEWAY_OTHER_URL": "https://other.example.com/mcp", "GATEWAY_OTHER_AUTH_TYPE": "CUSTOM_JWT"}
        self.assertIsNone(resolve(MODEL, env))

    def test_an_explicit_url_and_target_win(self):
        other = "https://other-xyz.gateway.bedrock-agentcore.eu-west-2.amazonaws.com/mcp"
        gateway = resolve(MODEL, {**INJECTED, "MODEL_GATEWAY_URL": other, "MODEL_GATEWAY_TARGET": "anthropic",
                                  "MODEL_MAX_TOKENS": "1024"})
        self.assertEqual(gateway.region, "eu-west-2")
        self.assertEqual(gateway.model, f"anthropic/{MODEL}")
        self.assertEqual(gateway.max_tokens, 1024)


class HelpersTestCase(unittest.TestCase):
    def test_the_inference_url_replaces_the_mcp_path(self):
        self.assertTrue(inference_url(MCP_URL + "/").endswith(".amazonaws.com/inference"))

    def test_a_model_is_qualified_once(self):
        self.assertEqual(qualified_model(MODEL, "bedrock"), f"bedrock/{MODEL}")
        self.assertEqual(qualified_model(f"bedrock/{MODEL}", "bedrock"), f"bedrock/{MODEL}")
        self.assertEqual(qualified_model(MODEL, ""), MODEL)


class AuthTestCase(unittest.TestCase):
    def sign(self) -> httpx.Request:
        request = httpx.Request("POST", "https://g.gateway.bedrock-agentcore.us-east-1.amazonaws.com/inference/v1/messages",
                                json={"model": MODEL}, headers={"x-api-key": "unused", "anthropic-version": "2023-06-01"})
        return next(GatewayModelAuth("us-east-1", session=FakeSession()).auth_flow(request))

    def test_the_sdk_api_key_never_leaves_the_agent(self):
        self.assertNotIn("x-api-key", self.sign().headers)

    def test_the_call_is_signed_for_the_gateway(self):
        signed = self.sign()
        self.assertIn("/us-east-1/bedrock-agentcore/aws4_request", signed.headers["authorization"])
        self.assertIn("anthropic-version", signed.headers["authorization"], "the version header is signed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
