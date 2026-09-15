"""Credential selection per endpoint auth type.

Needs httpx and botocore; no AWS account and no network.

Run: python3 tests/flow/test_auth.py
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "app" / "Flow"))

import mcp_client.sigv4 as sigv4  # noqa: E402
from botocore.credentials import ReadOnlyCredentials  # noqa: E402
from mcp_client.auth import build_auth  # noqa: E402
from mcp_client.endpoints import AUTH_AWS_IAM, AUTH_CUSTOM_JWT, AUTH_NONE, Endpoint  # noqa: E402
from mcp_client.sigv4 import SigV4Auth  # noqa: E402

GATEWAY_URL = "https://agentflow-skyflowgateway-k7lrzhryea.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"


class BearerTokenMixin(unittest.TestCase):
    """Set MCP_BEARER_TOKEN for the duration of a test, whatever the shell has."""

    def set_bearer(self, value: str | None) -> None:
        original = os.environ.get("MCP_BEARER_TOKEN")
        self.addCleanup(
            lambda: os.environ.__setitem__("MCP_BEARER_TOKEN", original)
            if original is not None
            else os.environ.pop("MCP_BEARER_TOKEN", None)
        )
        if value is None:
            os.environ.pop("MCP_BEARER_TOKEN", None)
        else:
            os.environ["MCP_BEARER_TOKEN"] = value


class FakeCredentials:
    def get_frozen_credentials(self):
        return ReadOnlyCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI", None)


class FakeSession:
    def get_credentials(self):
        return FakeCredentials()


class AwsIamTestCase(unittest.TestCase):
    def setUp(self):
        # build_auth resolves credentials through botocore's default chain.
        # Swap it out so the suite does not depend on the machine it runs on.
        self._real_get_session = sigv4.get_session
        sigv4.get_session = FakeSession
        self.addCleanup(lambda: setattr(sigv4, "get_session", self._real_get_session))

    def test_returns_a_sigv4_signer_and_no_headers(self):
        endpoint = Endpoint(GATEWAY_URL, AUTH_AWS_IAM, "GATEWAY_X_URL", region="us-east-1")
        auth, headers = build_auth(endpoint)
        self.assertIsInstance(auth, SigV4Auth)
        self.assertEqual(headers, {}, "a signed request carries no static credential header")

    def test_the_signer_is_built_for_the_endpoint_region(self):
        endpoint = Endpoint(GATEWAY_URL, AUTH_AWS_IAM, "GATEWAY_X_URL", region="eu-west-2")
        auth, _ = build_auth(endpoint)
        self.assertEqual(auth._region, "eu-west-2")

    def test_a_region_that_could_not_be_resolved_fails_loudly(self):
        """Signing for the wrong region fails at the gateway; refuse to start instead."""
        endpoint = Endpoint(GATEWAY_URL, AUTH_AWS_IAM, "GATEWAY_X_URL", region=None)
        with self.assertRaises(RuntimeError) as ctx:
            build_auth(endpoint)
        self.assertIn("GATEWAY_X_URL", str(ctx.exception))


class CustomJwtTestCase(BearerTokenMixin):
    def test_bearer_header_is_built_from_the_token(self):
        self.set_bearer("abc123")
        auth, headers = build_auth(Endpoint("https://x.example/mcp", AUTH_CUSTOM_JWT, "GATEWAY_X_URL"))
        self.assertIsNone(auth)
        self.assertEqual(headers, {"Authorization": "Bearer abc123"})

    def test_a_missing_token_warns_and_sends_nothing(self):
        self.set_bearer(None)
        with self.assertLogs("mcp_client.auth", level="WARNING") as logs:
            auth, headers = build_auth(Endpoint("https://x.example/mcp", AUTH_CUSTOM_JWT, "GATEWAY_X_URL"))
        self.assertEqual((auth, headers), (None, {}))
        self.assertTrue(any("MCP_BEARER_TOKEN" in line for line in logs.output))

    def test_a_whitespace_only_token_counts_as_missing(self):
        self.set_bearer("   ")
        with self.assertLogs("mcp_client.auth", level="WARNING"):
            _, headers = build_auth(Endpoint("https://x.example/mcp", AUTH_CUSTOM_JWT, "GATEWAY_X_URL"))
        self.assertEqual(headers, {})


class NoAuthTestCase(BearerTokenMixin):
    def test_nothing_is_attached(self):
        self.assertEqual(
            build_auth(Endpoint("https://mcp.exa.ai/mcp", AUTH_NONE, "fallback")), (None, {})
        )

    def test_a_stray_bearer_token_is_not_sent_to_a_none_endpoint(self):
        """The token belongs to a JWT gateway; leaking it to an upstream server would be worse
        than an unauthenticated call."""
        self.set_bearer("abc123")
        self.assertEqual(
            build_auth(Endpoint("https://mcp.exa.ai/mcp", AUTH_NONE, "fallback")), (None, {})
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
