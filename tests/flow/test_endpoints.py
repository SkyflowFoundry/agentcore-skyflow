"""Endpoint discovery: which MCP endpoints the agent connects to, and how.

Stdlib only — `mcp_client.endpoints` deliberately imports nothing from the
agent's dependency tree so this suite needs no install step.

These tests live outside app/Flow/ because that directory is the CodeZip
deployment root: anything under it ships to the runtime.

Run: python3 tests/flow/test_endpoints.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "app" / "Flow"))

from mcp_client.endpoints import (  # noqa: E402
    AUTH_AWS_IAM,
    AUTH_CUSTOM_JWT,
    AUTH_NONE,
    Endpoint,
    discover_gateways,
    explicit_endpoints,
    resolve_endpoints,
    signing_region,
)

GATEWAY_URL = "https://example-gateway-abc123.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"

# What a deployed runtime actually gets: the CDK stack sets this pair for every
# gateway declared under agentCoreGateways in agentcore.json.
IN_PROJECT_ENV = {
    "AGENTCORE_GATEWAY_SKYFLOWGATEWAY_URL": GATEWAY_URL,
    "AGENTCORE_GATEWAY_SKYFLOWGATEWAY_AUTH_TYPE": "AWS_IAM",
}


class SigningRegionTestCase(unittest.TestCase):
    def test_read_from_the_gateway_host(self):
        self.assertEqual(signing_region(GATEWAY_URL), "us-east-1")

    def test_host_region_beats_the_ambient_region(self):
        """A gateway in another region must be signed for its own region."""
        other = GATEWAY_URL.replace("us-east-1", "eu-west-2")
        self.assertEqual(signing_region(other), "eu-west-2")

    def test_non_gateway_url_falls_back_to_the_environment(self):
        import os

        original = os.environ.get("AWS_REGION")
        os.environ["AWS_REGION"] = "us-west-2"
        try:
            self.assertEqual(signing_region("https://mcp.exa.ai/mcp"), "us-west-2")
        finally:
            if original is None:
                del os.environ["AWS_REGION"]
            else:
                os.environ["AWS_REGION"] = original


class DiscoverGatewaysTestCase(unittest.TestCase):
    def test_in_project_gateway(self):
        found = discover_gateways(IN_PROJECT_ENV)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].url, GATEWAY_URL)
        self.assertEqual(found[0].auth_type, AUTH_AWS_IAM)
        self.assertEqual(found[0].region, "us-east-1")

    def test_connection_style_gateway(self):
        found = discover_gateways({
            "GATEWAY_SKYFLOW_URL": GATEWAY_URL,
            "GATEWAY_SKYFLOW_AUTH_TYPE": "AWS_IAM",
            "GATEWAY_SKYFLOW_ARN": "arn:aws:bedrock-agentcore:us-east-1:0:gateway/g",
        })
        self.assertEqual([e.url for e in found], [GATEWAY_URL])
        self.assertEqual(found[0].source, "GATEWAY_SKYFLOW_URL")

    def test_the_same_gateway_under_both_prefixes_is_reported_once(self):
        found = discover_gateways({
            **IN_PROJECT_ENV,
            "GATEWAY_SKYFLOW_URL": GATEWAY_URL,
            "GATEWAY_SKYFLOW_AUTH_TYPE": "AWS_IAM",
        })
        self.assertEqual(len(found), 1)
        self.assertEqual(
            found[0].source, "AGENTCORE_GATEWAY_SKYFLOWGATEWAY_URL",
            "the in-project spelling wins, and which one wins must not depend on dict order",
        )

    def test_several_gateways_are_returned_in_a_stable_order(self):
        env = {
            "GATEWAY_ZULU_URL": "https://zulu.example.com/mcp",
            "GATEWAY_ALPHA_URL": "https://alpha.example.com/mcp",
            "AGENTCORE_GATEWAY_MIKE_URL": "https://mike.example.com/mcp",
        }
        sources = [e.source for e in discover_gateways(env)]
        self.assertEqual(
            sources,
            ["AGENTCORE_GATEWAY_MIKE_URL", "GATEWAY_ALPHA_URL", "GATEWAY_ZULU_URL"],
        )

    def test_auth_types_other_than_iam(self):
        for value, expected in (("NONE", AUTH_NONE), ("CUSTOM_JWT", AUTH_CUSTOM_JWT)):
            with self.subTest(value):
                found = discover_gateways({
                    "GATEWAY_X_URL": "https://x.example.com/mcp",
                    "GATEWAY_X_AUTH_TYPE": value,
                })
                self.assertEqual(found[0].auth_type, expected)

    def test_auth_type_is_case_insensitive(self):
        found = discover_gateways({
            "GATEWAY_X_URL": "https://x.example.com/mcp",
            "GATEWAY_X_AUTH_TYPE": " aws_iam ",
        })
        self.assertEqual(found[0].auth_type, AUTH_AWS_IAM)

    def test_missing_auth_type_assumes_iam(self):
        found = discover_gateways({"GATEWAY_X_URL": GATEWAY_URL})
        self.assertEqual(found[0].auth_type, AUTH_AWS_IAM)

    def test_unrecognised_auth_type_warns_and_assumes_iam(self):
        with self.assertLogs("mcp_client.endpoints", level="WARNING") as logs:
            found = discover_gateways({
                "GATEWAY_X_URL": GATEWAY_URL,
                "GATEWAY_X_AUTH_TYPE": "MUTUAL_TLS",
            })
        self.assertEqual(found[0].auth_type, AUTH_AWS_IAM)
        self.assertTrue(any("MUTUAL_TLS" in line for line in logs.output))

    def test_empty_url_is_skipped_with_a_warning(self):
        with self.assertLogs("mcp_client.endpoints", level="WARNING"):
            self.assertEqual(discover_gateways({"GATEWAY_X_URL": "   "}), [])

    def test_unrelated_variables_are_ignored(self):
        env = {
            "MEMORY_FLOWMEMORY_ID": "agentflow_FlowMemory-ikHKznFNkF",
            "GATEWAY_X_ARN": "arn:aws:bedrock-agentcore:us-east-1:0:gateway/g",
            "GATEWAY_X_CREDENTIAL_PROVIDER": "arn:aws:...",
            "SOME_OTHER_URL": "https://not-a-gateway.example.com",
            "AWS_REGION": "us-east-1",
        }
        self.assertEqual(discover_gateways(env), [])

    def test_empty_environment(self):
        self.assertEqual(discover_gateways({}), [])


class ExplicitEndpointsTestCase(unittest.TestCase):
    def test_unset_yields_nothing(self):
        self.assertEqual(explicit_endpoints({}), [])

    def test_comma_separated_list_is_split_and_trimmed(self):
        found = explicit_endpoints({"MCP_ENDPOINTS": " https://a.example/mcp , https://b.example/mcp ,, "})
        self.assertEqual([e.url for e in found], ["https://a.example/mcp", "https://b.example/mcp"])

    def test_no_bearer_token_means_no_auth(self):
        found = explicit_endpoints({"MCP_ENDPOINTS": "https://a.example/mcp"})
        self.assertEqual(found[0].auth_type, AUTH_NONE)

    def test_a_bearer_token_implies_custom_jwt(self):
        found = explicit_endpoints({
            "MCP_ENDPOINTS": "https://a.example/mcp",
            "MCP_BEARER_TOKEN": "abc123",
        })
        self.assertEqual(found[0].auth_type, AUTH_CUSTOM_JWT)

    def test_explicit_auth_type_wins(self):
        """Pointing MCP_ENDPOINTS at the gateway from a laptop must still sign."""
        found = explicit_endpoints({
            "MCP_ENDPOINTS": GATEWAY_URL,
            "MCP_AUTH_TYPE": "AWS_IAM",
        })
        self.assertEqual(found[0].auth_type, AUTH_AWS_IAM)
        self.assertEqual(found[0].region, "us-east-1")


class ResolveEndpointsTestCase(unittest.TestCase):
    def test_gateways_are_used_when_nothing_is_overridden(self):
        found = resolve_endpoints(IN_PROJECT_ENV)
        self.assertEqual([e.url for e in found], [GATEWAY_URL])

    def test_mcp_endpoints_replaces_discovery_rather_than_adding_to_it(self):
        """The override exists to take the gateway out of the path entirely."""
        found = resolve_endpoints({**IN_PROJECT_ENV, "MCP_ENDPOINTS": "https://direct.example/mcp"})
        self.assertEqual([e.url for e in found], ["https://direct.example/mcp"])

    def test_nothing_configured_stops_the_agent(self):
        """No silent fallback to a public server: that would take the gateway,
        and the Skyflow interceptor with it, out of the path unnoticed."""
        with self.assertRaisesRegex(RuntimeError, "MCP_ENDPOINTS"):
            resolve_endpoints({})

    def test_an_explicit_endpoint_still_works_without_a_gateway(self):
        found = resolve_endpoints({"MCP_ENDPOINTS": "https://mcp.exa.ai/mcp"})
        self.assertEqual([e.url for e in found], ["https://mcp.exa.ai/mcp"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
