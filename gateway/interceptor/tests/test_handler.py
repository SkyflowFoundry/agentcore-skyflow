"""Offline tests for the interceptor. No AWS, no Skyflow, stdlib unittest only.

Run: python3 gateway/interceptor/tests/test_handler.py
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

# Set explicitly, not via setdefault: ambient values (a developer with
# SKYFLOW_VAULT_ID exported, say) would otherwise leak into the tests.
os.environ["POLICY_PARAMETER_NAME"] = "/test/policy"
os.environ["SKYFLOW_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:0:secret:test"
os.environ["SKYFLOW_VAULT_URL"] = "https://test.vault.skyflowapis.com"
os.environ["SKYFLOW_VAULT_ID"] = "vault123"

import handler  # noqa: E402
import settings  # noqa: E402
from policy import PolicyError, PolicySet  # noqa: E402
from skyflow_client import SkyflowError  # noqa: E402


SHIELD_THE_TOOL = {
    "defaults": {
        "request": {"action": "deidentify", "tokenType": "vault_token"},
        "response": {"action": "reidentify"},
        "entities": ["name", "email_address"],
        "scope": {"minLength": 4, "excludeKeys": ["api_key"]},
        "failure": {"onError": "fail_closed"},
    },
    "toolNameSeparator": "___",
    "overrides": [
        {"servers": ["exa"], "tools": ["get_code_context*"],
         "request": {"action": "none"}, "response": {"action": "none"}},
    ],
}


class FakeClient:
    """Stands in for SkyflowClient. Deterministic, reversible, counts calls."""

    def __init__(self, fail: bool = False):
        self.fail = fail
        self.deidentify_calls: list[str] = []
        self.reidentify_calls: list[str] = []

    def deidentify(self, text, entity_types, vault_token_entity_types=None):
        if self.fail:
            raise SkyflowError("boom")
        self.deidentify_calls.append(text)
        return type("R", (), {"processed_text": f"TOK({text})", "entities": []})()

    def reidentify(self, text):
        if self.fail:
            raise SkyflowError("boom")
        self.reidentify_calls.append(text)
        restored = text[4:-1] if text.startswith("TOK(") and text.endswith(")") else text
        return type("R", (), {"text": restored})()


class InterceptorTestCase(unittest.TestCase):
    def setUp(self):
        self.client = FakeClient()
        self._real_load = settings.load_policy
        self._real_build = settings.build_client
        settings.load_policy = lambda force=False: PolicySet.from_json(SHIELD_THE_TOOL)
        settings.build_client = lambda: self.client

    def tearDown(self):
        settings.load_policy = self._real_load
        settings.build_client = self._real_build

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def request_event(method="tools/call", name="exa___web_search_exa", arguments=None):
        body = {"jsonrpc": "2.0", "id": 1, "method": method}
        if method == "tools/call":
            body["params"] = {"name": name, "arguments": arguments or {}}
        return {"interceptorInputVersion": "1.0", "mcp": {"gatewayRequest": {"body": body}}}

    @staticmethod
    def response_event(name="exa___web_search_exa", result=None, streaming=False):
        gateway_response = {
            "statusCode": 200,
            "body": {"jsonrpc": "2.0", "id": 1, "result": result if result is not None else {}},
        }
        if streaming:
            gateway_response["isStreamingResponse"] = True
        return {
            "interceptorInputVersion": "1.0",
            "mcp": {
                "gatewayRequest": {
                    "body": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                             "params": {"name": name, "arguments": {}}}
                },
                "gatewayResponse": gateway_response,
            },
        }

    # -- request path ----------------------------------------------------

    def test_tools_list_passes_through_untouched(self):
        event = self.request_event(method="tools/list")
        out = handler.lambda_handler(event, None)
        body = out["mcp"]["transformedGatewayRequest"]["body"]
        self.assertEqual(body["method"], "tools/list")
        self.assertEqual(self.client.deidentify_calls, [])

    def test_request_deidentifies_arguments(self):
        event = self.request_event(arguments={"query": "contact Jane Doe jane@example.com"})
        out = handler.lambda_handler(event, None)
        args = out["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]
        self.assertEqual(args["query"], "TOK(contact Jane Doe jane@example.com)")
        self.assertEqual(len(self.client.deidentify_calls), 1)

    def test_request_respects_excluded_keys_and_min_length(self):
        event = self.request_event(arguments={"query": "a long enough value", "api_key": "secret-value", "n": "ab"})
        out = handler.lambda_handler(event, None)
        args = out["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]
        self.assertTrue(args["query"].startswith("TOK("))
        self.assertEqual(args["api_key"], "secret-value", "excluded key must not be sent")
        self.assertEqual(args["n"], "ab", "value under minLength must not be sent")

    def test_override_disables_interception_for_matching_tool(self):
        event = self.request_event(name="exa___get_code_context_exa", arguments={"query": "some long query"})
        out = handler.lambda_handler(event, None)
        args = out["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]
        self.assertEqual(args["query"], "some long query")
        self.assertEqual(self.client.deidentify_calls, [])

    def test_request_fail_closed_short_circuits_with_jsonrpc_error(self):
        settings.build_client = lambda: FakeClient(fail=True)
        event = self.request_event(arguments={"query": "contact Jane Doe"})
        out = handler.lambda_handler(event, None)
        self.assertIn("transformedGatewayResponse", out["mcp"])
        self.assertNotIn("transformedGatewayRequest", out["mcp"])
        self.assertEqual(out["mcp"]["transformedGatewayResponse"]["body"]["error"]["code"], -32603)

    def test_request_fail_open_forwards_original(self):
        settings.build_client = lambda: FakeClient(fail=True)
        open_policy = {**SHIELD_THE_TOOL,
                       "defaults": {**SHIELD_THE_TOOL["defaults"], "failure": {"onError": "fail_open"}}}
        settings.load_policy = lambda force=False: PolicySet.from_json(open_policy)
        event = self.request_event(arguments={"query": "contact Jane Doe"})
        out = handler.lambda_handler(event, None)
        args = out["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]
        self.assertEqual(args["query"], "contact Jane Doe")

    # -- response path ---------------------------------------------------

    def test_response_reidentifies_content_blocks(self):
        result = {"content": [{"type": "text", "text": "TOK(Jane Doe lives in Denver)"}]}
        out = handler.lambda_handler(self.response_event(result=result), None)
        text = out["mcp"]["transformedGatewayResponse"]["body"]["result"]["content"][0]["text"]
        self.assertEqual(text, "Jane Doe lives in Denver")

    def test_response_without_result_passes_through(self):
        """A REQUEST short circuit still invokes the RESPONSE interceptor on MCP."""
        event = self.response_event()
        event["mcp"]["gatewayResponse"]["body"] = {
            "jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "blocked"},
        }
        out = handler.lambda_handler(event, None)
        self.assertEqual(out["mcp"]["transformedGatewayResponse"]["body"]["error"]["message"], "blocked")
        self.assertEqual(self.client.reidentify_calls, [])

    def test_streaming_response_omits_status_code(self):
        result = {"content": [{"type": "text", "text": "TOK(Jane Doe lives here)"}]}
        out = handler.lambda_handler(self.response_event(result=result, streaming=True), None)
        transformed = out["mcp"]["transformedGatewayResponse"]
        self.assertNotIn("statusCode", transformed)

    def test_non_streaming_response_sets_status_code(self):
        result = {"content": [{"type": "text", "text": "TOK(Jane Doe lives here)"}]}
        out = handler.lambda_handler(self.response_event(result=result), None)
        self.assertEqual(out["mcp"]["transformedGatewayResponse"]["statusCode"], 200)

    # -- payload shapes --------------------------------------------------

    def test_http_payload_passes_through(self):
        out = handler.lambda_handler({"http": {"gatewayRequest": {"body": "eyJhIjoxfQ=="}}}, None)
        self.assertEqual(out, {"interceptorOutputVersion": "1.0", "http": {}})

    def test_round_trip_request_then_response(self):
        original = "contact Jane Doe jane@example.com"
        req_out = handler.lambda_handler(self.request_event(arguments={"query": original}), None)
        tokenized = req_out["mcp"]["transformedGatewayRequest"]["body"]["params"]["arguments"]["query"]
        self.assertNotEqual(tokenized, original, "value leaving the gateway must not be the original")

        result = {"content": [{"type": "text", "text": tokenized}]}
        resp_out = handler.lambda_handler(self.response_event(result=result), None)
        restored = resp_out["mcp"]["transformedGatewayResponse"]["body"]["result"]["content"][0]["text"]
        self.assertEqual(restored, original)


class TextBlockRedactionTestCase(unittest.TestCase):
    """A JSON text block is redacted as the one string the agent reads.

    Decoding it into fields would hand each field to `scope` separately, and
    rules written for prose (a minimum length, excluded keys) would then let
    short values such as a name or a phone number straight through.
    """

    SHIELD_THE_MODEL = {
        "defaults": {
            "request": {"action": "none"},
            "response": {"action": "deidentify", "tokenType": "vault_token"},
            "entities": ["name", "phone_number"],
            "scope": {"minLength": 8, "excludeKeys": ["url", "type"]},
            "failure": {"onError": "fail_closed"},
        },
        "toolNameSeparator": "___",
    }

    response_event = staticmethod(InterceptorTestCase.response_event)

    def setUp(self):
        self.client = FakeClient()
        self._real_load, self._real_build = settings.load_policy, settings.build_client
        settings.load_policy = lambda force=False: PolicySet.from_json(self.SHIELD_THE_MODEL)
        settings.build_client = lambda: self.client

    def tearDown(self):
        settings.load_policy, settings.build_client = self._real_load, self._real_build

    def test_a_json_text_block_costs_one_call_and_misses_nothing(self):
        import json
        payload = {"results": [{"author": "Bob Lee", "phone": "5550133",
                                "url": "https://example.com/bob-lee", "text": "Bob Lee called."}]}
        block = json.dumps(payload)
        result = {"content": [{"type": "text", "text": block}]}
        out = handler.lambda_handler(self.response_event(result=result), None)
        text = out["mcp"]["transformedGatewayResponse"]["body"]["result"]["content"][0]["text"]

        self.assertEqual(self.client.deidentify_calls, [block], "the whole block, in one call")
        self.assertEqual(text, f"TOK({block})")
        self.assertNotIn("Bob Lee", text.replace(f"TOK({block})", ""),
                         "nothing outside the single tokenized string")

    def test_non_ascii_text_reaches_the_agent_unescaped(self):
        result = {"content": [{"type": "text", "text": "Café Müller — résumé"}]}
        out = handler.lambda_handler(self.response_event(result=result), None)
        text = out["mcp"]["transformedGatewayResponse"]["body"]["result"]["content"][0]["text"]
        self.assertEqual(text, "TOK(Café Müller — résumé)")


class PolicyTestCase(unittest.TestCase):
    def test_counter_tokens_with_reidentify_is_rejected(self):
        broken = {
            "defaults": {
                "request": {"action": "deidentify", "tokenType": "counter"},
                "response": {"action": "reidentify"},
            }
        }
        with self.assertRaises(PolicyError) as ctx:
            PolicySet.from_json(broken)
        self.assertIn("one-way", str(ctx.exception))

    def test_vault_tokens_with_reidentify_is_accepted(self):
        PolicySet.from_json(SHIELD_THE_TOOL)  # must not raise

    def test_split_tool_name(self):
        ps = PolicySet.from_json(SHIELD_THE_TOOL)
        self.assertEqual(ps.split_tool_name("exa___web_search"), ("exa", "web_search"))
        self.assertEqual(ps.split_tool_name("web_search"), ("", "web_search"))

    def test_override_requires_both_server_and_tool_to_match(self):
        ps = PolicySet.from_json(SHIELD_THE_TOOL)
        matched = ps.resolve("exa", "get_code_context_exa")
        self.assertEqual(matched.request.action, "none")
        # Same tool name under a different server must not match.
        unmatched = ps.resolve("github", "get_code_context_exa")
        self.assertEqual(unmatched.request.action, "deidentify")

    def test_unknown_action_rejected(self):
        with self.assertRaises(PolicyError):
            PolicySet.from_json({"defaults": {"request": {"action": "encrypt"}}})


if __name__ == "__main__":
    unittest.main(verbosity=2)
