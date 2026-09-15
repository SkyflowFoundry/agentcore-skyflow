"""Upstream payload logging: what it shows, and what it must never show.

The feature exists to answer "what did the upstream server actually receive?".
It is only safe because it logs the two snapshots that carry tokens rather than
original values. These tests pin that down, because the failure mode is writing
user data to CloudWatch rather than anything that breaks visibly.

Run: python3 gateway/interceptor/tests/test_upstream_logging.py
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

os.environ["POLICY_PARAMETER_NAME"] = "/test/policy"
os.environ["SKYFLOW_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:0:secret:test"
os.environ["SKYFLOW_VAULT_URL"] = "https://test.vault.skyflowapis.com"
os.environ["SKYFLOW_VAULT_ID"] = "vault123"

import handler  # noqa: E402
import settings  # noqa: E402
from policy import PolicyError, PolicySet  # noqa: E402

from test_handler import FakeClient  # noqa: E402

SECRET = "contact Jane Doe jane@example.com"
TOKENIZED = f"TOK({SECRET})"

BASE = {
    "defaults": {
        "request": {"action": "deidentify", "tokenType": "vault_token"},
        "response": {"action": "reidentify"},
        "entities": ["name", "email_address"],
        "scope": {"minLength": 4},
        "failure": {"onError": "fail_closed"},
        "logUpstreamPayloads": True,
    },
    "toolNameSeparator": "___",
}


def without_logging() -> dict:
    return {**BASE, "defaults": {**BASE["defaults"], "logUpstreamPayloads": False}}


class PolicyParsingTestCase(unittest.TestCase):
    def test_defaults_to_off(self):
        self.assertFalse(PolicySet.from_json({"defaults": {}}).defaults.log_upstream_payloads)

    def test_parsed_from_defaults(self):
        self.assertTrue(PolicySet.from_json(BASE).defaults.log_upstream_payloads)

    def test_an_override_can_enable_it_for_one_tool(self):
        policy_set = PolicySet.from_json({
            **without_logging(),
            "overrides": [{"servers": ["exa"], "tools": ["web_search_exa"],
                           "logUpstreamPayloads": True}],
        })
        self.assertTrue(policy_set.resolve("exa", "web_search_exa").log_upstream_payloads)
        self.assertFalse(policy_set.resolve("exa", "web_fetch_exa").log_upstream_payloads)

    def test_an_override_can_disable_it_for_one_tool(self):
        policy_set = PolicySet.from_json({
            **BASE,
            "overrides": [{"servers": ["*"], "tools": ["web_fetch_exa"],
                           "logUpstreamPayloads": False}],
        })
        self.assertFalse(policy_set.resolve("exa", "web_fetch_exa").log_upstream_payloads)

    def test_a_string_is_rejected_rather_than_read_as_truthy(self):
        """"false" is truthy in Python; silently enabling logging would be bad."""
        for value in ("true", "false", 1, 0):
            with self.subTest(value):
                with self.assertRaises(PolicyError):
                    PolicySet.from_json({"defaults": {"logUpstreamPayloads": value}})


class ShouldLogUpstreamTestCase(unittest.TestCase):
    def test_requires_a_transforming_action(self):
        """With action none nothing is tokenized, so "upstream" is the original."""
        policy = PolicySet.from_json(BASE).defaults
        self.assertTrue(policy.should_log_upstream("deidentify"))
        self.assertTrue(policy.should_log_upstream("reidentify"))
        self.assertFalse(policy.should_log_upstream("none"))

    def test_off_means_off_for_every_action(self):
        policy = PolicySet.from_json(without_logging()).defaults
        for action in ("deidentify", "reidentify", "none"):
            with self.subTest(action):
                self.assertFalse(policy.should_log_upstream(action))


class LoggedContentTestCase(unittest.TestCase):
    """Drives the handler end to end with the fake Skyflow client.

    Deliberately not a subclass of test_handler's case: inheriting it would
    re-run its assertions against this module's policy, which has different
    scope rules.
    """

    def setUp(self):
        self.client = FakeClient()
        self._real_load = settings.load_policy
        self._real_build = settings.build_client
        settings.load_policy = lambda force=False: PolicySet.from_json(BASE)
        settings.build_client = lambda: self.client

    def tearDown(self):
        settings.load_policy = self._real_load
        settings.build_client = self._real_build

    @staticmethod
    def request_event(name="exa___web_search_exa", arguments=None):
        return {
            "interceptorInputVersion": "1.0",
            "mcp": {"gatewayRequest": {"body": {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}},
            }}},
        }

    @staticmethod
    def response_event(name="exa___web_search_exa", result=None):
        return {
            "interceptorInputVersion": "1.0",
            "mcp": {
                "gatewayRequest": {"body": {
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": name, "arguments": {}},
                }},
                "gatewayResponse": {
                    "statusCode": 200,
                    "body": {"jsonrpc": "2.0", "id": 1, "result": result if result is not None else {}},
                },
            },
        }

    def test_request_logs_the_tokenized_form_not_the_original(self):
        event = self.request_event(arguments={"query": SECRET})
        with self.assertLogs(level="INFO") as logs:
            handler.lambda_handler(event, None)
        line = next(l for l in logs.output if "upstream_request" in l)
        self.assertIn(TOKENIZED, line)
        self.assertNotIn(SECRET, line.replace(TOKENIZED, ""))

    def test_response_logs_the_form_the_upstream_returned(self):
        result = {"content": [{"type": "text", "text": TOKENIZED}]}
        with self.assertLogs(level="INFO") as logs:
            handler.lambda_handler(self.response_event(result=result), None)
        line = next(l for l in logs.output if "upstream_response" in l)
        self.assertIn(TOKENIZED, line)

    def test_the_reidentified_response_is_never_logged(self):
        """The whole safety argument: restored values must not reach a log."""
        result = {"content": [{"type": "text", "text": TOKENIZED}]}
        with self.assertLogs(level="INFO") as logs:
            out = handler.lambda_handler(self.response_event(result=result), None)

        restored = out["mcp"]["transformedGatewayResponse"]["body"]["result"]["content"][0]["text"]
        self.assertEqual(restored, SECRET, "the caller still gets the original back")
        for line in logs.output:
            self.assertNotIn(SECRET, line.replace(TOKENIZED, ""))

    def test_nothing_is_logged_when_disabled(self):
        settings.load_policy = lambda force=False: PolicySet.from_json(without_logging())
        with self.assertLogs(level="INFO") as logs:
            handler.lambda_handler(self.request_event(arguments={"query": SECRET}), None)
        self.assertFalse([l for l in logs.output if "upstream_" in l])

    def test_a_pass_through_tool_logs_nothing(self):
        """action none would mean logging the untouched original."""
        settings.load_policy = lambda force=False: PolicySet.from_json({
            **BASE,
            "overrides": [{"servers": ["exa"], "tools": ["*"],
                           "request": {"action": "none"}, "response": {"action": "none"}}],
        })
        with self.assertLogs(level="INFO") as logs:
            handler.lambda_handler(self.request_event(arguments={"query": SECRET}), None)
        self.assertFalse([l for l in logs.output if "upstream_" in l])

    def test_a_long_payload_is_truncated(self):
        long_value = "y" * (handler.MAX_LOGGED_PAYLOAD * 2)
        with self.assertLogs(level="INFO") as logs:
            handler.lambda_handler(self.request_event(arguments={"query": long_value}), None)
        line = next(l for l in logs.output if "upstream_request" in l)
        payload = line.split("payload=", 1)[1]
        self.assertEqual(len(payload), handler.MAX_LOGGED_PAYLOAD)

    def test_an_unserializable_payload_does_not_break_the_call(self):
        with self.assertLogs(level="INFO") as logs:
            handler._log_upstream("request", "exa", "t", {"k": {1, 2, 3}})
        self.assertIn("upstream_request", "\n".join(logs.output))

    def test_a_failed_request_logs_nothing(self):
        """Nothing was tokenized, so there is no safe payload to show."""
        settings.build_client = lambda: FakeClient(fail=True)
        with self.assertLogs(level="INFO") as logs:
            handler.lambda_handler(self.request_event(arguments={"query": SECRET}), None)
        self.assertFalse([l for l in logs.output if "upstream_" in l])


if __name__ == "__main__":
    unittest.main(verbosity=2)
