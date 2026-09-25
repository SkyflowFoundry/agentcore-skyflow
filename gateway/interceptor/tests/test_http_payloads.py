"""HTTP-shaped events: refused unless the policy explicitly lets them through.

AgentCore Runtime, passthrough and inference targets reach the interceptor as
`event["http"]` with a base64 body and no MCP framing. There is no tool call to
find and nothing the interceptor can redact, so passing them through silently
made an uninspected target look exactly like a protected one (SC-16091). These
tests pin down the replacement: block by default, pass through only when
`httpPayloads.action` says so, and say which happened at WARNING either way.

Run: python3 gateway/interceptor/tests/test_http_payloads.py
"""

from __future__ import annotations

import base64
import json
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

SECRET = "Jane Doe, SSN 123-45-6789"
REQUEST_BODY = base64.b64encode(json.dumps({"prompt": SECRET}).encode()).decode()
RESPONSE_BODY = base64.b64encode(json.dumps({"completion": SECRET}).encode()).decode()


def request_event(path="/billing-runtime/invocations/customers/jane"):
    return {"interceptorInputVersion": "1.0", "http": {"gatewayRequest": {
        "path": path, "httpMethod": "POST", "body": REQUEST_BODY}}}


def response_event():
    # As documented: an HTTP response event carries no request at all.
    return {"interceptorInputVersion": "1.0", "http": {
        "gatewayRequest": None,
        "gatewayResponse": {"statusCode": 200, "headers": None,
                            "body": RESPONSE_BODY, "contentType": "application/json"}}}


def policy(http_payloads=None) -> dict:
    raw = {"defaults": {}, "toolNameSeparator": "___"}
    if http_payloads is not None:
        raw["httpPayloads"] = http_payloads
    return raw


class HttpTestCase(unittest.TestCase):
    def setUp(self):
        self._load = settings.load_policy
        self.use(policy())

    def tearDown(self):
        settings.load_policy = self._load

    def use(self, raw: dict) -> None:
        settings.load_policy = lambda force=False: PolicySet.from_json(raw)

    def assert_blocked(self, out: dict) -> dict:
        response = out["http"]["transformedGatewayResponse"]
        self.assertEqual(response["statusCode"], 403)
        self.assertEqual(response["contentType"], "application/json")
        body = json.loads(base64.b64decode(response["body"]))
        self.assertEqual(body["error"]["code"], "SENSITIVE_DATA_UNINSPECTED")
        self.assertNotIn(SECRET, json.dumps(out), "the target's data never comes back")
        return body


class BlockTestCase(HttpTestCase):
    def test_a_request_is_blocked_by_default(self):
        """The short circuit: the gateway answers without calling the target."""
        out = handler.lambda_handler(request_event(), None)
        self.assert_blocked(out)
        self.assertNotIn("transformedGatewayRequest", out["http"])

    def test_a_response_is_blocked_by_default(self):
        """In case a response arrives anyway, e.g. only RESPONSE is attached."""
        self.assert_blocked(handler.lambda_handler(response_event(), None))

    def test_explicit_block_behaves_the_same(self):
        self.use(policy({"action": "block"}))
        self.assert_blocked(handler.lambda_handler(request_event(), None))

    def test_the_error_says_how_to_fix_it(self):
        body = self.assert_blocked(handler.lambda_handler(request_event(), None))
        self.assertIn("httpPayloads.action", body["error"]["message"])

    def test_a_block_is_logged_at_warning_with_the_target_name(self):
        with self.assertLogs(level="WARNING") as logs:
            handler.lambda_handler(request_event(), None)
        line = next(l for l in logs.output if "http_payload_blocked" in l)
        self.assertIn("direction=request", line)
        self.assertIn("target=billing-runtime", line)

    def test_only_the_first_path_segment_is_logged(self):
        """The rest of a passthrough path is the caller's, and may carry user data."""
        with self.assertLogs(level="WARNING") as logs:
            handler.lambda_handler(request_event(), None)
        joined = "\n".join(logs.output)
        self.assertNotIn("customers", joined)
        self.assertNotIn("jane", joined)

    def test_a_response_has_no_target_to_name(self):
        with self.assertLogs(level="WARNING") as logs:
            handler.lambda_handler(response_event(), None)
        self.assertIn("target=<unknown>", "\n".join(logs.output))

    def test_an_unreadable_policy_blocks(self):
        """No policy means no informed decision, the same as on the MCP path."""
        def broken(force=False):
            raise RuntimeError("SSM unavailable")

        settings.load_policy = broken
        with self.assertLogs(level="ERROR"):
            self.assert_blocked(handler.lambda_handler(request_event(), None))


class PassthroughTestCase(HttpTestCase):
    def setUp(self):
        super().setUp()
        self.use(policy({"action": "passthrough"}))

    def test_request_and_response_pass_through_untouched(self):
        for event in (request_event(), response_event()):
            with self.subTest(sorted(event["http"])):
                out = handler.lambda_handler(event, None)
                self.assertEqual(out, {"interceptorOutputVersion": "1.0", "http": {}})

    def test_passthrough_is_logged_at_warning_on_every_call(self):
        """Uninspected traffic must stand out in monitoring, not hide at INFO."""
        with self.assertLogs(level="WARNING") as logs:
            for _ in range(3):
                handler.lambda_handler(request_event(), None)
        lines = [l for l in logs.output if "http_payload_passthrough" in l]
        self.assertEqual(len(lines), 3)
        self.assertTrue(all(l.startswith("WARNING") for l in lines))
        self.assertIn("body not inspected", lines[0])

    def test_the_body_is_never_logged(self):
        with self.assertLogs(level="DEBUG") as logs:
            handler.lambda_handler(request_event(), None)
            handler.lambda_handler(response_event(), None)
        joined = "\n".join(logs.output)
        self.assertNotIn(SECRET, joined)
        self.assertNotIn(REQUEST_BODY, joined)


class PolicyParsingTestCase(unittest.TestCase):
    def test_defaults_to_block(self):
        self.assertEqual(PolicySet.from_json(policy()).http_payloads, "block")
        self.assertEqual(PolicySet.from_json(policy({})).http_payloads, "block")

    def test_passthrough_is_parsed(self):
        self.assertEqual(PolicySet.from_json(policy({"action": "passthrough"})).http_payloads, "passthrough")

    def test_an_unknown_action_is_rejected(self):
        for action in ("allow", "redact", "", None, True):
            with self.subTest(action):
                with self.assertRaises(PolicyError):
                    PolicySet.from_json(policy({"action": action}))

    def test_a_non_object_is_rejected(self):
        for value in ("passthrough", ["block"], True):
            with self.subTest(value):
                with self.assertRaises(PolicyError):
                    PolicySet.from_json(policy(value))

    def test_the_shipped_policy_blocks(self):
        shipped = Path(__file__).resolve().parents[1] / "config" / "policy.json"
        self.assertEqual(PolicySet.from_json(json.loads(shipped.read_text())).http_payloads, "block")


if __name__ == "__main__":
    unittest.main(verbosity=2)
