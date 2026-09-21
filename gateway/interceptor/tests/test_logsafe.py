"""Credentials must not reach CloudWatch, whatever the logging settings say.

Three routes are guarded: the root log level leaking into the AWS SDK loggers,
the upstream payload log printing fields that scope keeps out of tokenization,
and the caller's headers arriving inside the event.

Run: python3 gateway/interceptor/tests/test_logsafe.py
"""

from __future__ import annotations

import logging
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
import logsafe  # noqa: E402

BEARER = "Bearer eyJhbGciOiJIUzI1NiJ9.secret.signature"
SIGV4 = "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260921/us-east-1/bedrock-agentcore/aws4_request, Signature=abc"


class LogLevelTestCase(unittest.TestCase):
    """LOG_LEVEL=DEBUG must not switch botocore to DEBUG.

    botocore at DEBUG logs every response body, and the body of GetSecretValue
    is the Skyflow API key. It also logs the SigV4 Authorization header of each
    AWS call.
    """

    def setUp(self):
        self._root = logging.getLogger().level
        self._sdk = {name: logging.getLogger(name).level for name in logsafe.SDK_LOGGERS}

    def tearDown(self):
        logging.getLogger().setLevel(self._root)
        for name, level in self._sdk.items():
            logging.getLogger(name).setLevel(level)

    def test_debug_applies_to_the_interceptor_but_not_the_sdks(self):
        level = logsafe.configure_logging("DEBUG")
        self.assertEqual(level, logging.DEBUG)
        self.assertEqual(logging.getLogger().level, logging.DEBUG)
        for name in logsafe.SDK_LOGGERS:
            self.assertGreaterEqual(
                logging.getLogger(name).level, logging.INFO,
                f"{name} must never log at DEBUG: it prints secrets and signatures",
            )

    def test_a_quieter_level_is_honoured_everywhere(self):
        logsafe.configure_logging("WARNING")
        self.assertEqual(logging.getLogger().level, logging.WARNING)
        self.assertEqual(logging.getLogger("botocore").level, logging.WARNING)

    def test_an_unknown_level_falls_back_to_info_rather_than_failing(self):
        self.assertEqual(logsafe.configure_logging("VERBOSE"), logging.INFO)

    def test_the_environment_variable_is_read_when_no_level_is_given(self):
        previous = os.environ.get("LOG_LEVEL")
        os.environ["LOG_LEVEL"] = "debug"
        try:
            self.assertEqual(logsafe.configure_logging(), logging.DEBUG)
            self.assertGreaterEqual(logging.getLogger("botocore").level, logging.INFO)
        finally:
            if previous is None:
                del os.environ["LOG_LEVEL"]
            else:
                os.environ["LOG_LEVEL"] = previous


class RedactForLogTestCase(unittest.TestCase):
    def test_masks_by_key_at_any_depth(self):
        node = {"query": "hello", "api_key": "k-123", "nested": [{"Authorization": BEARER, "ok": "x"}]}
        out = logsafe.redact_for_log(node)
        self.assertEqual(out["api_key"], logsafe.REDACTED)
        self.assertEqual(out["nested"][0]["Authorization"], logsafe.REDACTED)
        self.assertEqual(out["query"], "hello")
        self.assertEqual(out["nested"][0]["ok"], "x")

    def test_masks_by_shape_when_the_key_is_innocent(self):
        out = logsafe.redact_for_log({"header_value": BEARER, "sig": SIGV4, "basic": "Basic dXNlcjpwYXNz"})
        self.assertEqual(set(out.values()), {logsafe.REDACTED})

    def test_key_matching_is_case_insensitive_and_glob_based(self):
        out = logsafe.redact_for_log({"X-Api-Key": "a", "ClientSecret": "b", "access_token": "c", "PASSWORD": "d"})
        self.assertEqual(set(out.values()), {logsafe.REDACTED})

    def test_the_input_is_not_mutated(self):
        node = {"api_key": "k-123"}
        logsafe.redact_for_log(node)
        self.assertEqual(node["api_key"], "k-123")

    def test_scalars_pass_through(self):
        self.assertEqual(logsafe.redact_for_log("plain text"), "plain text")
        self.assertEqual(logsafe.redact_for_log(42), 42)


class ScrubEventTestCase(unittest.TestCase):
    def event(self, shape="mcp"):
        return {
            shape: {
                "gatewayRequest": {
                    "headers": {"Authorization": SIGV4, "Content-Type": "application/json",
                                "X-Amz-Security-Token": "FwoG...", "Mcp-Session-Id": "s-1"},
                    "body": {"method": "tools/list"},
                },
                "gatewayResponse": {"headers": {"Set-Cookie": "sid=1", "Content-Type": "text/event-stream"},
                                    "body": {}},
            }
        }

    def test_credential_headers_are_blanked_in_place(self):
        event = self.event()
        logsafe.scrub_event(event)
        request_headers = event["mcp"]["gatewayRequest"]["headers"]
        self.assertEqual(request_headers["Authorization"], logsafe.REDACTED)
        self.assertEqual(request_headers["X-Amz-Security-Token"], logsafe.REDACTED)
        self.assertEqual(request_headers["Content-Type"], "application/json", "harmless headers survive")
        self.assertEqual(request_headers["Mcp-Session-Id"], "s-1")
        self.assertEqual(event["mcp"]["gatewayResponse"]["headers"]["Set-Cookie"], logsafe.REDACTED)

    def test_the_http_shape_is_covered_too(self):
        event = self.event(shape="http")
        logsafe.scrub_event(event)
        self.assertEqual(event["http"]["gatewayRequest"]["headers"]["Authorization"], logsafe.REDACTED)

    def test_an_event_without_headers_is_untouched(self):
        event = {"mcp": {"gatewayRequest": {"body": {"method": "tools/list"}}}}
        self.assertEqual(logsafe.scrub_event(event), {"mcp": {"gatewayRequest": {"body": {"method": "tools/list"}}}})

    def test_the_handler_scrubs_before_doing_anything_else(self):
        """Through the real entry point: after a call, the event the gateway
        handed us no longer holds the caller's Authorization header."""
        event = self.event()
        handler.lambda_handler(event, None)
        self.assertNotIn(SIGV4, str(event))
        self.assertEqual(event["mcp"]["gatewayRequest"]["headers"]["Authorization"], logsafe.REDACTED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
