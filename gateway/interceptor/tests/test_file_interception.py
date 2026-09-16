"""Swapping file URLs for de-identified ones, end to end through the handler.

The agent must never receive a URL to the original document. These tests cover
the swap, and the ways it can go wrong without being obvious: a partial swap, a
tokenized replacement URL, an unrecognised format, a run that never finishes.

Run: python3 gateway/interceptor/tests/test_file_interception.py
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

import file_urls  # noqa: E402
import handler  # noqa: E402
import settings  # noqa: E402
from policy import FileRule, PolicyError, PolicySet  # noqa: E402
from skyflow_client import FileOutput, FileRunResult, RunTimeout, SkyflowError  # noqa: E402

ORIGINAL = "https://bucket.s3.amazonaws.com/claims/invoice.pdf?X-Amz-Signature=abc"
CLEAN = "https://skyflow.s3.amazonaws.com/out/invoice.pdf?X-Amz-Signature=zzz"
PATTERNS = ["https://bucket.s3.amazonaws.com/*"]

POLICY = {
    "defaults": {
        "request": {"action": "none"},
        "response": {"action": "none"},
        "scope": {"minLength": 4},
        "failure": {"onError": "fail_closed"},
        "files": {"action": "deidentify", "directions": ["response"], "urlPatterns": PATTERNS},
    },
    "toolNameSeparator": "___",
}


class FakeFileClient:
    """Stands in for SkyflowClient's file methods."""

    def __init__(self, status="SUCCESS", outputs=None, submit_error=None):
        self.status = status
        self.outputs = outputs if outputs is not None else (
            FileOutput(url=CLEAN, file_type="REDACTED_FILE", extension="pdf"),
        )
        self.submit_error = submit_error
        self.submitted: list[tuple[str, str, dict]] = []

    def deidentify_file_url(self, url, data_format, configuration):
        if self.submit_error:
            raise self.submit_error
        self.submitted.append((url, data_format, configuration))
        return f"run-{len(self.submitted)}"

    def wait_for_run(self, run_id, seconds_remaining, reserve_seconds=5.0):
        if isinstance(self.status, Exception):
            raise self.status
        return FileRunResult(status=self.status, outputs=self.outputs, message="done")

    # string methods, unused unless a test enables string actions
    def deidentify(self, text, entity_types, vault_token_entity_types=None):
        return type("R", (), {"processed_text": f"TOK({text})", "entities": []})()

    def reidentify(self, text):
        return type("R", (), {"text": text})()


def response_event(result):
    return {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {"body": {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "s3___get_object", "arguments": {}},
            }},
            "gatewayResponse": {"statusCode": 200, "body": {
                "jsonrpc": "2.0", "id": 1, "result": result,
            }},
        },
    }


class SwapTestCase(unittest.TestCase):
    def setUp(self):
        self.client = FakeFileClient()
        self._load, self._build = settings.load_policy, settings.build_client
        settings.load_policy = lambda force=False: PolicySet.from_json(POLICY)
        settings.build_client = lambda: self.client

    def tearDown(self):
        settings.load_policy, settings.build_client = self._load, self._build

    def out(self, event):
        return handler.lambda_handler(event, None)["mcp"]["transformedGatewayResponse"]["body"]["result"]

    def test_the_original_url_is_replaced(self):
        result = self.out(response_event({"url": ORIGINAL}))
        self.assertEqual(result["url"], CLEAN)

    def test_the_original_url_does_not_survive_anywhere(self):
        """The agent must not be able to reach the un-redacted document."""
        import json
        result = self.out(response_event({"url": ORIGINAL, "note": "see attached"}))
        self.assertNotIn(ORIGINAL, json.dumps(result))

    def test_the_format_comes_from_the_path_not_the_query(self):
        self.out(response_event({"url": ORIGINAL}))
        _, data_format, _ = self.client.submitted[0]
        self.assertEqual(data_format, "pdf")

    def test_a_url_that_does_not_match_the_patterns_is_left_alone(self):
        other = "https://elsewhere.example.com/doc.pdf"
        result = self.out(response_event({"url": other}))
        self.assertEqual(result["url"], other)
        self.assertEqual(self.client.submitted, [])

    def test_nothing_happens_when_there_are_no_files(self):
        result = self.out(response_event({"content": [{"type": "text", "text": "no files here"}]}))
        self.assertEqual(result["content"][0]["text"], "no files here")

    def test_more_files_than_the_cap_is_refused_rather_than_truncated(self):
        """A partial swap would hand back some originals alongside some
        redacted copies, which is worse than refusing the call."""
        second = ORIGINAL.replace("invoice", "receipt")
        out = handler.lambda_handler(
            response_event({"a": ORIGINAL, "b": second}), None
        )
        body = out["mcp"]["transformedGatewayResponse"]["body"]
        self.assertIn("error", body)
        self.assertEqual(self.client.submitted, [])

    def test_the_cap_can_be_raised(self):
        policy = {**POLICY, "defaults": {**POLICY["defaults"],
                                         "files": {**POLICY["defaults"]["files"], "maxFiles": 2}}}
        settings.load_policy = lambda force=False: PolicySet.from_json(policy)
        second = ORIGINAL.replace("invoice", "receipt")
        result = self.out(response_event({"a": ORIGINAL, "b": second}))
        self.assertEqual([result["a"], result["b"]], [CLEAN, CLEAN])

    def test_an_unrecognised_extension_fails_closed(self):
        out = handler.lambda_handler(
            response_event({"url": "https://bucket.s3.amazonaws.com/claims/file.bin"}), None
        )
        self.assertIn("error", out["mcp"]["transformedGatewayResponse"]["body"])

    def test_a_failed_run_fails_closed(self):
        self.client.status = "FAILED"
        out = handler.lambda_handler(response_event({"url": ORIGINAL}), None)
        self.assertIn("error", out["mcp"]["transformedGatewayResponse"]["body"])

    def test_a_run_that_outruns_the_budget_fails_closed(self):
        self.client.status = RunTimeout("out of time")
        out = handler.lambda_handler(response_event({"url": ORIGINAL}), None)
        self.assertIn("error", out["mcp"]["transformedGatewayResponse"]["body"])

    def test_a_run_with_no_document_output_fails_closed(self):
        self.client.outputs = (FileOutput(url="https://x/e.json", file_type="ENTITIES", extension="json"),)
        out = handler.lambda_handler(response_event({"url": ORIGINAL}), None)
        self.assertIn("error", out["mcp"]["transformedGatewayResponse"]["body"])


class StringInteractionTestCase(unittest.TestCase):
    """File swapping and string redaction have to coexist on one payload."""

    def setUp(self):
        self.client = FakeFileClient()
        self._load, self._build = settings.load_policy, settings.build_client
        policy = {**POLICY, "defaults": {**POLICY["defaults"],
                                         "response": {"action": "deidentify", "tokenType": "counter"}}}
        settings.load_policy = lambda force=False: PolicySet.from_json(policy)
        settings.build_client = lambda: self.client

    def tearDown(self):
        settings.load_policy, settings.build_client = self._load, self._build

    def test_the_replacement_url_is_not_then_tokenized(self):
        """Tokenizing a freshly issued signed URL would turn it into a dead
        link, so the swapped path must be skipped by string redaction."""
        out = handler.lambda_handler(response_event({"url": ORIGINAL, "note": "Jane Doe called"}), None)
        result = out["mcp"]["transformedGatewayResponse"]["body"]["result"]
        self.assertEqual(result["url"], CLEAN)
        self.assertEqual(result["note"], "TOK(Jane Doe called)", "other strings still redacted")


class RuleValidationTestCase(unittest.TestCase):
    def test_deidentify_without_patterns_is_rejected(self):
        """Without patterns every string is a candidate file URL."""
        with self.assertRaises(PolicyError):
            FileRule(action="deidentify")

    def test_an_unknown_action_is_rejected(self):
        with self.assertRaises(PolicyError):
            FileRule(action="redact", url_patterns=("*",))

    def test_an_unknown_direction_is_rejected(self):
        with self.assertRaises(PolicyError):
            FileRule(action="deidentify", directions=("sideways",), url_patterns=("*",))

    def test_max_files_must_be_positive(self):
        with self.assertRaises(PolicyError):
            FileRule(action="deidentify", url_patterns=("*",), max_files=0)

    def test_inactive_by_default(self):
        self.assertFalse(FileRule().is_active)
        self.assertFalse(FileRule().applies_to("response"))

    def test_direction_is_respected(self):
        rule = FileRule(action="deidentify", directions=("request",), url_patterns=("*",))
        self.assertTrue(rule.applies_to("request"))
        self.assertFalse(rule.applies_to("response"))


class DataFormatTestCase(unittest.TestCase):
    def test_query_string_is_ignored(self):
        self.assertEqual(file_urls.data_format_for(ORIGINAL), "pdf")

    def test_case_is_normalised(self):
        self.assertEqual(file_urls.data_format_for("https://x/a/B.PDF"), "pdf")

    def test_percent_encoding_is_decoded(self):
        self.assertEqual(file_urls.data_format_for("https://x/my%20file.csv"), "csv")

    def test_unknown_extension_yields_none(self):
        self.assertIsNone(file_urls.data_format_for("https://x/a.bin"))

    def test_no_extension_yields_none(self):
        self.assertIsNone(file_urls.data_format_for("https://x/a/b"))

    def test_a_dot_in_a_directory_is_not_an_extension(self):
        self.assertIsNone(file_urls.data_format_for("https://x/v1.2/report"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
