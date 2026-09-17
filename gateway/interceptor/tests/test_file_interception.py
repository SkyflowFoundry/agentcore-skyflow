"""Swapping file URLs for de-identified ones, end to end through the handler.

The agent must never receive a URL to the original document. These tests cover
the swap, and the ways it can go wrong without being obvious: a partial swap, a
tokenized replacement URL, an unrecognised format, a run that never finishes.

Run: python3 gateway/interceptor/tests/test_file_interception.py
"""

from __future__ import annotations

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

import file_urls  # noqa: E402
import handler  # noqa: E402
import settings  # noqa: E402
from policy import FileRule, PolicyError, PolicySet, parse_field_path  # noqa: E402
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



class NamedFieldsTestCase(unittest.TestCase):
    """A rule can say exactly where the file reference is, instead of scanning."""

    def setUp(self):
        self.client = FakeFileClient()
        self._load, self._build = settings.load_policy, settings.build_client
        settings.build_client = lambda: self.client

    def tearDown(self):
        settings.load_policy, settings.build_client = self._load, self._build

    def use(self, files_rule):
        policy = {**POLICY, "defaults": {**POLICY["defaults"], "files": files_rule}}
        settings.load_policy = lambda force=False: PolicySet.from_json(policy)

    def out(self, event):
        return handler.lambda_handler(event, None)["mcp"]["transformedGatewayResponse"]["body"]["result"]

    def test_only_the_named_field_is_touched(self):
        self.use({"action": "deidentify", "directions": ["response"], "fields": ["url"]})
        elsewhere = ORIGINAL.replace("invoice", "other")
        result = self.out(response_event({"url": ORIGINAL, "backup": elsewhere}))
        self.assertEqual(result["url"], CLEAN)
        self.assertEqual(result["backup"], elsewhere, "an unnamed field is left alone")

    def test_a_list_path_covers_every_element(self):
        self.use({"action": "deidentify", "directions": ["response"],
                  "fields": ["content[*].url"], "maxFiles": 3})
        event = response_event({"content": [{"url": ORIGINAL}, {"url": ORIGINAL}, {"type": "text"}]})
        result = self.out(event)
        self.assertEqual([c.get("url") for c in result["content"]], [CLEAN, CLEAN, None])

    def test_a_named_field_that_is_absent_is_not_an_error(self):
        """Tools legitimately return responses with no attachment."""
        self.use({"action": "deidentify", "directions": ["response"], "fields": ["url"]})
        result = self.out(response_event({"content": [{"type": "text", "text": "nothing here"}]}))
        self.assertEqual(result["content"][0]["text"], "nothing here")
        self.assertEqual(self.client.submitted, [])

    def test_patterns_are_not_required_once_fields_are_named(self):
        self.use({"action": "deidentify", "directions": ["response"], "fields": ["url"]})
        self.assertEqual(self.out(response_event({"url": ORIGINAL}))["url"], CLEAN)

    def test_a_reference_outside_the_named_fields_is_warned_about(self):
        self.use({"action": "deidentify", "directions": ["response"],
                  "fields": ["url"], "urlPatterns": PATTERNS})
        stray = ORIGINAL.replace("invoice", "stray")
        with self.assertLogs("file_urls", level="WARNING") as logs:
            result = self.out(response_event({"url": ORIGINAL, "extra": {"link": stray}}))
        self.assertEqual(result["url"], CLEAN)
        self.assertEqual(result["extra"]["link"], stray, "warned about, not acted on")
        self.assertIn("extra.link", "\n".join(logs.output))

    def test_no_warning_when_the_named_fields_cover_everything(self):
        self.use({"action": "deidentify", "directions": ["response"],
                  "fields": ["url"], "urlPatterns": PATTERNS})
        with self.assertNoLogs("file_urls", level="WARNING"):
            self.out(response_event({"url": ORIGINAL}))

    def test_no_warning_is_possible_without_patterns(self):
        """Nothing to compare against, so the check is skipped rather than guessed."""
        self.use({"action": "deidentify", "directions": ["response"], "fields": ["url"]})
        with self.assertNoLogs("file_urls", level="WARNING"):
            self.out(response_event({"url": ORIGINAL, "extra": ORIGINAL}))


class FieldPathTestCase(unittest.TestCase):
    def test_plain_and_nested_keys(self):
        self.assertEqual(parse_field_path("url"), ("url",))
        self.assertEqual(parse_field_path("result.url"), ("result", "url"))

    def test_wildcard_and_index(self):
        self.assertEqual(parse_field_path("c[*].url"), ("c", "*", "url"))
        self.assertEqual(parse_field_path("c[0].url"), ("c", 0, "url"))

    def test_rejects_empty_and_malformed(self):
        for bad in ("", "   ", "a..b", "a[", "a]b"):
            with self.subTest(bad):
                with self.assertRaises(ValueError):
                    parse_field_path(bad)

    def test_a_malformed_path_is_rejected_when_the_policy_loads(self):
        """A typo should fail the policy that carries it, not a live call."""
        with self.assertRaises(PolicyError):
            PolicySet.from_json(
                {"defaults": {"files": {"action": "deidentify", "fields": ["a["]}}}
            )

    def test_a_path_reaching_a_non_string_yields_nothing(self):
        self.assertEqual(file_urls.resolve_field_paths({"url": {"nested": 1}}, ("url",)), [])

    def test_an_index_beyond_the_list_yields_nothing(self):
        self.assertEqual(file_urls.resolve_field_paths({"c": ["a"]}, ("c[3]",)), [])

    def test_several_paths_are_all_resolved(self):
        node = {"a": "x", "b": {"c": "y"}}
        self.assertEqual(
            file_urls.resolve_field_paths(node, ("a", "b.c")),
            [(("a",), "x"), (("b", "c"), "y")],
        )


class RuleWithFieldsValidationTestCase(unittest.TestCase):
    def test_neither_fields_nor_patterns_is_rejected(self):
        with self.assertRaises(PolicyError):
            FileRule(action="deidentify")

    def test_fields_alone_is_accepted(self):
        rule = FileRule(action="deidentify", fields=("url",))
        self.assertFalse(rule.scans)

    def test_patterns_alone_still_scans(self):
        self.assertTrue(FileRule(action="deidentify", url_patterns=("*",)).scans)


class McpEnvelopeTestCase(unittest.TestCase):
    """A real MCP result carries its payload as a JSON string in a text block.

    Without decoding, a file URL sits inside that string rather than at a field
    path, so nothing matches and the agent receives the original document.
    """

    POLICY = {
        "defaults": {
            "request": {"action": "none"},
            "response": {"action": "none"},
            "scope": {"minLength": 4},
            "failure": {"onError": "fail_closed"},
            "entities": ["name"],
        },
        "toolNameSeparator": "___",
        "overrides": [{
            "servers": ["s3"], "tools": ["*"],
            "files": {
                "action": "deidentify",
                "directions": ["response"],
                "fields": ["content[*].text.url"],
                "urlPatterns": PATTERNS,
                "maxFiles": 1,
            },
        }],
    }

    def setUp(self):
        self.client = FakeFileClient()
        self._load, self._build = settings.load_policy, settings.build_client
        settings.load_policy = lambda force=False: PolicySet.from_json(self.POLICY)
        settings.build_client = lambda: self.client

    def tearDown(self):
        settings.load_policy, settings.build_client = self._load, self._build

    def out(self, result):
        event = response_event(result)
        return handler.lambda_handler(event, None)["mcp"]["transformedGatewayResponse"]["body"]["result"]

    def text_block(self, payload):
        return {"isError": False, "content": [{"type": "text", "text": json.dumps(payload)}]}

    def test_a_url_inside_a_text_block_is_swapped(self):
        result = self.out(self.text_block({"key": "claims/invoice.pdf", "url": ORIGINAL}))
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(payload["url"], CLEAN)
        self.assertEqual(payload["key"], "claims/invoice.pdf", "other fields survive")

    def test_the_block_is_still_a_json_string_afterwards(self):
        result = self.out(self.text_block({"url": ORIGINAL}))
        self.assertIsInstance(result["content"][0]["text"], str)

    def test_the_original_url_appears_nowhere_in_the_response(self):
        result = self.out(self.text_block({"url": ORIGINAL, "note": "see attached"}))
        self.assertNotIn(ORIGINAL, json.dumps(result))

    def test_a_block_of_prose_is_passed_through(self):
        result = self.out({"isError": False, "content": [{"type": "text", "text": "no files here"}]})
        self.assertEqual(result["content"][0]["text"], "no files here")


if __name__ == "__main__":
    unittest.main(verbosity=2)
