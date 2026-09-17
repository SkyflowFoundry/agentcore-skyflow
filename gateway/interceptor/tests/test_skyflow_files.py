"""Detect v2 file de-identification: submit by URL, poll, pick the output.

No network. The HTTP layer is replaced so the tests pin the request bodies we
send and the handling of the responses we get back.

Run: python3 gateway/interceptor/tests/test_skyflow_files.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from skyflow_client import (  # noqa: E402
    VAULT_TOKEN_FORMATS,
    FileOutput,
    FileRunResult,
    RunTimeout,
    SkyflowClient,
    SkyflowError,
    build_file_configuration,
)

SIGNED_URL = "https://bucket.s3.amazonaws.com/claims/invoice.pdf?X-Amz-Signature=abc"
CLEAN_URL = "https://skyflow-out.s3.amazonaws.com/redacted/invoice.pdf?X-Amz-Signature=xyz"


class RecordingClient(SkyflowClient):
    """Captures requests and replays canned responses instead of doing HTTP."""

    def __init__(self, responses):
        super().__init__(
            vault_url="https://test.vault.skyflowapis.com",
            vault_id="vault123",
            api_key="key",
        )
        self.requests: list[tuple[str, str, dict | None]] = []
        self._responses = list(responses)

    def _request(self, method, path, body):
        self.requests.append((method, path, body))
        if not self._responses:
            raise AssertionError(f"unexpected extra request: {method} {path}")
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    @property
    def bodies(self):
        return [b for _, _, b in self.requests]


def run_response(status, outputs=(), message=""):
    return {
        "status": status,
        "outputType": "PRESIGNED_URL",
        "output": [
            {
                "processedFile": url,
                "processedFileType": ftype,
                "processedFileExtension": ext,
            }
            for url, ftype, ext in outputs
        ],
        "message": message,
    }


class SubmitTestCase(unittest.TestCase):
    def test_sends_the_url_rather_than_the_bytes(self):
        """The whole point: the file never passes through this Lambda."""
        client = RecordingClient([{"runId": "run-1"}])
        run_id = client.deidentify_file_url(SIGNED_URL, "pdf", build_file_configuration())

        self.assertEqual(run_id, "run-1")
        method, path, body = client.requests[0]
        self.assertEqual((method, path), ("POST", "/v2/detect/deidentify/file"))
        self.assertEqual(body["dataSource"], "PRESIGNED_URL")
        self.assertEqual(body["value"], SIGNED_URL)
        self.assertEqual(body["dataFormat"], "pdf")

    def test_the_vault_id_is_injected_into_the_configuration(self):
        client = RecordingClient([{"runId": "run-1"}])
        client.deidentify_file_url(SIGNED_URL, "pdf", {"detect": {"entities": []}})
        self.assertEqual(client.bodies[0]["configuration"]["vaultId"], "vault123")

    def test_the_configuration_is_passed_through_as_given(self):
        """The policy must be able to express Detect options this client does
        not model, so the configuration is forwarded rather than rebuilt."""
        configuration = {
            "detect": {"customTypes": [{"label": "EMPLOYEE_ID", "match": ["EMP-[0-9]{6}"]}]},
            "media": {"document": {"pdf": {"processingMode": "OCR", "density": 300}}},
        }
        client = RecordingClient([{"runId": "run-1"}])
        client.deidentify_file_url(SIGNED_URL, "pdf", configuration)
        sent = client.bodies[0]["configuration"]
        self.assertEqual(sent["media"], configuration["media"])
        self.assertEqual(sent["detect"], configuration["detect"])

    def test_a_caller_supplied_vault_id_wins_over_the_client_default(self):
        client = RecordingClient([{"runId": "run-1"}])
        client.deidentify_file_url(SIGNED_URL, "pdf", {"vaultId": "other"})
        self.assertEqual(client.bodies[0]["configuration"]["vaultId"], "other")

    def test_a_missing_run_id_is_an_error_rather_than_a_silent_pass(self):
        client = RecordingClient([{}])
        with self.assertRaises(SkyflowError):
            client.deidentify_file_url(SIGNED_URL, "pdf", build_file_configuration())


class BuildFileConfigurationTestCase(unittest.TestCase):
    def test_entity_types_are_upper_cased_for_v2(self):
        detect = build_file_configuration(("name", "email_address"))["detect"]
        self.assertEqual(
            [e["entityType"] for e in detect["entities"]], ["NAME", "EMAIL_ADDRESS"]
        )

    def test_no_entity_types_means_detect_everything(self):
        detect = build_file_configuration()["detect"]
        self.assertEqual([e["entityType"] for e in detect["entities"]], ["ALL"])

    def test_vault_tokens_are_requested_for_a_supported_format(self):
        detect = build_file_configuration(("name",), "vault_token", "csv")["detect"]
        self.assertEqual(detect["entities"][0]["deidentificationType"], "VAULT_TOKEN")

    def test_vault_tokens_are_downgraded_for_a_format_that_cannot_support_them(self):
        """VAULT_TOKEN on a PDF is rejected by the API; counters still work."""
        self.assertNotIn("pdf", VAULT_TOKEN_FORMATS)
        detect = build_file_configuration(("name",), "vault_token", "pdf")["detect"]
        self.assertEqual(detect["entities"][0]["deidentificationType"], "ENTITY_UNIQUE_COUNTER")

    def test_counters_are_the_default(self):
        detect = build_file_configuration(("name",), data_format="csv")["detect"]
        self.assertEqual(detect["entities"][0]["deidentificationType"], "ENTITY_UNIQUE_COUNTER")

    def test_no_vault_id_is_added_here(self):
        """The client injects it, so a configuration stays portable."""
        self.assertNotIn("vaultId", build_file_configuration())


class GetRunTestCase(unittest.TestCase):
    def test_parses_status_and_outputs(self):
        client = RecordingClient([run_response("SUCCESS", [(CLEAN_URL, "REDACTED_FILE", "pdf")])])
        result = client.get_run("run-1")
        self.assertTrue(result.succeeded)
        self.assertEqual(result.outputs[0].url, CLEAN_URL)

    def test_the_vault_id_is_sent_as_a_query_parameter(self):
        client = RecordingClient([run_response("SUCCESS")])
        client.get_run("run-1")
        method, path, _ = client.requests[0]
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/v2/detect/runs/run-1?vaultId=vault123")

    def test_a_run_id_is_url_encoded(self):
        client = RecordingClient([run_response("SUCCESS")])
        client.get_run("run/../1")
        self.assertIn("run%2F..%2F1", client.requests[0][1])

    def test_queued_and_in_progress_are_not_terminal(self):
        for status in ("QUEUED", "IN_PROGRESS"):
            with self.subTest(status):
                self.assertFalse(FileRunResult(status=status).is_terminal)

    def test_success_failed_and_unknown_are_terminal(self):
        for status in ("SUCCESS", "FAILED", "UNKNOWN"):
            with self.subTest(status):
                self.assertTrue(FileRunResult(status=status).is_terminal)

    def test_outputs_without_a_url_are_dropped(self):
        client = RecordingClient([{"status": "SUCCESS", "output": [{"processedFileType": "x"}]}])
        self.assertEqual(client.get_run("run-1").outputs, ())


class FirstDocumentTestCase(unittest.TestCase):
    def test_entity_metadata_is_not_mistaken_for_the_document(self):
        """A run returns the file plus entity JSON; swapping in the JSON would
        hand the agent a list of detected entities instead of the file."""
        result = FileRunResult(
            status="SUCCESS",
            outputs=(
                FileOutput(url="https://x/entities.json", file_type="ENTITIES", extension="json"),
                FileOutput(url=CLEAN_URL, file_type="REDACTED_FILE", extension="pdf"),
            ),
        )
        self.assertEqual(result.first_document().url, CLEAN_URL)

    def test_a_json_document_is_still_a_document(self):
        result = FileRunResult(
            status="SUCCESS",
            outputs=(FileOutput(url=CLEAN_URL, file_type="REDACTED_FILE", extension="json"),),
        )
        self.assertEqual(result.first_document().url, CLEAN_URL)

    def test_no_outputs_yields_none(self):
        self.assertIsNone(FileRunResult(status="SUCCESS").first_document())


class WaitForRunTestCase(unittest.TestCase):
    def test_returns_as_soon_as_the_run_is_terminal(self):
        client = RecordingClient([
            run_response("QUEUED"),
            run_response("IN_PROGRESS"),
            run_response("SUCCESS", [(CLEAN_URL, "REDACTED_FILE", "pdf")]),
        ])
        result = client.wait_for_run("run-1", lambda: 60.0, poll_initial_seconds=0)
        self.assertTrue(result.succeeded)
        self.assertEqual(len(client.requests), 3)

    def test_a_failed_run_is_returned_not_retried_forever(self):
        client = RecordingClient([run_response("FAILED", message="unsupported format")])
        result = client.wait_for_run("run-1", lambda: 60.0, poll_initial_seconds=0)
        self.assertFalse(result.succeeded)
        self.assertEqual(result.message, "unsupported format")

    def test_gives_up_when_the_caller_budget_runs_out(self):
        client = RecordingClient([run_response("QUEUED")] * 5)
        with self.assertRaises(RunTimeout):
            client.wait_for_run("run-1", lambda: 3.0, reserve_seconds=3.0, poll_initial_seconds=0.1)

    def test_the_reserve_is_held_back_so_a_response_can_still_be_returned(self):
        """With 4s left and a 3s reserve there is 1s of budget, not 4."""
        client = RecordingClient([run_response("QUEUED")])
        with self.assertRaises(RunTimeout):
            client.wait_for_run("run-1", lambda: 4.0, reserve_seconds=3.0, poll_initial_seconds=2.0)

    def test_the_poll_interval_backs_off_but_is_capped(self):
        sleeps = []
        client = RecordingClient([run_response("QUEUED")] * 6 + [run_response("SUCCESS")])
        import skyflow_client

        real_sleep = skyflow_client.time.sleep
        skyflow_client.time.sleep = sleeps.append
        try:
            client.wait_for_run(
                "run-1", lambda: 600.0, poll_initial_seconds=1.0, poll_max_seconds=4.0
            )
        finally:
            skyflow_client.time.sleep = real_sleep
        self.assertEqual(sleeps, [1.0, 2.0, 4.0, 4.0, 4.0, 4.0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
