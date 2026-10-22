"""Skyflow Detect client: request shape, retry behaviour, and error handling.

urllib is patched throughout — these tests never touch the network.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from skyflow_client import SkyflowClient, SkyflowError  # noqa: E402


def response(payload: dict):
    body = json.dumps(payload).encode()
    resp = mock.MagicMock()
    resp.read.return_value = body
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    return resp


def http_error(code: int, body: str = "error detail"):
    return urllib.error.HTTPError(
        url="https://vault.example/v1/detect/deidentify/string",
        code=code,
        msg="err",
        hdrs=None,
        fp=io.BytesIO(body.encode()),
    )


def client(**kwargs):
    defaults = dict(
        vault_url="https://vault.example/",
        vault_id="vault123",
        api_key="test-key",
        max_retries=2,
        backoff_initial_ms=1,
    )
    defaults.update(kwargs)
    return SkyflowClient(**defaults)


class RequestShapeTestCase(unittest.TestCase):
    def _capture(self, payload: dict, call):
        with mock.patch("urllib.request.urlopen", return_value=response(payload)) as urlopen:
            result = call()
        request = urlopen.call_args[0][0]
        return result, request, json.loads(request.data.decode())

    def test_deidentify_body_and_headers(self):
        _, request, body = self._capture(
            {"processed_text": "tokenized", "entities": []},
            lambda: client().deidentify("secret text", ["name", "ssn"]),
        )
        self.assertEqual(request.full_url, "https://vault.example/v1/detect/deidentify/string")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.headers["Authorization"], "Bearer test-key")
        self.assertEqual(body["text"], "secret text")
        self.assertEqual(body["vault_id"], "vault123")
        self.assertEqual(body["entity_types"], ["name", "ssn"])

    def test_trailing_slash_on_vault_url_does_not_double_up(self):
        _, request, _ = self._capture(
            {"processed_text": "x", "entities": []},
            lambda: client(vault_url="https://vault.example///").deidentify("text", ["name"]),
        )
        self.assertNotIn("//v1", request.full_url.replace("https://", ""))

    def test_counter_tokens_omit_token_type_entirely(self):
        _, _, body = self._capture(
            {"processed_text": "x", "entities": []},
            lambda: client().deidentify("text", ["name"], vault_token_entity_types=None),
        )
        self.assertNotIn("token_type", body, "counter is the API default; sending nothing selects it")

    def test_vault_tokens_request_them_explicitly(self):
        _, _, body = self._capture(
            {"processed_text": "x", "entities": []},
            lambda: client().deidentify("text", ["name"], vault_token_entity_types=["name"]),
        )
        self.assertEqual(body["token_type"], {"vault_token": ["name"]})

    def test_reidentify_body(self):
        result, request, body = self._capture(
            {"text": "Jane Doe"},
            lambda: client().reidentify("[NAME_abc]"),
        )
        self.assertEqual(request.full_url, "https://vault.example/v1/detect/reidentify/string")
        self.assertEqual(body, {"text": "[NAME_abc]", "vault_id": "vault123"})
        self.assertEqual(result.text, "Jane Doe")

    def test_missing_fields_fall_back_to_the_input(self):
        with mock.patch("urllib.request.urlopen", return_value=response({})):
            self.assertEqual(client().deidentify("original", ["name"]).processed_text, "original")
            self.assertEqual(client().reidentify("original").text, "original")


class RetryTestCase(unittest.TestCase):
    def test_retries_retryable_status_then_succeeds(self):
        outcomes = [http_error(503), response({"processed_text": "ok", "entities": []})]
        with mock.patch("urllib.request.urlopen", side_effect=outcomes) as urlopen:
            with mock.patch("time.sleep"):
                result = client().deidentify("text", ["name"])
        self.assertEqual(result.processed_text, "ok")
        self.assertEqual(urlopen.call_count, 2)

    def test_gives_up_after_max_retries(self):
        with mock.patch("urllib.request.urlopen", side_effect=http_error(503)) as urlopen:
            with mock.patch("time.sleep"):
                with self.assertRaises(SkyflowError):
                    client(max_retries=2).deidentify("text", ["name"])
        self.assertEqual(urlopen.call_count, 3, "initial attempt plus two retries")

    def test_non_retryable_status_fails_immediately(self):
        with mock.patch("urllib.request.urlopen", side_effect=http_error(401)) as urlopen:
            with self.assertRaises(SkyflowError):
                client().deidentify("text", ["name"])
        self.assertEqual(urlopen.call_count, 1, "4xx other than 429 must not be retried")

    def test_network_errors_are_retried(self):
        outcomes = [urllib.error.URLError("dns"), response({"processed_text": "ok", "entities": []})]
        with mock.patch("urllib.request.urlopen", side_effect=outcomes):
            with mock.patch("time.sleep"):
                self.assertEqual(client().deidentify("t", ["name"]).processed_text, "ok")

    def test_backoff_doubles(self):
        with mock.patch("urllib.request.urlopen", side_effect=http_error(500)):
            with mock.patch("time.sleep") as sleep:
                with self.assertRaises(SkyflowError):
                    client(max_retries=2, backoff_initial_ms=100).deidentify("t", ["name"])
        self.assertEqual([c[0][0] for c in sleep.call_args_list], [0.1, 0.2])

    def test_rate_limit_is_retryable(self):
        outcomes = [http_error(429), response({"processed_text": "ok", "entities": []})]
        with mock.patch("urllib.request.urlopen", side_effect=outcomes):
            with mock.patch("time.sleep"):
                self.assertEqual(client().deidentify("t", ["name"]).processed_text, "ok")


class ErrorDisclosureTestCase(unittest.TestCase):
    def test_error_body_is_not_included_in_the_exception(self):
        """A Detect error can echo the submitted text, which is the sensitive data."""
        secret = "Jane Doe jane@example.com"
        with mock.patch("urllib.request.urlopen", side_effect=http_error(400, f"invalid: {secret}")):
            with self.assertRaises(SkyflowError) as ctx:
                client().deidentify(secret, ["name"])
        self.assertNotIn(secret, str(ctx.exception))
        self.assertIn("400", str(ctx.exception))

    def test_error_body_is_not_logged(self):
        secret = "Jane Doe jane@example.com"
        with mock.patch("urllib.request.urlopen", side_effect=http_error(400, f"invalid: {secret}")):
            with self.assertLogs("skyflow_client", level="DEBUG") as logs:
                # A log record is emitted for the failure path; assert on its content.
                import logging
                logging.getLogger("skyflow_client").debug("probe")
                with self.assertRaises(SkyflowError):
                    client().deidentify(secret, ["name"])
        self.assertFalse(
            any(secret in line for line in logs.output),
            "response bodies must never reach the logs",
        )


class KeyRotationTestCase(unittest.TestCase):
    """A 401 re-reads the key once, so a rotated secret does not mean an outage."""

    def test_a_401_refreshes_the_key_and_retries(self):
        refreshed = []
        c = client(refresh_api_key=lambda: refreshed.append(1) or "new-key")
        with mock.patch("urllib.request.urlopen",
                        side_effect=[http_error(401), response({"processed_text": "ok"})]) as urlopen:
            self.assertEqual(c.deidentify("x", ["name"]).processed_text, "ok")
        self.assertEqual(refreshed, [1])
        self.assertEqual(urlopen.call_args_list[1][0][0].get_header("Authorization"), "Bearer new-key")

    def test_the_refresh_does_not_spend_a_retry(self):
        c = client(max_retries=0, refresh_api_key=lambda: "new-key")
        with mock.patch("urllib.request.urlopen",
                        side_effect=[http_error(401), response({"processed_text": "ok"})]):
            self.assertEqual(c.deidentify("x", ["name"]).processed_text, "ok")

    def test_an_unchanged_key_fails_without_looping(self):
        c = client(refresh_api_key=lambda: "test-key")
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(401)]) as urlopen:
            with self.assertRaisesRegex(SkyflowError, "status 401"):
                c.deidentify("x", ["name"])
        self.assertEqual(urlopen.call_count, 1)

    def test_a_second_401_is_not_refreshed_again(self):
        calls = []
        c = client(refresh_api_key=lambda: calls.append(1) or f"key-{len(calls)}")
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(401), http_error(401)]):
            with self.assertRaisesRegex(SkyflowError, "status 401"):
                c.deidentify("x", ["name"])
        self.assertEqual(calls, [1])

    def test_a_key_another_call_already_refreshed_is_still_retried(self):
        """Fields are transformed in parallel on one client. If another call
        swapped the key while this one was in flight, the refreshed key differs
        from the one this request sent, and it must retry rather than give up."""
        c = client(refresh_api_key=lambda: "new-key")

        def first_call(request, timeout):
            c._api_key = "new-key"  # a parallel call got there first
            raise http_error(401)

        calls = iter([first_call, lambda request, timeout: response({"processed_text": "ok"})])
        with mock.patch("urllib.request.urlopen", side_effect=lambda request, timeout: next(calls)(request, timeout)):
            self.assertEqual(c.deidentify("x", ["name"]).processed_text, "ok")

    def test_without_a_refresher_a_401_fails_as_before(self):
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(401)]):
            with self.assertRaisesRegex(SkyflowError, "status 401"):
                client().deidentify("x", ["name"])


class FileErrorDetailTestCase(unittest.TestCase):
    """File endpoint errors are readable; string endpoint errors stay opaque."""

    SIGNED = "https://bucket.s3.amazonaws.com/doc.txt?X-Amz-Signature=deadbeef&X-Amz-Credential=AKIA"

    def test_a_file_submit_error_carries_the_reason(self):
        body = '{"error":{"message":"Missing Destination for entity NAME in DetectConfigV2"}}'
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(400, body)]):
            with self.assertRaises(SkyflowError) as caught:
                client().deidentify_file_url(self.SIGNED, "txt", {})
        self.assertIn("Missing Destination for entity NAME", str(caught.exception))

    def test_a_url_in_the_body_is_cut_to_its_host(self):
        body = f'{{"error":"could not fetch {self.SIGNED}"}}'
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(400, body)]):
            with self.assertRaises(SkyflowError) as caught:
                client().deidentify_file_url(self.SIGNED, "txt", {})
        message = str(caught.exception)
        self.assertIn("bucket.s3.amazonaws.com", message)
        self.assertNotIn("deadbeef", message)
        self.assertNotIn("AKIA", message)

    def test_a_long_body_is_capped(self):
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(400, "x" * 5000)]):
            with self.assertRaises(SkyflowError) as caught:
                client().deidentify_file_url(self.SIGNED, "txt", {})
        self.assertLess(len(str(caught.exception)), 400)

    def test_a_string_endpoint_body_is_still_withheld(self):
        with mock.patch("urllib.request.urlopen", side_effect=[http_error(400, "Jane Doe was here")]):
            with self.assertRaises(SkyflowError) as caught:
                client().deidentify("Jane Doe was here", ["name"])
        self.assertNotIn("Jane", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
