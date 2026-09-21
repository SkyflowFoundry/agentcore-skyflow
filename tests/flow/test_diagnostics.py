"""Error-response logging.

This is the hook that turns Strands' "Connection to the MCP server was closed"
into the server's actual message, so it has to behave under conditions where
the response is awkward: a stream, an unreadable body, a huge body.

Needs httpx only.

Run: python3 tests/flow/test_diagnostics.py
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "app" / "Flow"))

import httpx  # noqa: E402

from mcp_client.diagnostics import MAX_LOGGED_ERROR_BODY, REDACTED, log_http_errors, redact_credentials  # noqa: E402

GATEWAY_400 = (
    '{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":'
    '"Config bundle fetch failed: ... is not authorized to perform: '
    'bedrock-agentcore:GetConfigurationBundleVersion ..."}}'
)


def response(status: int, body: bytes = b"") -> httpx.Response:
    return httpx.Response(status, content=body, request=httpx.Request("POST", "https://gw/mcp"))


def run(coro):
    return asyncio.run(coro)


class LogHttpErrorsTestCase(unittest.TestCase):
    def test_a_gateway_error_body_reaches_the_log(self):
        with self.assertLogs("mcp_client.diagnostics", level="ERROR") as logs:
            run(log_http_errors(response(400, GATEWAY_400.encode())))
        line = "\n".join(logs.output)
        self.assertIn("HTTP 400", line)
        self.assertIn("GetConfigurationBundleVersion", line)

    def test_success_is_not_logged(self):
        for status in (200, 202, 204, 399):
            with self.subTest(status):
                with self.assertNoLogs("mcp_client.diagnostics", level="ERROR"):
                    run(log_http_errors(response(status, b"ok")))

    def test_a_success_body_is_never_read(self):
        """Reading an SSE stream here would consume it before the caller sees it."""
        reads = []

        class Streaming(httpx.Response):
            async def aread(self):  # type: ignore[override]
                reads.append(1)
                return b""

        streamed = Streaming(200, request=httpx.Request("GET", "https://gw/mcp"))
        run(log_http_errors(streamed))
        self.assertEqual(reads, [], "a 2xx response must not be read")

    def test_client_and_server_errors_are_both_logged(self):
        for status in (400, 401, 403, 429, 500, 503):
            with self.subTest(status):
                with self.assertLogs("mcp_client.diagnostics", level="ERROR") as logs:
                    run(log_http_errors(response(status, b"boom")))
                self.assertIn(f"HTTP {status}", "\n".join(logs.output))

    def test_a_large_body_is_truncated(self):
        with self.assertLogs("mcp_client.diagnostics", level="ERROR") as logs:
            run(log_http_errors(response(500, b"x" * (MAX_LOGGED_ERROR_BODY * 3))))
        logged = logs.records[0].getMessage()
        self.assertEqual(logged.count("x"), MAX_LOGGED_ERROR_BODY)

    def test_an_unreadable_body_still_logs_the_status(self):
        """Diagnostics must never replace the real failure with their own."""

        class Broken(httpx.Response):
            async def aread(self):  # type: ignore[override]
                raise httpx.ReadError("stream already consumed")

        with self.assertLogs("mcp_client.diagnostics", level="ERROR") as logs:
            run(log_http_errors(Broken(502, request=httpx.Request("POST", "https://gw/mcp"))))
        line = "\n".join(logs.output)
        self.assertIn("HTTP 502", line)
        self.assertIn("<unreadable>", line)

    def test_an_empty_error_body_is_fine(self):
        with self.assertLogs("mcp_client.diagnostics", level="ERROR") as logs:
            run(log_http_errors(response(504)))
        self.assertIn("HTTP 504", "\n".join(logs.output))


SESSION_TOKEN = "FwoGZXIvYXdzEBYaDFAKESESSIONTOKENabcdefghijklmnopqrstuvwxyz0123456789"
SIGV4_MISMATCH = (
    "The request signature we calculated does not match the signature you provided. "
    "The Canonical String for this request should have been\n"
    "'POST\n/mcp\n\naccept:application/json\nhost:gw.example.com\n"
    "x-amz-date:20260921T170000Z\n"
    f"x-amz-security-token:{SESSION_TOKEN}\n\n"
    "accept;host;x-amz-date;x-amz-security-token\nabc123'\n"
    "The String-to-Sign should have been 'AWS4-HMAC-SHA256\n20260921T170000Z\n"
    "20260921/us-east-1/bedrock-agentcore/aws4_request\ndef456'"
)


class CredentialRedactionTestCase(unittest.TestCase):
    """An error body is logged for its message, never for the credentials in it.

    A SigV4 signature mismatch is the concrete case: AWS answers with the
    canonical request, which lists every signed header with its value, and one
    of those is the caller's session token.
    """

    def logged(self, body: str) -> str:
        with self.assertLogs("mcp_client.diagnostics", level="ERROR") as logs:
            run(log_http_errors(response(403, body.encode())))
        return logs.records[0].getMessage()

    def test_a_sigv4_mismatch_body_keeps_the_message_and_drops_the_token(self):
        line = self.logged(SIGV4_MISMATCH)
        self.assertIn("HTTP 403", line)
        self.assertIn("signature we calculated does not match", line, "the diagnosis survives")
        self.assertIn("x-amz-security-token", line, "the header name survives")
        self.assertNotIn(SESSION_TOKEN, line)
        self.assertIn(REDACTED, line)

    def test_an_echoed_bearer_token_is_masked(self):
        line = self.logged('{"error": "invalid token: Bearer eyJhbGciOiJSUzI1NiJ9.payload.signature"}')
        self.assertNotIn("eyJhbGciOiJSUzI1NiJ9", line)
        self.assertIn(f"Bearer {REDACTED}", line)

    def test_an_echoed_authorization_header_is_masked_in_either_spelling(self):
        for text in ("Authorization: Basic dXNlcjpwYXNzd29yZA==", "authorization:Basic dXNlcjpwYXNzd29yZA=="):
            with self.subTest(text):
                self.assertNotIn("dXNlcjpwYXNzd29yZA", redact_credentials(text))

    def test_a_sigv4_authorization_value_is_masked(self):
        text = ("Authorization: AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260921/us-east-1/bedrock-agentcore/aws4_request, "
                "SignedHeaders=host;x-amz-date, Signature=0123456789abcdef")
        out = redact_credentials(text)
        self.assertNotIn("AKIAEXAMPLE", out)
        self.assertNotIn("0123456789abcdef", out)

    def test_an_echoed_json_secret_field_is_masked(self):
        out = redact_credentials('{"message": "bad key", "api_key": "k-live-123", "access_token": "t-456", "id": 7}')
        self.assertNotIn("k-live-123", out)
        self.assertNotIn("t-456", out)
        self.assertIn('"id": 7', out)
        self.assertIn("bad key", out)

    def test_a_token_cut_by_the_length_cap_is_still_masked(self):
        body = ("x" * (MAX_LOGGED_ERROR_BODY - 30)) + " x-amz-security-token:" + SESSION_TOKEN
        line = self.logged(body)
        self.assertNotIn(SESSION_TOKEN[:12], line)

    def test_ordinary_error_text_is_untouched(self):
        plain = '{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"Config bundle fetch failed"}}'
        self.assertEqual(redact_credentials(plain), plain)


if __name__ == "__main__":
    unittest.main(verbosity=2)
