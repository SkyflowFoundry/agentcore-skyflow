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

from mcp_client.diagnostics import MAX_LOGGED_ERROR_BODY, log_http_errors  # noqa: E402

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
