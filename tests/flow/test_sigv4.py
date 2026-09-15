"""SigV4 signing of the MCP transport's requests.

Needs httpx and botocore, but no AWS account and no network: credentials are
supplied directly and only the headers the signer produces are inspected.

Run: python3 tests/flow/test_sigv4.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "app" / "Flow"))

import httpx  # noqa: E402
from botocore.credentials import ReadOnlyCredentials  # noqa: E402

from mcp_client.sigv4 import SERVICE, SigV4Auth  # noqa: E402

GATEWAY_URL = "https://agentflow-skyflowgateway-k7lrzhryea.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"

TOOLS_CALL = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {"name": "exa___web_search_exa", "arguments": {"query": "anything"}},
}


class FakeCredentials:
    """Counts freezes, so a test can prove the signer re-reads on every request."""

    def __init__(self, access_key="AKIDEXAMPLE", secret_key="wJalrXUtnFEMI", token=None):
        self._frozen = ReadOnlyCredentials(access_key, secret_key, token)
        self.freeze_count = 0

    def get_frozen_credentials(self):
        self.freeze_count += 1
        return self._frozen


class FakeSession:
    def __init__(self, credentials):
        self._credentials = credentials

    def get_credentials(self):
        return self._credentials


def sign(request: httpx.Request, credentials=None, region="us-east-1") -> httpx.Request:
    auth = SigV4Auth(region=region, session=FakeSession(credentials or FakeCredentials()))
    return next(auth.auth_flow(request))


def post(url=GATEWAY_URL, json=TOOLS_CALL) -> httpx.Request:
    return httpx.Request("POST", url, json=json, headers={"Accept": "application/json"})


class SigningTestCase(unittest.TestCase):
    def test_requires_the_body_so_httpx_reads_it_before_signing(self):
        """Without this the payload hash would be computed over an empty body."""
        self.assertTrue(SigV4Auth.requires_request_body)

    def test_authorization_header_is_added(self):
        header = sign(post()).headers["authorization"]
        self.assertTrue(header.startswith("AWS4-HMAC-SHA256 "))
        self.assertIn("Credential=AKIDEXAMPLE/", header)

    def test_credential_scope_names_the_gateway_service_and_region(self):
        header = sign(post()).headers["authorization"]
        self.assertIn(f"/us-east-1/{SERVICE}/aws4_request", header)
        self.assertEqual(SERVICE, "bedrock-agentcore")

    def test_region_comes_from_the_caller_not_the_url(self):
        header = sign(post(), region="eu-west-2").headers["authorization"]
        self.assertIn(f"/eu-west-2/{SERVICE}/aws4_request", header)

    def test_date_header_is_added(self):
        signed = sign(post())
        self.assertRegex(signed.headers["x-amz-date"], r"^\d{8}T\d{6}Z$")

    def test_host_is_signed(self):
        header = sign(post()).headers["authorization"]
        signed_headers = header.split("SignedHeaders=")[1].split(",")[0]
        self.assertIn("host", signed_headers.split(";"))

    def test_session_token_is_forwarded_for_temporary_credentials(self):
        signed = sign(post(), credentials=FakeCredentials(token="FwoGZXIvYXdz"))
        self.assertEqual(signed.headers["x-amz-security-token"], "FwoGZXIvYXdz")

    def test_no_session_token_header_for_long_lived_credentials(self):
        self.assertNotIn("x-amz-security-token", sign(post()).headers)

    def test_the_body_is_covered_by_the_signature(self):
        """A tampered payload must not verify under the original signature."""
        first = sign(post(json=TOOLS_CALL)).headers["authorization"]
        altered = {**TOOLS_CALL, "params": {"name": "exa___web_search_exa", "arguments": {"query": "other"}}}
        second = sign(post(json=altered)).headers["authorization"]
        self.assertNotEqual(first, second)

    def test_the_path_is_covered_by_the_signature(self):
        first = sign(post()).headers["authorization"]
        second = sign(post(url=GATEWAY_URL.replace("/mcp", "/other"))).headers["authorization"]
        self.assertNotEqual(first, second)

    def test_original_headers_survive_signing(self):
        signed = sign(post())
        self.assertEqual(signed.headers["accept"], "application/json")
        self.assertEqual(signed.headers["content-type"], "application/json")

    def test_a_bodiless_request_signs(self):
        """The SSE GET and the terminating DELETE carry no body."""
        for method in ("GET", "DELETE"):
            with self.subTest(method):
                signed = sign(httpx.Request(method, GATEWAY_URL))
                self.assertIn("AWS4-HMAC-SHA256", signed.headers["authorization"])

    def test_credentials_are_refreshed_per_request(self):
        """Container credentials expire; freezing once at construction would pin them."""
        credentials = FakeCredentials()
        auth = SigV4Auth(region="us-east-1", session=FakeSession(credentials))
        for _ in range(3):
            next(auth.auth_flow(post()))
        self.assertEqual(credentials.freeze_count, 3)

    def test_missing_credentials_fail_loudly(self):
        with self.assertRaises(RuntimeError) as ctx:
            SigV4Auth(region="us-east-1", session=FakeSession(None))
        self.assertIn("No AWS credentials", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
