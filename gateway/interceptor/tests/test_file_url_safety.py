"""File URLs are fetched from inside AWS, so which ones may be is a security boundary.

The size probe requests the URL from the interceptor Lambda and Skyflow fetches
it from its own network. A tool that controls its response controls the URL, so
these tests pin down the three layers between that URL and a request (SC-16092):

1. `files.urlPatterns` is an allowlist of `https` hosts and paths, required
   for every active rule and checked for every URL, named field or not.
2. A pattern's host wildcard cannot cross a dot, so a glob cannot be stretched
   over an attacker's domain.
3. The probe itself speaks only HTTPS, follows no redirects, and refuses to
   connect to any address that is not public.

Run: python3 gateway/interceptor/tests/test_file_url_safety.py
"""

from __future__ import annotations

import io
import json
import os
import socket
import sys
import unittest
import urllib.error
import urllib.request
from email.message import Message
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
from policy import FileRule, PolicyError, PolicySet, UrlPattern, split_file_url  # noqa: E402

from test_file_interception import CLEAN, FakeFileClient, response_event  # noqa: E402

#: The shipped pattern, and a URL shaped exactly like the S3 target's output.
SHIPPED = "https://agentcore-skyflow-files-*.s3.amazonaws.com/*"
PRESIGNED = (
    "https://agentcore-skyflow-files-123456789012.s3.amazonaws.com/claims/a%20b.pdf"
    "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc"
)


def rule(*patterns: str) -> FileRule:
    return FileRule(action="deidentify", url_patterns=patterns or (SHIPPED,))


class PatternParsingTestCase(unittest.TestCase):
    def test_well_formed_patterns_are_accepted(self):
        for pattern in (
            SHIPPED,
            "https://my-bucket.s3.amazonaws.com/*",
            "https://*.s3.amazonaws.com/claims/*",
            "https://files.example.com",
        ):
            with self.subTest(pattern):
                UrlPattern.parse(pattern)

    def test_patterns_that_cannot_be_an_allowlist_are_rejected(self):
        for pattern in (
            "*",                                # every string
            "*.pdf",                            # the old whole-URL style
            "https://*/*",                      # every host
            "https://*.com/*",                  # every host under a TLD
        ):
            with self.subTest(pattern):
                with self.assertRaises(PolicyError):
                    UrlPattern.parse(pattern)

    def test_a_wildcard_below_the_owning_domain_is_allowed(self):
        UrlPattern.parse("https://bucket.*.amazonaws.com/*")

    def test_other_schemes_ports_users_and_queries_are_rejected(self):
        for pattern in (
            "http://bucket.s3.amazonaws.com/*",
            "file:///var/task/*",
            "https://bucket.s3.amazonaws.com:8443/*",
            "https://user@bucket.s3.amazonaws.com/*",
            "https://bucket.s3.amazonaws.com/*?X-Amz-*",
            "https://bucket.s3.amazonaws.com/*#frag",
            "https://bucket.s3.amazonaws.com\\@evil.com/*",
            "https://bücket.s3.amazonaws.com/*",
            "https://bucket.s3.amazonaws.com/a b/*",
        ):
            with self.subTest(pattern):
                with self.assertRaises(PolicyError):
                    UrlPattern.parse(pattern)

    def test_an_active_rule_needs_patterns_even_with_fields(self):
        with self.assertRaises(PolicyError):
            FileRule(action="deidentify", fields=("url",))

    def test_a_bad_pattern_fails_the_policy_when_it_loads(self):
        with self.assertRaises(PolicyError):
            PolicySet.from_json({"defaults": {"files": {
                "action": "deidentify", "urlPatterns": ["https://*/*"]}}})

    def test_the_shipped_policy_still_loads(self):
        shipped = Path(__file__).resolve().parents[1] / "config" / "policy.json"
        PolicySet.from_json(json.loads(shipped.read_text()))


class PatternMatchingTestCase(unittest.TestCase):
    def test_the_s3_targets_presigned_url_is_allowed(self):
        self.assertTrue(rule().matches_url(PRESIGNED))

    def test_host_case_does_not_matter(self):
        self.assertTrue(rule().matches_url(PRESIGNED.replace("agentcore-skyflow-files", "AGENTCORE-SKYFLOW-FILES")))

    def test_a_host_wildcard_cannot_cross_into_another_domain(self):
        """The reported bypass: fnmatch's * matched dots and slashes."""
        for url in (
            "https://agentcore-skyflow-files-x.evil.com/.s3.amazonaws.com/a.pdf",
            "https://agentcore-skyflow-files-1.s3.amazonaws.com.evil.com/a.pdf",
            "https://agentcore-skyflow-files-1.evil.s3.amazonaws.com/a.pdf",
        ):
            with self.subTest(url):
                self.assertFalse(rule().matches_url(url))

    def test_urls_a_parser_could_read_two_ways_are_refused(self):
        for url in (
            "https://agentcore-skyflow-files-1.s3.amazonaws.com@evil.com/a.pdf",
            "https://evil.com\\@agentcore-skyflow-files-1.s3.amazonaws.com/a.pdf",
            "https://agentcore-skyflow-files-1.s3.amazonaws.com\t.evil.com/a.pdf",
            "https://agentcore-skyflow-files-1.s3.amazonaws.com./a.pdf",
            "https://agentcore-skyflow-files-1.s3.amazonaws.com:8443/a.pdf",
        ):
            with self.subTest(url):
                self.assertFalse(rule().matches_url(url))

    def test_only_https_is_ever_allowed(self):
        for url in (
            PRESIGNED.replace("https://", "http://"),
            "file:///proc/self/environ",
            "ftp://agentcore-skyflow-files-1.s3.amazonaws.com/a.pdf",
            "data:text/plain,hello",
        ):
            with self.subTest(url):
                self.assertFalse(rule().matches_url(url))

    def test_internal_addresses_never_match_a_named_host(self):
        for url in ("https://169.254.169.254/latest/a.pdf", "https://127.0.0.1/a.pdf", "https://[::1]/a.pdf"):
            with self.subTest(url):
                self.assertFalse(rule().matches_url(url))

    def test_the_path_is_matched_as_well_as_the_host(self):
        scoped = rule("https://bucket.s3.amazonaws.com/claims/*")
        self.assertTrue(scoped.matches_url("https://bucket.s3.amazonaws.com/claims/a.pdf"))
        self.assertFalse(scoped.matches_url("https://bucket.s3.amazonaws.com/private/a.pdf"))

    def test_the_query_string_is_ignored(self):
        self.assertTrue(rule("https://bucket.s3.amazonaws.com/*.pdf").matches_url(
            "https://bucket.s3.amazonaws.com/a.pdf?X-Amz-Signature=x"))

    def test_split_file_url_returns_host_and_path(self):
        self.assertEqual(
            split_file_url(PRESIGNED),
            ("agentcore-skyflow-files-123456789012.s3.amazonaws.com", "/claims/a%20b.pdf"),
        )
        self.assertIsNone(split_file_url(42))


class ScanModeTestCase(unittest.TestCase):
    """Without named fields, a string that fails the allowlist is not a file at all."""

    POLICY = {
        "defaults": {
            "request": {"action": "none"},
            "response": {"action": "none"},
            "scope": {"minLength": 4},
            "failure": {"onError": "fail_closed"},
            "files": {"action": "deidentify", "directions": ["response"], "urlPatterns": [SHIPPED]},
        },
        "toolNameSeparator": "___",
    }

    def setUp(self):
        self.client = FakeFileClient()
        self._load, self._build = settings.load_policy, settings.build_client
        settings.load_policy = lambda force=False: PolicySet.from_json(self.POLICY)
        settings.build_client = lambda: self.client

    def tearDown(self):
        settings.load_policy, settings.build_client = self._load, self._build

    def test_a_lookalike_host_is_neither_fetched_nor_submitted(self):
        lookalike = "https://agentcore-skyflow-files-x.evil.com/.s3.amazonaws.com/a.pdf"
        out = handler.lambda_handler(response_event({"url": lookalike}), None)
        result = out["mcp"]["transformedGatewayResponse"]["body"]["result"]
        self.assertEqual(result["url"], lookalike, "left alone: it is not a file reference")
        self.assertEqual(self.client.submitted, [])

    def test_the_real_url_is_still_swapped(self):
        out = handler.lambda_handler(response_event({"url": PRESIGNED}), None)
        self.assertEqual(out["mcp"]["transformedGatewayResponse"]["body"]["result"]["url"], CLEAN)


class AddressTestCase(unittest.TestCase):
    def test_non_public_addresses_are_refused(self):
        for address in (
            "169.254.169.254",      # instance metadata
            "169.254.170.2",        # ECS task metadata
            "127.0.0.1", "::1",
            "10.0.0.5", "172.16.0.1", "192.168.1.1",
            "100.64.0.1",           # carrier-grade NAT
            "0.0.0.0",
            "fd00::1", "fe80::1%eth0",
            "::ffff:127.0.0.1", "::ffff:169.254.169.254",
            "224.0.0.1",
        ):
            with self.subTest(address):
                self.assertFalse(file_urls._is_public(address))

    def test_public_addresses_are_allowed(self):
        for address in ("52.216.0.1", "8.8.8.8", "2600:1f18::1", "::ffff:52.216.0.1"):
            with self.subTest(address):
                self.assertTrue(file_urls._is_public(address))

    def test_the_connection_is_refused_before_any_bytes_are_sent(self):
        """Checked on the socket's real peer, so DNS cannot route around it."""
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        self.addCleanup(server.close)
        with self.assertRaises(file_urls.UnsafeFileUrl):
            file_urls._public_only_connection(server.getsockname(), 2)
        server.settimeout(2)
        accepted, _ = server.accept()
        self.addCleanup(accepted.close)
        accepted.settimeout(0.5)
        self.assertEqual(accepted.recv(1), b"", "closed without sending a TLS hello")


class ProbeTestCase(unittest.TestCase):
    def test_the_opener_has_no_redirect_proxy_or_non_https_handlers(self):
        opener = file_urls._probe_opener()
        kinds = {type(h) for h in opener.handlers}
        for banned in (
            urllib.request.HTTPRedirectHandler,
            urllib.request.ProxyHandler,
            urllib.request.HTTPHandler,
            urllib.request.FileHandler,
            urllib.request.FTPHandler,
            urllib.request.DataHandler,
            urllib.request.UnknownHandler,
        ):
            with self.subTest(banned.__name__):
                self.assertNotIn(banned, kinds)
        self.assertIn(file_urls._PublicHTTPSHandler, kinds)

    def test_a_url_that_is_not_plain_https_raises_rather_than_returning_unknown(self):
        for url in ("file:///etc/passwd.pdf", "http://bucket.s3.amazonaws.com/a.pdf",
                    "https://bucket.s3.amazonaws.com:8443/a.pdf", "https://u@bucket.s3.amazonaws.com/a.pdf"):
            with self.subTest(url):
                with self.assertRaises(file_urls.UnsafeFileUrl):
                    file_urls.content_length(url)

    def test_a_redirect_is_not_followed(self):
        """A 302 to the metadata service must end the probe, not continue it."""
        requested = []

        def fake_open(handler_self, req):
            requested.append(req.full_url)
            headers = Message()
            headers["Location"] = "http://169.254.169.254/latest/meta-data/"
            response = urllib.request.addinfourl(io.BytesIO(b""), headers, req.full_url, 302)
            response.msg = "Found"
            return response

        original = file_urls._PublicHTTPSHandler.https_open
        file_urls._PublicHTTPSHandler.https_open = fake_open
        self.addCleanup(setattr, file_urls._PublicHTTPSHandler, "https_open", original)

        with self.assertLogs("file_urls", level="WARNING") as logs:
            size = file_urls.content_length(PRESIGNED)
        self.assertIsNone(size)
        self.assertEqual(requested, [PRESIGNED], "exactly one request, to the allowed URL")
        self.assertIn("redirect_not_followed", "\n".join(logs.output))

    def test_an_unsafe_url_fails_the_call_closed(self):
        """The handler turns a refused probe into a blocked call, not a skipped check."""
        policy = {
            "defaults": {
                "request": {"action": "none"}, "response": {"action": "none"},
                "scope": {"minLength": 4}, "failure": {"onError": "fail_closed"},
                "files": {"action": "deidentify", "directions": ["response"],
                          "urlPatterns": [SHIPPED], "maxFileBytes": 1000},
            },
            "toolNameSeparator": "___",
        }
        client = FakeFileClient()
        load, build, length = settings.load_policy, settings.build_client, file_urls.content_length
        settings.load_policy = lambda force=False: PolicySet.from_json(policy)
        settings.build_client = lambda: client

        def refuse(url, timeout=5.0):
            raise file_urls.UnsafeFileUrl("file host resolved to non-public address 10.0.0.5")

        file_urls.content_length = refuse
        try:
            body = handler.lambda_handler(response_event({"url": PRESIGNED}), None)[
                "mcp"]["transformedGatewayResponse"]["body"]
        finally:
            settings.load_policy, settings.build_client, file_urls.content_length = load, build, length
        self.assertIn("error", body)
        self.assertEqual(client.submitted, [], "nothing reaches Skyflow")


if __name__ == "__main__":
    unittest.main(verbosity=2)
