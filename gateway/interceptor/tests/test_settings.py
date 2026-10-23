"""Settings: policy caching against SSM, and API key parsing from Secrets Manager.

boto3 clients are replaced with fakes; nothing reaches AWS.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# Set explicitly, not via setdefault: ambient values (a developer with
# SKYFLOW_VAULT_ID exported, say) would otherwise leak into the tests.
os.environ["POLICY_PARAMETER_NAME"] = "/test/policy"
os.environ["SKYFLOW_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:0:secret:test"
os.environ["SKYFLOW_VAULT_URL"] = "https://test.vault.skyflowapis.com"
os.environ["SKYFLOW_VAULT_ID"] = "vault123"

import settings  # noqa: E402

POLICY = {
    "defaults": {"request": {"action": "deidentify", "tokenType": "counter"}},
    "overrides": [{"servers": ["exa"], "tools": ["*"], "request": {"action": "none"}}],
}


class FakeSsm:
    def __init__(self, value):
        self.value = value
        self.calls = 0
        self.error: Exception | None = None
        # A read that takes this long moves `clock` on, as a slow SSM would.
        self.clock: Clock | None = None
        self.latency = 0.0

    def get_parameter(self, Name):  # noqa: N803 - boto3 casing
        self.calls += 1
        if self.clock is not None:
            self.clock.now += self.latency
        if self.error is not None:
            raise self.error
        return {"Parameter": {"Value": self.value}}


class Clock:
    """Stands in for time.monotonic so cache ages are exact."""

    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeSecrets:
    def __init__(self, stored):
        self.stored = stored
        self.calls = 0

    def get_secret_value(self, SecretId):  # noqa: N803 - boto3 casing
        self.calls += 1
        return {"SecretString": self.stored}


class SettingsTestCase(unittest.TestCase):
    def setUp(self):
        # Module-scope caches persist across invocations in a warm Lambda, so
        # each test starts from a cold one.
        settings._policy_cache = None
        settings._policy_next_read = 0.0
        settings._policy_failure = None
        settings._api_key_cache = None
        settings._api_key_refreshed_at = None


class PolicyCacheTestCase(SettingsTestCase):
    def test_loads_and_parses_from_ssm(self):
        fake = FakeSsm(json.dumps(POLICY))
        with mock.patch.object(settings, "_ssm_client", return_value=fake):
            policy_set = settings.load_policy()
        self.assertEqual(len(policy_set.overrides), 1)
        self.assertEqual(policy_set.resolve("exa", "anything").request.action, "none")

    def test_second_call_within_ttl_uses_the_cache(self):
        fake = FakeSsm(json.dumps(POLICY))
        with mock.patch.object(settings, "_ssm_client", return_value=fake):
            settings.load_policy()
            settings.load_policy()
        self.assertEqual(fake.calls, 1, "warm invocations must not re-read SSM")

    def test_force_bypasses_the_cache(self):
        fake = FakeSsm(json.dumps(POLICY))
        with mock.patch.object(settings, "_ssm_client", return_value=fake):
            settings.load_policy()
            settings.load_policy(force=True)
        self.assertEqual(fake.calls, 2)

    def test_expired_cache_is_refreshed(self):
        fake = FakeSsm(json.dumps(POLICY))
        with mock.patch.dict(os.environ, {"POLICY_CACHE_TTL_SECONDS": "0"}):
            with mock.patch.object(settings, "_ssm_client", return_value=fake):
                settings.load_policy()
                settings.load_policy()
        self.assertEqual(fake.calls, 2, "a zero TTL means every call re-reads")

    def test_edited_policy_takes_effect_after_expiry(self):
        fake = FakeSsm(json.dumps(POLICY))
        with mock.patch.dict(os.environ, {"POLICY_CACHE_TTL_SECONDS": "0"}):
            with mock.patch.object(settings, "_ssm_client", return_value=fake):
                self.assertEqual(settings.load_policy().resolve("exa", "t").request.action, "none")
                fake.value = json.dumps({"defaults": {"request": {"action": "deidentify", "tokenType": "counter"}}})
                self.assertEqual(settings.load_policy().resolve("exa", "t").request.action, "deidentify")

    def test_invalid_stored_policy_raises(self):
        broken = {"defaults": {
            "request": {"action": "deidentify", "tokenType": "counter"},
            "response": {"action": "reidentify"}}}
        with mock.patch.object(settings, "_ssm_client", return_value=FakeSsm(json.dumps(broken))):
            with self.assertLogs(settings.logger, level="ERROR"):
                with self.assertRaises(Exception):
                    settings.load_policy()


class StalePolicyTestCase(SettingsTestCase):
    """A failed refresh keeps the last good policy serving, for a while.

    Without this, one SSM throttle or one bad publish blocks every tool call
    on every warm Lambda until someone fixes it.
    """

    def setUp(self):
        super().setUp()
        self.clock = Clock()
        self.ssm = FakeSsm(json.dumps(POLICY))
        self.ssm.clock = self.clock
        patches = [
            mock.patch.object(settings.time, "monotonic", self.clock),
            mock.patch.object(settings, "_ssm_client", return_value=self.ssm),
            mock.patch.dict(os.environ, {"POLICY_CACHE_TTL_SECONDS": "60", "POLICY_MAX_STALE_SECONDS": "600"}),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.good = settings.load_policy()

    def expire(self, seconds: float = 61):
        self.clock.now += seconds

    def test_an_ssm_failure_serves_the_last_good_policy(self):
        self.expire()
        self.ssm.error = RuntimeError("ThrottlingException")
        with self.assertLogs(settings.logger, level="WARNING") as logs:
            self.assertIs(settings.load_policy(), self.good)
        self.assertIn("action=serving_last_good", logs.output[0])

    def test_a_bad_publish_serves_the_last_good_policy(self):
        self.expire()
        self.ssm.value = "{not json"
        with self.assertLogs(settings.logger, level="WARNING"):
            self.assertIs(settings.load_policy(), self.good)

    def test_a_failing_ssm_is_not_asked_on_every_call(self):
        self.expire()
        self.ssm.error = RuntimeError("ThrottlingException")
        with self.assertLogs(settings.logger, level="WARNING"):
            settings.load_policy()
        calls = self.ssm.calls
        self.clock.now += settings.POLICY_RETRY_SECONDS - 1
        settings.load_policy()
        self.assertEqual(self.ssm.calls, calls, "no retry inside the retry window")
        self.clock.now += 2
        with self.assertLogs(settings.logger, level="WARNING"):
            settings.load_policy()
        self.assertEqual(self.ssm.calls, calls + 1, "retries once the window passes")

    def test_recovery_replaces_the_stale_policy(self):
        self.expire()
        self.ssm.error = RuntimeError("ThrottlingException")
        with self.assertLogs(settings.logger, level="WARNING"):
            settings.load_policy()
        self.ssm.error = None
        self.ssm.value = json.dumps({"defaults": {"request": {"action": "none"}}})
        self.clock.now += settings.POLICY_RETRY_SECONDS + 1
        self.assertEqual(settings.load_policy().resolve("x", "y").request.action, "none")

    def test_too_stale_fails_closed(self):
        self.ssm.error = RuntimeError("ThrottlingException")
        self.expire(601)
        with self.assertLogs(settings.logger, level="ERROR") as logs:
            with self.assertRaises(RuntimeError):
                settings.load_policy()
        self.assertIn("action=fail_closed", logs.output[0])

    def test_nothing_cached_still_raises(self):
        settings._policy_cache = None
        settings._policy_next_read = 0.0
        self.ssm.error = RuntimeError("ThrottlingException")
        with self.assertLogs(settings.logger, level="ERROR"):
            with self.assertRaises(RuntimeError):
                settings.load_policy()

    def test_the_retry_pause_cannot_outlive_the_stale_limit(self):
        """A failure just before the limit must not schedule the next read
        past it, or the pause would serve a policy older than allowed."""
        self.ssm.error = RuntimeError("ThrottlingException")
        self.clock.now += 599
        with self.assertLogs(settings.logger, level="WARNING"):
            self.assertIs(settings.load_policy(), self.good)
        self.clock.now += 0.5
        self.assertIs(settings.load_policy(), self.good, "still inside the limit")
        self.clock.now += 1
        with self.assertLogs(settings.logger, level="ERROR"):
            with self.assertRaises(RuntimeError):
                settings.load_policy()

    def test_failing_closed_backs_off_ssm_too(self):
        """Once nothing is servable, the next calls fail closed without
        reading SSM until the retry time, rather than one read per call."""
        self.ssm.error = RuntimeError("ThrottlingException")
        self.clock.now += 601
        with self.assertLogs(settings.logger, level="ERROR"):
            with self.assertRaises(RuntimeError):
                settings.load_policy()
        reads = self.ssm.calls
        for _ in range(5):
            self.clock.now += 1
            with self.assertRaises(settings.PolicyUnavailable) as caught:
                settings.load_policy()
            self.assertIsInstance(caught.exception.__cause__, RuntimeError)
        self.assertEqual(self.ssm.calls, reads, "no SSM read inside the retry window")
        self.clock.now += settings.POLICY_RETRY_SECONDS
        self.ssm.error = None
        self.assertEqual(settings.load_policy().resolve("x", "y").request.action, "deidentify")
        self.assertEqual(self.ssm.calls, reads + 1, "recovers on the first read after the window")

    def test_a_slow_failed_read_is_judged_when_it_ends(self):
        """A read that starts inside the stale limit and fails after it must
        fail closed, and back off from the failure rather than the start."""
        self.ssm.error = RuntimeError("ReadTimeout")
        self.ssm.latency = 20
        self.clock.now += 599
        with self.assertLogs(settings.logger, level="ERROR") as logs:
            with self.assertRaises(RuntimeError):
                settings.load_policy()
        self.assertIn("stale_seconds=619", logs.output[0])
        self.assertEqual(settings._policy_next_read, self.clock.now + settings.POLICY_RETRY_SECONDS)

    def test_a_slow_failed_read_caps_the_pause_from_when_it_ends(self):
        loaded_at = self.clock.now
        self.ssm.error = RuntimeError("ReadTimeout")
        self.ssm.latency = 20
        self.clock.now += 575
        with self.assertLogs(settings.logger, level="WARNING") as logs:
            self.assertIs(settings.load_policy(), self.good)
        self.assertIn("stale_seconds=595", logs.output[0])
        self.assertEqual(settings._policy_next_read, loaded_at + 600, "next read at the stale limit, still ahead")

    def test_a_slow_successful_read_is_aged_from_when_it_ends(self):
        self.ssm.latency = 20
        self.expire()
        settings.load_policy()
        self.assertEqual(settings._policy_cache[0], self.clock.now)
        self.assertEqual(settings._policy_next_read, self.clock.now + 60)

    def test_a_cold_start_failure_backs_off_too(self):
        settings._policy_cache = None
        settings._policy_next_read = 0.0
        self.ssm.error = RuntimeError("ThrottlingException")
        with self.assertLogs(settings.logger, level="ERROR"):
            with self.assertRaises(RuntimeError):
                settings.load_policy()
        reads = self.ssm.calls
        self.clock.now += 1
        with self.assertRaises(settings.PolicyUnavailable):
            settings.load_policy()
        self.assertEqual(self.ssm.calls, reads)


class ApiKeyTestCase(SettingsTestCase):
    def test_bare_string_secret(self):
        with mock.patch.object(settings, "_secrets_client", return_value=FakeSecrets("  sky-abc123  ")):
            self.assertEqual(settings.load_api_key(), "sky-abc123", "surrounding whitespace trimmed")

    def test_json_secret_with_api_key_field(self):
        stored = json.dumps({"apiKey": "sky-abc123", "vaultId": "v1"})
        with mock.patch.object(settings, "_secrets_client", return_value=FakeSecrets(stored)):
            self.assertEqual(settings.load_api_key(), "sky-abc123")

    def test_json_secret_with_snake_case_field(self):
        stored = json.dumps({"api_key": "sky-abc123"})
        with mock.patch.object(settings, "_secrets_client", return_value=FakeSecrets(stored)):
            self.assertEqual(settings.load_api_key(), "sky-abc123")

    def test_json_object_without_a_key_field_is_an_error(self):
        stored = json.dumps({"vaultId": "v1"})
        with mock.patch.object(settings, "_secrets_client", return_value=FakeSecrets(stored)):
            with self.assertRaises(RuntimeError):
                settings.load_api_key()

    def test_json_scalar_is_treated_as_the_key(self):
        with mock.patch.object(settings, "_secrets_client", return_value=FakeSecrets('"sky-abc123"')):
            self.assertEqual(settings.load_api_key(), "sky-abc123")

    def test_key_is_cached_for_the_life_of_the_environment(self):
        fake = FakeSecrets("sky-abc123")
        with mock.patch.object(settings, "_secrets_client", return_value=fake):
            settings.load_api_key()
            settings.load_api_key()
        self.assertEqual(fake.calls, 1, "the key is long lived; fetch it once")


class ApiKeyRefreshTestCase(SettingsTestCase):
    def test_refresh_rereads_the_secret(self):
        fake = FakeSecrets("sky-old")
        with mock.patch.object(settings, "_secrets_client", return_value=fake):
            settings.load_api_key()
            fake.stored = "sky-new"
            with self.assertLogs(settings.logger, level="WARNING") as logs:
                self.assertEqual(settings.refresh_api_key(), "sky-new")
        self.assertIn("changed=True", logs.output[0])
        self.assertEqual(settings.load_api_key(), "sky-new", "the new key is cached")

    def test_refresh_is_rate_limited(self):
        """A key that is wrong rather than rotated must not turn every call
        into a Secrets Manager read."""
        fake = FakeSecrets("sky-old")
        clock = Clock()
        with mock.patch.object(settings, "_secrets_client", return_value=fake), \
                mock.patch.object(settings.time, "monotonic", clock):
            settings.load_api_key()
            with self.assertLogs(settings.logger, level="WARNING"):
                settings.refresh_api_key()
            reads = fake.calls
            clock.now += settings.API_KEY_REFRESH_INTERVAL_SECONDS - 1
            settings.refresh_api_key()
            self.assertEqual(fake.calls, reads)
            clock.now += 2
            with self.assertLogs(settings.logger, level="WARNING"):
                settings.refresh_api_key()
            self.assertEqual(fake.calls, reads + 1)


class ConcurrentRefreshTestCase(SettingsTestCase):
    """Parallel 401s during a rotation all end up with the new key."""

    def test_a_second_caller_waits_for_the_first_read(self):
        gate, entered = threading.Event(), threading.Event()

        class SlowSecrets(FakeSecrets):
            def get_secret_value(self, SecretId):  # noqa: N803 - boto3 casing
                if self.stored == "sky-new":
                    entered.set()
                    gate.wait(5)
                return super().get_secret_value(SecretId)

        fake = SlowSecrets("sky-old")
        results = {}
        with mock.patch.object(settings, "_secrets_client", return_value=fake), \
                self.assertLogs(settings.logger, level="WARNING"):
            settings.load_api_key()
            fake.stored = "sky-new"
            first = threading.Thread(target=lambda: results.update(first=settings.refresh_api_key("sky-old")))
            first.start()
            self.assertTrue(entered.wait(5), "the first refresh is reading Secrets Manager")
            second = threading.Thread(target=lambda: results.update(second=settings.refresh_api_key("sky-old")))
            second.start()
            second.join(0.2)
            self.assertTrue(second.is_alive(), "the second caller waits rather than take the old key")
            gate.set()
            first.join(5)
            second.join(5)
        self.assertEqual(results, {"first": "sky-new", "second": "sky-new"})
        self.assertEqual(fake.calls, 2, "one initial load and one refresh; the second caller reads nothing")

    def test_a_key_already_replaced_is_returned_without_a_read(self):
        fake = FakeSecrets("sky-new")
        with mock.patch.object(settings, "_secrets_client", return_value=fake):
            settings.load_api_key()
            self.assertEqual(settings.refresh_api_key("sky-old"), "sky-new")
        self.assertEqual(fake.calls, 1)


class ClientConstructionTestCase(SettingsTestCase):
    def test_build_client_wires_env_and_key(self):
        with mock.patch.object(settings, "_secrets_client", return_value=FakeSecrets("sky-abc123")):
            client = settings.build_client()
        self.assertEqual(client._vault_url, "https://test.vault.skyflowapis.com")
        self.assertEqual(client._vault_id, "vault123")
        self.assertEqual(client._api_key, "sky-abc123")
        self.assertIs(client._refresh_api_key, settings.refresh_api_key)

    def test_timeout_comes_from_the_environment(self):
        with mock.patch.object(settings, "_secrets_client", return_value=FakeSecrets("k")), \
                mock.patch.dict(os.environ, {"SKYFLOW_TIMEOUT_SECONDS": "12.5"}):
            self.assertEqual(settings.build_client()._timeout, 12.5)

    def test_timeout_defaults_to_five_seconds(self):
        with mock.patch.object(settings, "_secrets_client", return_value=FakeSecrets("k")), \
                mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SKYFLOW_TIMEOUT_SECONDS", None)
            self.assertEqual(settings.build_client()._timeout, 5.0)

    def test_boto_clients_are_not_built_at_import(self):
        """Building a client at import resolves credentials eagerly and makes
        the module unimportable without an AWS credential chain."""
        self.assertIsNone(settings._ssm, "SSM client must be lazy")
        self.assertIsNone(settings._secrets, "Secrets Manager client must be lazy")


if __name__ == "__main__":
    unittest.main(verbosity=2)
