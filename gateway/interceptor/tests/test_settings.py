"""Settings: policy caching against SSM, and API key parsing from Secrets Manager.

boto3 clients are replaced with fakes; nothing reaches AWS.
"""

from __future__ import annotations

import json
import os
import sys
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

    def get_parameter(self, Name):  # noqa: N803 - boto3 casing
        self.calls += 1
        return {"Parameter": {"Value": self.value}}


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
        settings._api_key_cache = None


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
            with self.assertRaises(Exception):
                settings.load_policy()


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


class ClientConstructionTestCase(SettingsTestCase):
    def test_build_client_wires_env_and_key(self):
        with mock.patch.object(settings, "_secrets_client", return_value=FakeSecrets("sky-abc123")):
            client = settings.build_client()
        self.assertEqual(client._vault_url, "https://test.vault.skyflowapis.com")
        self.assertEqual(client._vault_id, "vault123")
        self.assertEqual(client._api_key, "sky-abc123")

    def test_boto_clients_are_not_built_at_import(self):
        """Building a client at import resolves credentials eagerly and makes
        the module unimportable without an AWS credential chain."""
        self.assertIsNone(settings._ssm, "SSM client must be lazy")
        self.assertIsNone(settings._secrets, "Secrets Manager client must be lazy")


if __name__ == "__main__":
    unittest.main(verbosity=2)
