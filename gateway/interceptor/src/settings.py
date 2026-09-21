"""Runtime settings: policy from SSM Parameter Store, Skyflow key from Secrets Manager.

Both are cached at module scope so warm invocations avoid the round trip. The
policy cache has a TTL so a policy edit takes effect without redeploying the
function; the Skyflow API key is long-lived and cached for the life of the
execution environment.

Environment variables (set by the CDK stack):

| Variable | Description |
| --- | --- |
| `POLICY_PARAMETER_NAME` | SSM parameter holding the policy JSON |
| `SKYFLOW_SECRET_ARN` | Secrets Manager secret holding the Skyflow API key |
| `SKYFLOW_VAULT_URL` | Vault host, e.g. https://abcd.vault.skyflowapis.com |
| `SKYFLOW_VAULT_ID` | Vault ID |
| `POLICY_CACHE_TTL_SECONDS` | Policy cache lifetime in seconds, default 60 |
| `LOG_LEVEL` | Interceptor log level, default INFO. The AWS SDK loggers stay at INFO or above regardless; see `logsafe` |
"""

from __future__ import annotations

import json
import logging
import os
import time

import boto3

from policy import PolicySet
from skyflow_client import SkyflowClient

logger = logging.getLogger(__name__)

_ssm = None
_secrets = None

_policy_cache: tuple[float, PolicySet] | None = None
_api_key_cache: str | None = None


def _ssm_client():
    """Build the SSM client on first use.

    Deliberately not built at import: constructing a client resolves credentials
    eagerly, which adds to cold start and makes the module impossible to import
    without an AWS credential chain.
    """
    global _ssm
    if _ssm is None:
        _ssm = boto3.client("ssm")
    return _ssm


def _secrets_client():
    global _secrets
    if _secrets is None:
        _secrets = boto3.client("secretsmanager")
    return _secrets


def _cache_ttl() -> float:
    return float(os.environ.get("POLICY_CACHE_TTL_SECONDS", "60"))


def load_policy(force: bool = False) -> PolicySet:
    """Return the policy set, refreshing from SSM when the cache expires."""
    global _policy_cache

    now = time.monotonic()
    if not force and _policy_cache is not None:
        cached_at, cached = _policy_cache
        if now - cached_at < _cache_ttl():
            return cached

    name = os.environ["POLICY_PARAMETER_NAME"]
    raw = _ssm_client().get_parameter(Name=name)["Parameter"]["Value"]
    policy_set = PolicySet.from_json(json.loads(raw))
    _policy_cache = (now, policy_set)
    logger.info("policy_loaded parameter=%s overrides=%d", name, len(policy_set.overrides))
    return policy_set


def load_api_key() -> str:
    """Return the long-lived Skyflow API key.

    Accepts either a bare key string or a JSON object with an `apiKey` field,
    so the secret can carry vault metadata alongside the key if wanted.
    """
    global _api_key_cache

    if _api_key_cache is not None:
        return _api_key_cache

    arn = os.environ["SKYFLOW_SECRET_ARN"]
    stored = _secrets_client().get_secret_value(SecretId=arn)["SecretString"]

    try:
        parsed = json.loads(stored)
    except json.JSONDecodeError:
        _api_key_cache = stored.strip()
        return _api_key_cache

    if isinstance(parsed, dict):
        key = parsed.get("apiKey") or parsed.get("api_key")
        if not key:
            raise RuntimeError("Skyflow secret JSON contains no 'apiKey' field")
        _api_key_cache = key
    elif isinstance(parsed, str):
        # A JSON-encoded string: use the decoded value, or the key would carry
        # its surrounding quotes into the Authorization header.
        _api_key_cache = parsed.strip()
    else:
        _api_key_cache = stored.strip()

    return _api_key_cache


def build_client() -> SkyflowClient:
    return SkyflowClient(
        vault_url=os.environ["SKYFLOW_VAULT_URL"],
        vault_id=os.environ["SKYFLOW_VAULT_ID"],
        api_key=load_api_key(),
    )
