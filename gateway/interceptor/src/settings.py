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
| `ALLOW_UPSTREAM_PAYLOAD_LOGGING` | `true` to let the policy's `logUpstreamPayloads` take effect. Unset, the flag is ignored |
| `POLICY_MAX_STALE_SECONDS` | How long the last good policy keeps serving while SSM cannot be read, default 3600 |
| `SKYFLOW_TIMEOUT_SECONDS` | Per-request timeout for Skyflow calls, default 5 |
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

#: `(checked_at, loaded_at, policy)`. `checked_at` is when SSM was last asked
#: and `loaded_at` when it last answered with a valid policy. They differ only
#: while refreshes are failing and the last good policy is being served.
_policy_cache: tuple[float, float, PolicySet] | None = None
_api_key_cache: str | None = None
#: Monotonic time of the last forced key refresh, so a key Skyflow keeps
#: rejecting cannot turn every call into a Secrets Manager read.
_api_key_refreshed_at: float | None = None

#: After a failed refresh, wait this long before asking SSM again rather than
#: retrying on every call, which would add to whatever is throttling it.
POLICY_RETRY_SECONDS = 10.0
#: Minimum gap between forced API key refreshes.
API_KEY_REFRESH_INTERVAL_SECONDS = 30.0


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


def _max_stale() -> float:
    return float(os.environ.get("POLICY_MAX_STALE_SECONDS", "3600"))


def load_policy(force: bool = False) -> PolicySet:
    """Return the policy set, refreshing from SSM when the cache expires.

    A refresh that fails, whether SSM is throttling or someone published a
    policy that does not parse, keeps serving the last good policy rather
    than blocking every call. That holds for `POLICY_MAX_STALE_SECONDS`; after
    that the failure is raised and the handler fails closed. With nothing
    cached at all there is no informed decision to fall back on, so the first
    load always raises.
    """
    global _policy_cache

    now = time.monotonic()
    if not force and _policy_cache is not None:
        checked_at, _, cached = _policy_cache
        if now - checked_at < _cache_ttl():
            return cached

    name = os.environ["POLICY_PARAMETER_NAME"]
    try:
        raw = _ssm_client().get_parameter(Name=name)["Parameter"]["Value"]
        policy_set = PolicySet.from_json(json.loads(raw))
    except Exception as exc:
        if _policy_cache is None:
            raise
        _, loaded_at, cached = _policy_cache
        age = now - loaded_at
        if age > _max_stale():
            logger.error(
                "policy_refresh_failed parameter=%s stale_seconds=%d action=fail_closed err=%s",
                name, age, type(exc).__name__,
            )
            raise
        # Ask again after a short pause, not on every call.
        _policy_cache = (now - _cache_ttl() + POLICY_RETRY_SECONDS, loaded_at, cached)
        logger.warning(
            "policy_refresh_failed parameter=%s stale_seconds=%d action=serving_last_good err=%s",
            name, age, type(exc).__name__,
        )
        return cached

    _policy_cache = (now, now, policy_set)
    logger.info("policy_loaded parameter=%s overrides=%d", name, len(policy_set.overrides))
    return policy_set


def load_api_key(force: bool = False) -> str:
    """Return the long-lived Skyflow API key.

    Accepts either a bare key string or a JSON object with an `apiKey` field,
    so the secret can carry vault metadata alongside the key if wanted.

    `force` re-reads Secrets Manager, which is how a rotated key reaches a
    warm execution environment: the client calls it when Skyflow answers 401.
    """
    global _api_key_cache

    if _api_key_cache is not None and not force:
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


def upstream_payload_logging_allowed() -> bool:
    """Whether the policy's `logUpstreamPayloads` may take effect at all.

    The policy lives in SSM and changes without a deploy, so on its own the
    flag lets anyone who can write one parameter start copying payloads into
    CloudWatch. This env var is set by the stack, so turning payload logging on
    takes a deploy as well as a policy edit. Read on every call so a test, or a
    console edit to the function, applies at once.
    """
    return os.environ.get("ALLOW_UPSTREAM_PAYLOAD_LOGGING", "").strip().lower() == "true"


def refresh_api_key() -> str:
    """Re-read the API key after Skyflow rejected the cached one.

    Rate-limited: a key that is wrong, rather than rotated, would otherwise
    turn every call into a Secrets Manager read. Inside the interval the
    cached key comes back unchanged and the client gives up.
    """
    global _api_key_refreshed_at

    now = time.monotonic()
    if _api_key_refreshed_at is not None and now - _api_key_refreshed_at < API_KEY_REFRESH_INTERVAL_SECONDS:
        return load_api_key()
    _api_key_refreshed_at = now
    previous = _api_key_cache
    key = load_api_key(force=True)
    logger.warning("skyflow_api_key_refreshed changed=%s", key != previous)
    return key


def _timeout_seconds() -> float:
    return float(os.environ.get("SKYFLOW_TIMEOUT_SECONDS", "5"))


def build_client() -> SkyflowClient:
    return SkyflowClient(
        vault_url=os.environ["SKYFLOW_VAULT_URL"],
        vault_id=os.environ["SKYFLOW_VAULT_ID"],
        api_key=load_api_key(),
        timeout_seconds=_timeout_seconds(),
        refresh_api_key=refresh_api_key,
    )
