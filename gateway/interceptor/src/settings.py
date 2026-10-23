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
import threading
import time

import boto3

from policy import PolicySet
from skyflow_client import SkyflowClient

logger = logging.getLogger(__name__)

_ssm = None
_secrets = None

#: `(loaded_at, policy)`: the last policy SSM answered with, and when.
_policy_cache: tuple[float, PolicySet] | None = None
#: Monotonic time before which SSM is not asked again. Kept apart from the
#: cache so a failing SSM is backed off whether or not a usable policy is
#: left to serve meanwhile.
_policy_next_read: float = 0.0
#: The last refresh failure, chained onto the error raised while backing off.
_policy_failure: Exception | None = None
_api_key_cache: str | None = None
#: Monotonic time of the last forced key refresh, so a key Skyflow keeps
#: rejecting cannot turn every call into a Secrets Manager read.
_api_key_refreshed_at: float | None = None
#: Serialises refreshes. String fields are transformed in parallel, so during
#: a rotation several calls see a 401 at once; the ones that arrive while the
#: first is still reading Secrets Manager must wait for its answer rather
#: than take the old key from the cache.
_api_key_lock = threading.Lock()

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


class PolicyUnavailable(RuntimeError):
    """No usable policy, and SSM is not asked again until the retry time."""


def _usable_policy(now: float) -> PolicySet | None:
    """The cached policy while it may still be served, else None."""
    if _policy_cache is None:
        return None
    loaded_at, policy = _policy_cache
    # Within the TTL a policy is current; beyond it, it is stale but still
    # served until POLICY_MAX_STALE_SECONDS while refreshes keep failing.
    if now - loaded_at <= max(_cache_ttl(), _max_stale()):
        return policy
    return None


def load_policy(force: bool = False) -> PolicySet:
    """Return the policy set, refreshing from SSM when the cache expires.

    A refresh that fails, whether SSM is throttling or someone published a
    policy that does not parse, keeps serving the last good policy rather
    than blocking every call. That holds until the policy is
    `POLICY_MAX_STALE_SECONDS` old, measured from when it was loaded; after
    that the interceptor fails closed. A cold Lambda with no policy at all
    always fails closed.

    Either way, a failed read is not repeated for `POLICY_RETRY_SECONDS`, so
    a throttled SSM is not asked again on every call. While failing closed in
    that window the error is raised without an SSM read.
    """
    global _policy_cache, _policy_next_read, _policy_failure

    now = time.monotonic()
    if not force and now < _policy_next_read:
        policy = _usable_policy(now)
        if policy is not None:
            return policy
        raise PolicyUnavailable(
            f"policy unavailable; SSM is read again in {_policy_next_read - now:.0f}s"
        ) from _policy_failure

    name = os.environ["POLICY_PARAMETER_NAME"]
    try:
        raw = _ssm_client().get_parameter(Name=name)["Parameter"]["Value"]
        policy_set = PolicySet.from_json(json.loads(raw))
    except Exception as exc:
        _policy_failure = exc
        policy = _usable_policy(now)
        if policy is None:
            _policy_next_read = now + POLICY_RETRY_SECONDS
            stale = f"stale_seconds={now - _policy_cache[0]:.0f}" if _policy_cache else "cached=none"
            logger.error(
                "policy_refresh_failed parameter=%s %s action=fail_closed err=%s",
                name, stale, type(exc).__name__,
            )
            raise
        loaded_at = _policy_cache[0]
        # Ask again after a short pause, but no later than the moment the
        # policy stops being servable, so the pause cannot stretch its life.
        _policy_next_read = min(now + POLICY_RETRY_SECONDS, loaded_at + max(_cache_ttl(), _max_stale()))
        logger.warning(
            "policy_refresh_failed parameter=%s stale_seconds=%.0f action=serving_last_good err=%s",
            name, now - loaded_at, type(exc).__name__,
        )
        return policy

    _policy_cache = (now, policy_set)
    _policy_next_read = now + _cache_ttl()
    _policy_failure = None
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


def refresh_api_key(rejected_key: str | None = None) -> str:
    """Re-read the API key after Skyflow rejected `rejected_key`.

    If another call has already replaced the rejected key, that replacement
    is returned without reading Secrets Manager again. Otherwise the read is
    rate-limited: a key that is wrong, rather than rotated, would turn every
    call into a Secrets Manager read, so inside the interval the cached key
    comes back unchanged and the client gives up.
    """
    global _api_key_refreshed_at

    with _api_key_lock:
        if rejected_key is not None and _api_key_cache is not None and _api_key_cache != rejected_key:
            return _api_key_cache
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
