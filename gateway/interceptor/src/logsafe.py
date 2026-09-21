"""Keep credentials out of CloudWatch, whatever the logging settings say.

Three things can put a credential in the interceptor's log group, and each has
a guard here:

1. `LOG_LEVEL=DEBUG`. The handler used to set that level on the root logger,
   which botocore inherits, and botocore at DEBUG logs every response body and
   every SigV4 signing step. The response body of `GetSecretValue` is the
   Skyflow API key. `configure_logging` applies `LOG_LEVEL` to this code and
   holds the AWS SDK loggers at INFO or above, so DEBUG here means verbose
   interceptor logs and never a printed secret.
2. `logUpstreamPayloads`. The payload snapshots carry tokens rather than
   original values, but the policy's `scope.excludeKeys` deliberately keeps
   fields such as `api_key` and `authorization` out of tokenization so a tool
   that needs them still works. Logged verbatim, those would be credentials in
   the clear. `redact_for_log` masks them by key and by shape before anything
   is serialized.
3. `passRequestHeaders`. When it is on, the gateway hands the caller's headers,
   Authorization included, to the interceptor inside the event. Nothing here
   reads them, so `scrub_event` blanks the credential-bearing ones on entry;
   a future log line that prints the event cannot print a token.
"""

from __future__ import annotations

import logging
import os
from fnmatch import fnmatchcase
from typing import Any

#: Replaces a masked value. Distinct from a Skyflow token on purpose.
REDACTED = "<redacted>"

#: Loggers that print request and response internals at DEBUG. Held at INFO or
#: above regardless of LOG_LEVEL. `urllib3` is included because it logs
#: request lines and, with the AWS SDK, can echo signed query strings.
SDK_LOGGERS = ("botocore", "boto3", "s3transfer", "urllib3")

#: Key names, case-insensitive globs, whose values are masked in any logged
#: payload or header map. Over-matching is the safe direction for a debug log.
SENSITIVE_KEY_PATTERNS = (
    "authorization",
    "proxy-authorization",
    "proxy_authorization",
    "cookie",
    "set-cookie",
    "set_cookie",
    "x-api-key",
    "x_api_key",
    "x-amz-security-token",
    "x_amz_security_token",
    "*api_key*",
    "*apikey*",
    "*api-key*",
    "*token*",
    "*secret*",
    "*password*",
    "*passwd*",
    "*credential*",
    "*private_key*",
    "*private-key*",
)

#: Value prefixes that mark a credential whatever the key is called.
CREDENTIAL_VALUE_PREFIXES = ("bearer ", "basic ", "aws4-hmac-sha256 ", "digest ")


def configure_logging(level_name: str | None = None) -> int:
    """Apply `LOG_LEVEL` to the interceptor without letting the SDKs follow.

    Returns the level applied to the root logger. An unrecognised name falls
    back to INFO rather than failing the import, because a typo in a Lambda
    environment variable should not take the gateway down.
    """
    name = (level_name or os.environ.get("LOG_LEVEL", "INFO")).strip().upper()
    level = logging.getLevelName(name)
    if not isinstance(level, int):
        level = logging.INFO

    logging.getLogger().setLevel(level)
    for sdk in SDK_LOGGERS:
        # Never below INFO: DEBUG is where botocore prints response bodies
        # (the Skyflow key, on GetSecretValue) and SigV4 Authorization headers.
        logging.getLogger(sdk).setLevel(max(level, logging.INFO))
    return level


def is_sensitive_key(key: Any) -> bool:
    name = str(key).lower()
    return any(fnmatchcase(name, pattern) for pattern in SENSITIVE_KEY_PATTERNS)


def looks_like_credential(value: Any) -> bool:
    return isinstance(value, str) and value.lower().startswith(CREDENTIAL_VALUE_PREFIXES)


def redact_for_log(node: Any) -> Any:
    """Return a copy of `node` with credential-bearing values masked.

    Masks by key (`api_key`, `authorization`, anything containing `token`,
    `secret`, `password` or `credential`) and by shape (`Bearer …`, `Basic …`,
    a SigV4 `Authorization` value) so a credential under an unexpected key is
    still caught. Only for logging: the payload itself is never changed.
    """
    if isinstance(node, dict):
        return {
            key: REDACTED if is_sensitive_key(key) else redact_for_log(value)
            for key, value in node.items()
        }
    if isinstance(node, list):
        return [redact_for_log(item) for item in node]
    if looks_like_credential(node):
        return REDACTED
    return node


def scrub_event(event: Any) -> Any:
    """Blank credential headers in a gateway interceptor event, in place.

    Covers `headers` on the request and response halves of both payload shapes
    (`mcp` and `http`). The interceptor never reads headers, and the gateway
    forwards its own copy upstream, so nothing is lost. Returns the event for
    convenience.
    """
    if not isinstance(event, dict):
        return event
    for shape in ("mcp", "http"):
        section = event.get(shape)
        if not isinstance(section, dict):
            continue
        for half in ("gatewayRequest", "gatewayResponse"):
            headers = (section.get(half) or {}).get("headers") if isinstance(section.get(half), dict) else None
            if isinstance(headers, dict):
                for key in list(headers):
                    if is_sensitive_key(key) or looks_like_credential(headers[key]):
                        headers[key] = REDACTED
    return event
