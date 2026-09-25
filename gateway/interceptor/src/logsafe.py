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
   is serialized. It also masks values shaped like an email address, an SSN, a
   card number or a phone number, as a backstop for anything detection missed.
   That backstop cannot recognise a name or an address; what keeps those out
   is logging only the tokenized side (`Policy.should_log_upstream`).
3. `passRequestHeaders`. When it is on, the gateway hands the caller's headers,
   Authorization included, to the interceptor inside the event. Nothing here
   reads them, so `scrub_event` blanks the credential-bearing ones on entry;
   a future log line that prints the event cannot print a token.
"""

from __future__ import annotations

import logging
import os
import re
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


#: PII with a recognisable shape, masked inside any logged string. Order
#: matters: a card number would otherwise be claimed by the phone pattern.
#: Over-matching is accepted here too, so a long run of digits that is not a
#: phone number is masked all the same.
#:
#: Each pattern may only start at the beginning of a run (the lookbehinds) and
#: every repetition is bounded. Without both, a long run of letters or digits
#: in a payload is retried from every position and costs quadratic time.
EMAIL_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}"
    r"@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}\.[A-Za-z]{2,24}(?![A-Za-z0-9-])"
)
SSN_PATTERN = re.compile(r"(?<![\w-])\d{3}[- ]\d{2}[- ]\d{4}(?![\w-])")
CARD_PATTERN = re.compile(r"(?<![\w-])\d(?:[ -]?\d){12,18}(?![\w-])")
#: A candidate only: `_mask_phone` then insists on 10 to 15 digits, the range
#: E.164 allows once a country or area code is included.
PHONE_PATTERN = re.compile(r"(?<![\w+(-])\+?[\d(](?:[\d ().-]{0,30}\d)?(?![\w-])")


def _luhn_valid(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _mask_card(match: re.Match) -> str:
    digits = re.sub(r"\D", "", match.group(0))
    # Luhn keeps an order number or a timestamp from reading as a card; the
    # phone pattern after this still masks it if it is long enough.
    return "<redacted:card>" if _luhn_valid(digits) else match.group(0)


def _mask_phone(match: re.Match) -> str:
    candidate = match.group(0)
    digits = sum(char.isdigit() for char in candidate)
    return "<redacted:phone>" if 10 <= digits <= 15 else candidate


def mask_pii(text: str) -> str:
    """Mask substrings of `text` shaped like an email, SSN, card or phone number.

    A backstop, not a detector: it only knows shapes, so a name, a street
    address or a date of birth goes through untouched.
    """
    text = EMAIL_PATTERN.sub("<redacted:email>", text)
    text = SSN_PATTERN.sub("<redacted:ssn>", text)
    text = CARD_PATTERN.sub(_mask_card, text)
    return PHONE_PATTERN.sub(_mask_phone, text)


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
    """Return a copy of `node` with credential-bearing and PII-shaped values masked.

    Masks by key (`api_key`, `authorization`, anything containing `token`,
    `secret`, `password` or `credential`) and by shape (`Bearer …`, `Basic …`,
    a SigV4 `Authorization` value) so a credential under an unexpected key is
    still caught. Any other string has emails, SSNs, card numbers and phone
    numbers masked within it (`mask_pii`). Only for logging: the payload itself
    is never changed.
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
    if isinstance(node, str):
        return mask_pii(node)
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
