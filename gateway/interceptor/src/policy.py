"""Redaction policy model and resolution.

Ported from the Context Forge plugin's config.py, with two changes:

1. No pydantic — the Lambda ships with zero third-party dependencies, so
   plain dataclasses plus explicit validation.
2. Overrides match on `servers` as well as `tools`. A gateway fronts many
   targets, so the target name is the "server" half of the identity.

Matching is fnmatch-glob, first match wins, whole sub-blocks replace (never a
per-field merge) — same semantics as the Context Forge `tool_overrides`.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, replace
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

ACTIONS = ("deidentify", "reidentify", "none")
TOKEN_TYPES = ("counter", "vault_token")

DEFAULT_ENTITIES = [
    "name",
    "email_address",
    "phone_number",
    "ssn",
    "credit_card",
    "dob",
    "location",
]


class PolicyError(ValueError):
    """Raised when stored policy JSON is malformed or self-contradictory."""


@dataclass(frozen=True)
class DirectionAction:
    """What runs on one direction (request or response).

    - `none`       — pass through untouched.
    - `deidentify` — replace detected entities with Skyflow tokens. `token_type`
      picks the format: `counter` is per-call sequential and ephemeral (cheap,
      but ONE-WAY — the Detect API cannot resolve it later); `vault_token` is
      vault-persisted and restorable by any later re-identify call.
    - `reidentify` — swap vault tokens back to their original values.
      `token_type` is ignored.
    """

    action: str = "none"
    token_type: str = "counter"

    def __post_init__(self) -> None:
        if self.action not in ACTIONS:
            raise PolicyError(f"action must be one of {ACTIONS}, got {self.action!r}")
        if self.token_type not in TOKEN_TYPES:
            raise PolicyError(f"tokenType must be one of {TOKEN_TYPES}, got {self.token_type!r}")

    @property
    def mints_vault_tokens(self) -> bool:
        return self.action == "deidentify" and self.token_type == "vault_token"

    @classmethod
    def from_json(cls, raw: Any, where: str) -> "DirectionAction":
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise PolicyError(f"{where} must be an object, got {type(raw).__name__}")
        return cls(
            action=raw.get("action", "none"),
            token_type=raw.get("tokenType", "counter"),
        )


@dataclass(frozen=True)
class Scope:
    """Which string values are eligible for redaction."""

    min_length: int = 8
    include_keys: tuple[str, ...] = ("*",)
    exclude_keys: tuple[str, ...] = ()

    def key_in_scope(self, key: str) -> bool:
        if any(fnmatchcase(key, p) for p in self.exclude_keys):
            return False
        return any(fnmatchcase(key, p) for p in self.include_keys)

    def value_eligible(self, value: str) -> bool:
        return len(value) >= self.min_length

    @classmethod
    def from_json(cls, raw: Any, where: str) -> "Scope":
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise PolicyError(f"{where} must be an object, got {type(raw).__name__}")
        return cls(
            min_length=int(raw.get("minLength", 8)),
            include_keys=tuple(raw.get("includeKeys", ["*"])),
            exclude_keys=tuple(raw.get("excludeKeys", [])),
        )


@dataclass(frozen=True)
class Failure:
    """What to do when Skyflow itself fails.

    `fail_closed` blocks the call rather than risk forwarding un-redacted data.
    `fail_open` lets the original payload through.
    """

    on_error: str = "fail_closed"

    def __post_init__(self) -> None:
        if self.on_error not in ("fail_closed", "fail_open"):
            raise PolicyError(f"onError must be fail_closed or fail_open, got {self.on_error!r}")

    @classmethod
    def from_json(cls, raw: Any, where: str) -> "Failure":
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise PolicyError(f"{where} must be an object, got {type(raw).__name__}")
        return cls(on_error=raw.get("onError", "fail_closed"))


#: Extension -> Detect `dataFormat`. A URL whose path has no recognised
#: extension cannot be submitted, because dataFormat is how Skyflow decides
#: which processor to run.
FILE_FORMATS = frozenset({
    "mp3", "wav", "pdf", "txt", "csv", "json", "jpg", "jpeg", "tif", "tiff",
    "png", "bmp", "xls", "xlsx", "doc", "docx", "ppt", "pptx", "xml", "dcm",
    "jsonl", "zip", "gif",
})


#: Marks `[*]` in a field path — every element of a list at this position.
WILDCARD = "*"

#: A path segment is either a key name or a bracketed index/wildcard:
#: `content[*].url` -> "content", "[*]", "url".
_PATH_SEGMENT = re.compile(r"[^.\[\]]+|\[(?:\*|\d+)\]")


def parse_field_path(path: str) -> tuple:
    """Turn `content[*].url` into ("content", WILDCARD, "url").

    Paths are relative to the node being examined: the tool's arguments on a
    request, the tool's result on a response. That matches how the rest of the
    policy addresses payloads.
    """
    if not path or not path.strip():
        raise ValueError("field path must not be empty")

    segments: list = []
    position = 0
    for match in _PATH_SEGMENT.finditer(path):
        if match.start() > position and path[position:match.start()] != ".":
            raise ValueError(f"cannot parse field path {path!r}")
        position = match.end()
        token = match.group()
        if token.startswith("["):
            inner = token[1:-1]
            segments.append(WILDCARD if inner == "*" else int(inner))
        else:
            segments.append(token)
    if position != len(path) or not segments:
        raise ValueError(f"cannot parse field path {path!r}")
    return tuple(segments)


#: Anything outside printable ASCII, and the backslash. URL parsers disagree
#: about all of these (a backslash reads as a path separator to some and as
#: part of the authority to others), so a URL or pattern carrying one is
#: refused rather than interpreted.
_UNSAFE_URL_CHARS = re.compile(r"[^\x21-\x7e]|\\")

#: One DNS label of a host pattern, where `*` stands for part of a label.
_HOST_LABEL = re.compile(r"[a-z0-9*-]+")


@dataclass(frozen=True)
class UrlPattern:
    """One `files.urlPatterns` entry, parsed into the parts that are matched.

    A whole-URL glob cannot be an allowlist: `*` matches dots and slashes, so
    `https://files-*.s3.amazonaws.com/*` also matches
    `https://files-x.evil.com/.s3.amazonaws.com/a.pdf`, whose host is
    `files-x.evil.com`. Matching the host and the path separately, with a host
    `*` confined to one label, closes that.
    """

    source: str
    host: re.Pattern
    path: str

    @classmethod
    def parse(cls, pattern: Any) -> "UrlPattern":
        if not isinstance(pattern, str) or not pattern:
            raise PolicyError("files.urlPatterns entries must be non-empty strings")
        if _UNSAFE_URL_CHARS.search(pattern):
            raise PolicyError(f"files.urlPatterns entry {pattern!r} has whitespace, a backslash or non-ASCII")
        parts = urlsplit(pattern)
        if parts.scheme != "https" or not pattern.startswith("https://"):
            raise PolicyError(f"files.urlPatterns entry {pattern!r} must start with https://")
        if parts.query or parts.fragment or "?" in pattern or "#" in pattern:
            raise PolicyError(
                f"files.urlPatterns entry {pattern!r} must not have a query or fragment; "
                "they are ignored when matching, since a presigned URL's query changes every time"
            )
        if "@" in parts.netloc or ":" in parts.netloc:
            raise PolicyError(f"files.urlPatterns entry {pattern!r} must not name a user or a port")

        labels = parts.netloc.lower().split(".")
        if len(labels) < 2 or not all(_HOST_LABEL.fullmatch(label) for label in labels):
            raise PolicyError(f"files.urlPatterns entry {pattern!r} has an invalid host")
        if any("*" in label for label in labels[-2:]):
            # `*.com` would allow every host under a TLD, and `*` alone every
            # host at all. The domain that owns the files has to be named.
            raise PolicyError(
                f"files.urlPatterns entry {pattern!r} must name its last two host labels "
                "without a wildcard, for example *.s3.amazonaws.com"
            )
        host = re.compile(
            r"\.".join(re.escape(label).replace(r"\*", "[a-z0-9-]*") for label in labels)
        )
        return cls(source=pattern, host=host, path=parts.path or "/*")

    def matches(self, host: str, path: str) -> bool:
        return bool(self.host.fullmatch(host)) and fnmatchcase(path, self.path)


def split_file_url(value: Any) -> tuple[str, str] | None:
    """`(host, path)` of a URL that is safe to compare against a pattern, else None.

    Only `https`, on the default port, with no user info and nothing a parser
    could read two ways. Anything else is not a file reference this
    interceptor will fetch or hand to Skyflow, whatever the patterns say.
    """
    if not isinstance(value, str) or _UNSAFE_URL_CHARS.search(value):
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme != "https" or not value[:8].lower() == "https://":
        return None
    if not parts.netloc or "@" in parts.netloc or port not in (None, 443):
        return None
    host = parts.hostname or ""
    if not host or host.endswith("."):
        return None
    return host, parts.path or "/"


def _destinations(raw: Any, where: str) -> tuple[tuple[str, str], ...]:
    """Parse the entity-to-`table.column` map into a stable ordered tuple."""
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        raise PolicyError(f"{where}.destinations must be an object")
    pairs = []
    for entity, value in raw.items():
        if not isinstance(value, str) or not value.strip():
            raise PolicyError(f"{where}.destinations[{entity!r}] must be a non-empty string")
        pairs.append((str(entity).lower(), value.strip()))
    return tuple(pairs)


@dataclass(frozen=True)
class FileRule:
    """What to do with file URLs a tool hands back.

    Tools that deal in files return signed URLs, not bytes, so string redaction
    never sees the contents. This rule instead swaps the URL for one pointing at
    a de-identified copy, which is a one-way transform: the agent is not meant
    to see the original at all.

    `directions` exists because which side carries the file depends on the tool
    — a download returns one in the response, an upload sends one in the
    request.
    """

    action: str = "none"
    directions: tuple[str, ...] = ("response",)
    #: The allowlist of places a file may come from, as `https://host/path`
    #: globs (see `UrlPattern`). Required whenever the rule is active: every
    #: URL is checked against it before the interceptor fetches it or hands it
    #: to Skyflow, however it was found. When `fields` is absent the patterns
    #: also find the references, so an arbitrary link in prose is left alone.
    url_patterns: tuple[str, ...] = ()
    #: Where the file reference lives, relative to the tool's arguments on a
    #: request or its result on a response — for example `url` or
    #: `content[*].url`. When set, only these locations are examined, and a
    #: URL there that no pattern allows fails the call. Matches found elsewhere
    #: are only warned about.
    fields: tuple[str, ...] = ()
    #: Cap on files processed per call. Each one is a separate Skyflow run, and
    #: they are serialised inside a synchronous interceptor.
    max_files: int = 1
    #: Inline Detect configuration, forwarded to Skyflow as given. Empty means
    #: build a default from `entities`.
    configuration: dict | None = None
    #: Refuse a document larger than this many bytes. Zero means no limit.
    #: The right value depends on the throughput of the vault being called, so
    #: this is a per-deployment setting rather than a fixed ceiling. A document
    #: that cannot finish spends the whole timeout inside a synchronous
    #: interceptor and then fails anyway.
    max_file_bytes: int = 0
    #: Where each entity's original value is stored when `token_type` resolves
    #: to `vault_token`. Keys are entity names and values are `table.column`
    #: strings. The key `default` supplies a template for any entity not named,
    #: and `{entity}` inside a value is replaced with the entity name. Skyflow
    #: rejects a vault-token file run outright unless every entity has one.
    destinations: tuple[tuple[str, str], ...] = ()
    #: Which kind of token replaces a detected entity inside the file.
    #: `vault_token` leaves the original recoverable out of band by someone with
    #: vault permissions and `counter` does not. Empty means inherit from the
    #: string rule for the same direction, which is how this behaved before the
    #: field existed. Naming it here is clearer because a file rule paired with
    #: `action: none` on the string rule would otherwise silently inherit the
    #: default of `counter`.
    token_type: str = ""
    #: `url_patterns`, parsed. Built in `__post_init__`, not passed in.
    compiled_patterns: tuple[UrlPattern, ...] = field(default=(), init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.action not in ("deidentify", "none"):
            raise PolicyError(
                f"files.action must be deidentify or none, got {self.action!r}"
            )
        for direction in self.directions:
            if direction not in ("request", "response"):
                raise PolicyError(
                    f"files.directions must be request or response, got {direction!r}"
                )
        if self.max_files < 1:
            raise PolicyError(f"files.maxFiles must be at least 1, got {self.max_files}")
        if self.max_file_bytes < 0:
            raise PolicyError(
                f"files.maxFileBytes cannot be negative, got {self.max_file_bytes}"
            )
        if self.token_type and self.token_type not in TOKEN_TYPES:
            raise PolicyError(
                f"files.tokenType must be one of {TOKEN_TYPES}, got {self.token_type!r}"
            )
        for entity, value in self.destinations:
            # Checked here rather than at first use because a malformed
            # destination fails the run rather than the request, which surfaces
            # as a fail-closed error hours later.
            probe = value.replace("{entity}", "x")
            table, _, column = probe.partition(".")
            if not table or not column or "." in column:
                raise PolicyError(
                    f"files.destinations[{entity!r}] must be 'table.column', got {value!r}"
                )
        for path in self.fields:
            # Parsed here rather than at first use: a typo should fail the
            # policy that carries it, not a customer's call hours later.
            try:
                parse_field_path(path)
            except ValueError as exc:
                raise PolicyError(f"files.fields: {exc}") from exc
        if self.action == "deidentify" and not self.url_patterns:
            # The patterns are the only thing standing between a tool's
            # response and a request the interceptor makes from inside AWS.
            # Named fields say where to look, not what is safe to fetch.
            raise PolicyError(
                "files.urlPatterns is required when files.action is deidentify: "
                "it is the allowlist of hosts a file may be fetched from"
            )
        object.__setattr__(
            self, "compiled_patterns", tuple(UrlPattern.parse(p) for p in self.url_patterns)
        )

    @property
    def is_active(self) -> bool:
        return self.action == "deidentify"

    @property
    def scans(self) -> bool:
        """Whether references are found by scanning rather than by named field."""
        return not self.fields

    def applies_to(self, direction: str) -> bool:
        return self.is_active and direction in self.directions

    def token_type_for(self, fallback: str) -> str:
        """The token type to request, falling back to the string rule's."""
        return self.token_type or fallback

    def destination_for(self, entity: str) -> str | None:
        """Where this entity's original value is stored, or None if unmapped."""
        name = entity.lower()
        mapping = dict(self.destinations)
        value = mapping.get(name)
        if value is None and name != "all":
            # The `default` template substitutes the entity name into a column,
            # which cannot work for ALL because there is no `all` column. ALL
            # needs an explicit entry or nothing.
            value = mapping.get("default")
        if value is None:
            return None
        return value.replace("{entity}", name)

    def matches_url(self, value: str) -> bool:
        """Whether `value` is a safe `https` URL that a pattern allows."""
        split = split_file_url(value)
        if split is None:
            return False
        host, path = split
        return any(pattern.matches(host, path) for pattern in self.compiled_patterns)

    @classmethod
    def from_json(cls, raw: Any, where: str) -> "FileRule":
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise PolicyError(f"{where} must be an object, got {type(raw).__name__}")
        configuration = raw.get("configuration")
        if configuration is not None and not isinstance(configuration, dict):
            raise PolicyError(f"{where}.configuration must be an object")
        return cls(
            action=raw.get("action", "none"),
            directions=tuple(raw.get("directions", ["response"])),
            url_patterns=tuple(raw.get("urlPatterns", [])),
            fields=tuple(raw.get("fields", [])),
            max_files=int(raw.get("maxFiles", 1)),
            configuration=configuration,
            token_type=raw.get("tokenType", ""),
            max_file_bytes=int(raw.get("maxFileBytes", 0)),
            destinations=_destinations(raw.get("destinations"), where),
        )


def _bool_field(raw: dict, key: str, where: str) -> bool | None:
    """Read an optional boolean, rejecting anything truthy-but-not-a-bool.

    A policy that says "true" as a string would otherwise silently enable
    payload logging.
    """
    if key not in raw:
        return None
    value = raw[key]
    if not isinstance(value, bool):
        raise PolicyError(f"{where}.{key} must be true or false, got {type(value).__name__}")
    return value


@dataclass(frozen=True)
class Policy:
    """Effective settings for one tool call."""

    request: DirectionAction = field(default_factory=DirectionAction)
    response: DirectionAction = field(default_factory=DirectionAction)
    entities: tuple[str, ...] = tuple(DEFAULT_ENTITIES)
    scope: Scope = field(default_factory=Scope)
    failure: Failure = field(default_factory=Failure)
    files: FileRule = field(default_factory=FileRule)
    #: Log the upstream-facing form of each payload: the request after
    #: de-identification and the response before re-identification. Those are
    #: the two snapshots that carry tokens rather than original values. Off by
    #: default; see `should_log_upstream` for what it does not promise.
    log_upstream_payloads: bool = False

    @property
    def is_noop(self) -> bool:
        return self.request.action == "none" and self.response.action == "none"

    def should_log_upstream(self, direction: str) -> bool:
        """Whether the upstream-facing payload for this direction may be logged.

        Only when the upstream side is the tokenized side, which depends on the
        direction as well as the action:

        - request + `deidentify`: the payload sent upstream carries tokens.
        - response + `reidentify`: the payload the upstream returned carries
          tokens.

        Every other combination puts original values on the upstream side. A
        response with `deidentify` is the upstream returning real data for the
        interceptor to redact; a request with `reidentify` is tokens being
        restored before they go upstream; `none` transforms nothing. Logging
        any of those would write user data to CloudWatch.

        The action is read from the policy rather than passed in, so a caller
        cannot pair a direction with the wrong one.

        Even when it returns True this is a debugging aid, not a guarantee: the
        payload is only as redacted as detection was complete, and anything
        Skyflow did not recognize is still there in the clear.
        """
        if not self.log_upstream_payloads:
            return False
        if direction == "request":
            return self.request.action == "deidentify"
        if direction == "response":
            return self.response.action == "reidentify"
        raise ValueError(f"unknown direction {direction!r}")


@dataclass(frozen=True)
class Override:
    """One conditional rule. Both globs must match if both are present."""

    servers: tuple[str, ...] = ("*",)
    tools: tuple[str, ...] = ("*",)
    request: DirectionAction | None = None
    response: DirectionAction | None = None
    entities: tuple[str, ...] | None = None
    scope: Scope | None = None
    failure: Failure | None = None
    files: FileRule | None = None
    log_upstream_payloads: bool | None = None

    def matches(self, server: str, tool: str) -> bool:
        server_ok = any(fnmatchcase(server, p) for p in self.servers)
        tool_ok = any(fnmatchcase(tool, p) for p in self.tools)
        return server_ok and tool_ok

    @classmethod
    def from_json(cls, raw: Any, index: int) -> "Override":
        where = f"overrides[{index}]"
        if not isinstance(raw, dict):
            raise PolicyError(f"{where} must be an object")
        entities = raw.get("entities")
        return cls(
            servers=tuple(raw.get("servers", ["*"])),
            tools=tuple(raw.get("tools", ["*"])),
            request=DirectionAction.from_json(raw["request"], f"{where}.request") if "request" in raw else None,
            response=DirectionAction.from_json(raw["response"], f"{where}.response") if "response" in raw else None,
            entities=tuple(entities) if entities is not None else None,
            scope=Scope.from_json(raw["scope"], f"{where}.scope") if "scope" in raw else None,
            failure=Failure.from_json(raw["failure"], f"{where}.failure") if "failure" in raw else None,
            files=FileRule.from_json(raw["files"], f"{where}.files") if "files" in raw else None,
            log_upstream_payloads=_bool_field(raw, "logUpstreamPayloads", where),
        )


@dataclass(frozen=True)
class PolicySet:
    """Top-level stored config: defaults plus ordered conditional overrides."""

    defaults: Policy = field(default_factory=Policy)
    overrides: tuple[Override, ...] = ()
    tool_name_separator: str = "___"

    def resolve(self, server: str, tool: str) -> Policy:
        """Return effective policy for a tool, applying the first matching override."""
        for ov in self.overrides:
            if not ov.matches(server, tool):
                continue
            updates: dict[str, Any] = {}
            if ov.request is not None:
                updates["request"] = ov.request
            if ov.response is not None:
                updates["response"] = ov.response
            if ov.entities is not None:
                updates["entities"] = ov.entities
            if ov.scope is not None:
                updates["scope"] = ov.scope
            if ov.failure is not None:
                updates["failure"] = ov.failure
            if ov.files is not None:
                updates["files"] = ov.files
            if ov.log_upstream_payloads is not None:
                updates["log_upstream_payloads"] = ov.log_upstream_payloads
            return replace(self.defaults, **updates) if updates else self.defaults
        return self.defaults

    def split_tool_name(self, qualified: str) -> tuple[str, str]:
        """Split a gateway tool name into (server, tool).

        Gateway namespaces tools by target. The separator is configurable
        because the exact delimiter should be confirmed against a live gateway
        rather than assumed. An unqualified name yields server "" so that
        `servers: ["*"]` still matches it.
        """
        sep = self.tool_name_separator
        if sep and sep in qualified:
            server, _, tool = qualified.partition(sep)
            return server, tool
        return "", qualified

    @classmethod
    def from_json(cls, raw: Any) -> "PolicySet":
        if not isinstance(raw, dict):
            raise PolicyError("policy document must be a JSON object")

        defaults_raw = raw.get("defaults") or {}
        if not isinstance(defaults_raw, dict):
            raise PolicyError("defaults must be an object")

        entities = defaults_raw.get("entities", DEFAULT_ENTITIES)
        defaults = Policy(
            request=DirectionAction.from_json(defaults_raw.get("request"), "defaults.request"),
            response=DirectionAction.from_json(defaults_raw.get("response"), "defaults.response"),
            entities=tuple(entities),
            scope=Scope.from_json(defaults_raw.get("scope"), "defaults.scope"),
            failure=Failure.from_json(defaults_raw.get("failure"), "defaults.failure"),
            files=FileRule.from_json(defaults_raw.get("files"), "defaults.files"),
            log_upstream_payloads=bool(_bool_field(defaults_raw, "logUpstreamPayloads", "defaults")),
        )

        overrides_raw = raw.get("overrides", [])
        if not isinstance(overrides_raw, list):
            raise PolicyError("overrides must be an array")
        overrides = tuple(Override.from_json(o, i) for i, o in enumerate(overrides_raw))

        policy_set = cls(
            defaults=defaults,
            overrides=overrides,
            tool_name_separator=raw.get("toolNameSeparator", "___"),
        )
        policy_set.validate()
        return policy_set

    def validate(self) -> None:
        """Reject provably-broken configs; warn on suspicious ones.

        Re-identify only resolves vault tokens. Counter tokens are one-way, so a
        policy that mints counter tokens in one direction and re-identifies in
        the other can never round-trip — that is a hard error.

        Re-identifying when nothing anywhere mints vault tokens is legal (the
        tokens may come from another tool's policy) but is usually a mistake, so
        it warns rather than fails.
        """
        resolved = [self.defaults] + [self.resolve_override(o) for o in self.overrides]

        for i, pol in enumerate(resolved):
            where = "defaults" if i == 0 else f"overrides[{i - 1}]"
            for this, other, name in (
                (pol.response, pol.request, "response"),
                (pol.request, pol.response, "request"),
            ):
                if this.action == "reidentify" and other.action == "deidentify" and not other.mints_vault_tokens:
                    raise PolicyError(
                        f"{where}: {name} re-identifies but its partner direction mints "
                        f"'counter' tokens, which are one-way. Set tokenType to 'vault_token'."
                    )

        for i, pol in enumerate(resolved):
            where = "defaults" if i == 0 else f"overrides[{i - 1}]"
            rule = pol.files
            if not rule.is_active:
                continue
            for direction in rule.directions:
                token_type = rule.token_type_for(getattr(pol, direction).token_type)
                if token_type != "vault_token":
                    continue
                # An empty entity list means ALL, which no template can spell.
                for entity in pol.entities or ("ALL",):
                    if rule.destination_for(entity) is None:
                        raise PolicyError(
                            f"{where}: files.tokenType is 'vault_token' so entity "
                            f"{entity!r} needs an entry in files.destinations. Add it "
                            f"or a 'default' template such as 'table1.{{entity}}_entity'."
                        )

        mints_anywhere = any(
            pol.request.mints_vault_tokens or pol.response.mints_vault_tokens for pol in resolved
        )
        reidentifies_anywhere = any(
            pol.request.action == "reidentify" or pol.response.action == "reidentify" for pol in resolved
        )
        if reidentifies_anywhere and not mints_anywhere:
            logger.warning(
                "policy re-identifies but no rule mints vault tokens; re-identify will be a no-op "
                "unless tokens originate from another gateway's policy"
            )

    def resolve_override(self, ov: Override) -> Policy:
        """Materialize an override against the defaults, for validation."""
        updates: dict[str, Any] = {}
        if ov.request is not None:
            updates["request"] = ov.request
        if ov.response is not None:
            updates["response"] = ov.response
        if ov.entities is not None:
            updates["entities"] = ov.entities
        if ov.scope is not None:
            updates["scope"] = ov.scope
        if ov.failure is not None:
            updates["failure"] = ov.failure
        if ov.files is not None:
            updates["files"] = ov.files
        if ov.log_upstream_payloads is not None:
            updates["log_upstream_payloads"] = ov.log_upstream_payloads
        return replace(self.defaults, **updates) if updates else self.defaults
