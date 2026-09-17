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
    #: Globs matched against the whole URL. A value only counts as a file
    #: reference if it matches, so an arbitrary link in prose is left alone.
    url_patterns: tuple[str, ...] = ()
    #: Where the file reference lives, relative to the tool's arguments on a
    #: request or its result on a response — for example `url` or
    #: `content[*].url`. When set, only these locations are examined and
    #: `url_patterns` is no longer needed to find anything; it is then used only
    #: to warn about references found elsewhere.
    fields: tuple[str, ...] = ()
    #: Cap on files processed per call. Each one is a separate Skyflow run, and
    #: they are serialised inside a synchronous interceptor.
    max_files: int = 1
    #: Inline Detect configuration, forwarded to Skyflow as given. Empty means
    #: build a default from `entities`.
    configuration: dict | None = None
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
        if self.action == "deidentify" and not (self.fields or self.url_patterns):
            # With neither, there is nothing to identify a file reference by:
            # every string would be a candidate, which would either submit
            # nonsense to Skyflow or silently do nothing.
            raise PolicyError(
                "files needs fields or urlPatterns when files.action is deidentify"
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
        return any(fnmatchcase(value, pattern) for pattern in self.url_patterns)

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

    def should_log_upstream(self, action: str) -> bool:
        """Whether the upstream-facing payload for this direction may be logged.

        Only when something was actually de-identified. With `action: none`
        nothing is tokenized, so the "upstream" payload is the original one and
        logging it would write user data to CloudWatch.

        Even when it returns True this is a debugging aid, not a guarantee: the
        payload is only as redacted as detection was complete, and anything
        Skyflow did not recognize is still there in the clear.
        """
        return self.log_upstream_payloads and action in ("deidentify", "reidentify")


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
