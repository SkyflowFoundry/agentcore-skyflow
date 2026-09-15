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


@dataclass(frozen=True)
class Policy:
    """Effective settings for one tool call."""

    request: DirectionAction = field(default_factory=DirectionAction)
    response: DirectionAction = field(default_factory=DirectionAction)
    entities: tuple[str, ...] = tuple(DEFAULT_ENTITIES)
    scope: Scope = field(default_factory=Scope)
    failure: Failure = field(default_factory=Failure)

    @property
    def is_noop(self) -> bool:
        return self.request.action == "none" and self.response.action == "none"


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
        return replace(self.defaults, **updates) if updates else self.defaults
