"""Per-request records that carry a model call's decision from request to response.

An HTTP response event carries no request, and the model name in an answer
does not match the one in the request: a call to an inference-profile ARN came
back as `claude-sonnet-5`. The gateway does give both invocations of one call
the same `REQUEST_ID` in the Lambda client context. So the request side writes
what it decided under that id and the response side reads it back.

A record holds no user data. It names the rule's response settings and lists
the tokens the request minted, which are stand-ins rather than values. Items
expire through DynamoDB's time to live.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

#: How long a record outlives its request. Generous: a model call that runs
#: longer than this has its answer blocked rather than handled with no rule.
TTL_SECONDS = 900


@dataclass(frozen=True)
class CallRecord:
    """What the request side decided for one model call."""

    kind: str
    response_action: str = "none"
    response_parts: tuple[str, ...] = ()
    response_only: str = "minted_for_request"
    on_error: str = "fail_closed"
    #: Tokens the request side minted, for `minted_for_request`.
    tokens: frozenset[str] = field(default_factory=frozenset)

    def to_json(self) -> str:
        return json.dumps({
            "kind": self.kind,
            "responseAction": self.response_action,
            "responseParts": list(self.response_parts),
            "responseOnly": self.response_only,
            "onError": self.on_error,
            "tokens": sorted(self.tokens),
        })

    @classmethod
    def from_json(cls, raw: str) -> "CallRecord":
        data = json.loads(raw)
        return cls(
            kind=data["kind"],
            response_action=data.get("responseAction", "none"),
            response_parts=tuple(data.get("responseParts", ())),
            response_only=data.get("responseOnly", "minted_for_request"),
            on_error=data.get("onError", "fail_closed"),
            tokens=frozenset(data.get("tokens", ())),
        )


class RecordStore:
    """A DynamoDB table keyed by `requestId` with `expiresAt` as its TTL attribute."""

    def __init__(self, table_name: str, client: Any) -> None:
        self._table = table_name
        self._client = client

    def put(self, request_id: str, record: CallRecord) -> None:
        self._client.put_item(
            TableName=self._table,
            Item={
                "requestId": {"S": request_id},
                "record": {"S": record.to_json()},
                "expiresAt": {"N": str(int(time.time()) + TTL_SECONDS)},
            },
        )

    def get(self, request_id: str) -> CallRecord | None:
        item = self._client.get_item(
            TableName=self._table,
            Key={"requestId": {"S": request_id}},
            ConsistentRead=True,
        ).get("Item")
        if not item:
            return None
        expires = int(item.get("expiresAt", {}).get("N", "0"))
        if expires and expires < time.time():
            # TTL deletion runs in the background and can lag by hours.
            return None
        return CallRecord.from_json(item["record"]["S"])


def request_id(context) -> str | None:
    """The gateway's id for this call, from the Lambda client context."""
    custom = getattr(getattr(context, "client_context", None), "custom", None) or {}
    value = custom.get("REQUEST_ID")
    return str(value) if value else None
