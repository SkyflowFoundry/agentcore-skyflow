#!/usr/bin/env python3
"""Switch the live policy between the states the recorded demo needs.

Each state is derived from the shipped gateway/interceptor/config/policy.json
when it is run, so there is no second policy file to drift out of date. Every
state is validated with the Lambda's own parser before it is published, and
`reset` puts the shipped policy back.

    python3 scripts/demo_policy.py show-upstream-search --region us-east-1
    python3 scripts/demo_policy.py one-way-documents --region us-east-1
    python3 scripts/demo_policy.py reset --region us-east-1
    python3 scripts/demo_policy.py one-way-documents --dry-run   # validate only

States:

- `show-upstream-search` turns on `logUpstreamPayloads` for `web_search_exa`
  only, so the tokenized query the search provider received appears in the
  interceptor's log. It has no effect unless the interceptor stack was
  deployed with `-c allowUpstreamPayloadLogging=true`.
- `one-way-documents` switches the S3 document rule to one-way counter
  tokens, so `[NAME_AJbrIud]` becomes `[NAME_1]` about a minute later.
- `reset` publishes the shipped policy unchanged.

The interceptor picks a change up within its cache TTL, sixty seconds by
default.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import put_policy  # noqa: E402


def _override(document: dict, server: str, tool: str) -> dict:
    for override in document.get("overrides", []):
        if server in override.get("servers", []) and tool in override.get("tools", []):
            return override
    sys.exit(f"The shipped policy has no override naming {server}___{tool}; this script needs one.")


def show_upstream_search(document: dict) -> list[str]:
    _override(document, "exa", "web_search_exa")["logUpstreamPayloads"] = True
    return ["exa___web_search_exa: logUpstreamPayloads -> true"]


def one_way_documents(document: dict) -> list[str]:
    rule = _override(document, "s3", "get_document")["files"]
    rule["tokenType"] = "counter"
    # Counter tokens store nothing, so they take no destination.
    rule.pop("destinations", None)
    return ["s3___get_document: files.tokenType -> counter"]


def reset(document: dict) -> list[str]:
    return ["shipped policy, unchanged"]


STATES = {
    "show-upstream-search": show_upstream_search,
    "one-way-documents": one_way_documents,
    "reset": reset,
}


def build(state: str) -> tuple[dict, list[str]]:
    """The policy for `state`, and a line per change from the shipped one."""
    shipped = json.loads(put_policy.POLICY_FILE.read_text())
    document = copy.deepcopy(shipped)
    changes = STATES[state](document)
    return document, changes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("state", choices=sorted(STATES))
    parser.add_argument("--parameter-name", default=put_policy.DEFAULT_PARAMETER)
    parser.add_argument("--region", default=None)
    parser.add_argument("--tier", choices=["standard", "advanced"], default="standard")
    parser.add_argument("--dry-run", action="store_true", help="Validate without writing to SSM.")
    args = parser.parse_args()
    tier = args.tier.capitalize()

    document, changes = build(args.state)
    policy_set = put_policy.validate(document)
    print(f"Demo state {args.state!r}:")
    for change in changes:
        print(f"  {change}")
    put_policy.describe(policy_set)
    put_policy.check_size(put_policy.serialize(document), tier)

    if args.dry_run:
        print("\nDry run — nothing written.")
        return
    put_policy.publish(document, args.parameter_name, args.region, tier)


if __name__ == "__main__":
    main()
