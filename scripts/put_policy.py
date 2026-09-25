#!/usr/bin/env python3
"""Validate gateway/interceptor/config/policy.json and push it to SSM.

Faster than a full `cdk deploy` when iterating on redaction rules. The
interceptor re-reads SSM once its cache TTL expires (default 60s), so a change
takes effect without redeploying the function.

    python3 scripts/put_policy.py --region us-east-1
    python3 scripts/put_policy.py --dry-run     # validate only

Validation runs the same PolicySet parser the Lambda uses, so a config that
would fail at runtime fails here instead.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_FILE = REPO_ROOT / "gateway" / "interceptor" / "config" / "policy.json"
DEFAULT_PARAMETER = "/agentcore/interceptor/skyflow-policy"

sys.path.insert(0, str(REPO_ROOT / "gateway" / "interceptor" / "src"))

from policy import PolicyError, PolicySet  # noqa: E402


def describe(policy_set: PolicySet) -> None:
    d = policy_set.defaults
    print(f"  defaults: request={d.request.action}/{d.request.token_type} "
          f"response={d.response.action}/{d.response.token_type} "
          f"onError={d.failure.on_error}")
    print(f"  entities: {', '.join(d.entities)}")
    print(f"  http payloads: {policy_set.http_payloads}")
    for i, ov in enumerate(policy_set.overrides):
        resolved = policy_set.resolve_override(ov)
        print(f"  override[{i}]: servers={list(ov.servers)} tools={list(ov.tools)} "
              f"-> request={resolved.request.action} response={resolved.response.action}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--parameter-name", default=DEFAULT_PARAMETER)
    parser.add_argument("--region", default=None)
    parser.add_argument("--dry-run", action="store_true", help="Validate without writing to SSM.")
    args = parser.parse_args()

    if not POLICY_FILE.exists():
        sys.exit(f"Policy file not found: {POLICY_FILE}")

    raw = POLICY_FILE.read_text()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.exit(f"Policy file is not valid JSON: {exc}")

    try:
        policy_set = PolicySet.from_json(document)
    except PolicyError as exc:
        sys.exit(f"Policy is invalid: {exc}")

    print(f"Policy valid ({POLICY_FILE.relative_to(REPO_ROOT)}):")
    describe(policy_set)

    if args.dry_run:
        print("\nDry run — nothing written.")
        return

    import boto3

    session = boto3.Session(region_name=args.region) if args.region else boto3.Session()
    ssm = session.client("ssm")
    ssm.put_parameter(
        Name=args.parameter_name,
        Value=raw,
        Type="String",
        Overwrite=True,
    )
    print(f"\nWrote {args.parameter_name}. Active within the interceptor's cache TTL.")


if __name__ == "__main__":
    main()
