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


#: SSM's limit for a Standard-tier parameter value. Advanced allows 8 KB but is
#: billed per parameter, so it is opt-in.
STANDARD_TIER_LIMIT = 4096
ADVANCED_TIER_LIMIT = 8192


def serialize(document: dict) -> str:
    """The policy as published: minified, so whitespace does not spend the limit."""
    return json.dumps(document, separators=(",", ":"))


def validate(document: dict) -> PolicySet:
    """Parse with the Lambda's own model, exiting with the reason on failure."""
    try:
        return PolicySet.from_json(document)
    except PolicyError as exc:
        sys.exit(f"Policy is invalid: {exc}")


def check_size(value: str, tier: str) -> None:
    """Exit before SSM refuses the write, naming the way out."""
    limit = ADVANCED_TIER_LIMIT if tier == "Advanced" else STANDARD_TIER_LIMIT
    if len(value.encode("utf-8")) > limit:
        hint = (
            "Publish with --tier advanced (and deploy the stack with "
            "-c policyParameterTier=advanced) to raise the limit to 8 KB."
            if tier != "Advanced" else "Split the policy or shorten its overrides."
        )
        sys.exit(f"Policy is {len(value.encode('utf-8'))} bytes minified; the {tier} tier allows {limit}. {hint}")


def publish(document: dict, parameter_name: str, region: str | None, tier: str) -> None:
    value = serialize(document)
    check_size(value, tier)

    import boto3

    session = boto3.Session(region_name=region) if region else boto3.Session()
    session.client("ssm").put_parameter(
        Name=parameter_name,
        Value=value,
        Type="String",
        Tier=tier,
        Overwrite=True,
    )
    print(f"\nWrote {parameter_name} ({len(value)} bytes). Active within the interceptor's cache TTL.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--parameter-name", default=DEFAULT_PARAMETER)
    parser.add_argument("--region", default=None)
    parser.add_argument("--tier", choices=["standard", "advanced"], default="standard",
                        help="SSM parameter tier. Standard holds 4 KB, advanced 8 KB.")
    parser.add_argument("--dry-run", action="store_true", help="Validate without writing to SSM.")
    args = parser.parse_args()
    tier = args.tier.capitalize()

    if not POLICY_FILE.exists():
        sys.exit(f"Policy file not found: {POLICY_FILE}")

    try:
        document = json.loads(POLICY_FILE.read_text())
    except json.JSONDecodeError as exc:
        sys.exit(f"Policy file is not valid JSON: {exc}")

    policy_set = validate(document)
    print(f"Policy valid ({POLICY_FILE.relative_to(REPO_ROOT)}):")
    describe(policy_set)
    value = serialize(document)
    check_size(value, tier)
    print(f"  size: {len(value)} of {STANDARD_TIER_LIMIT if tier == 'Standard' else ADVANCED_TIER_LIMIT} bytes ({tier} tier)")

    if args.dry_run:
        print("\nDry run — nothing written.")
        return

    publish(document, args.parameter_name, args.region, tier)


if __name__ == "__main__":
    main()
