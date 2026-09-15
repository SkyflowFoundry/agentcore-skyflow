#!/usr/bin/env python3
"""Let a gateway read the config bundles of the runtimes that call it.

When a caller with a ConfigBundle invokes a gateway, the gateway fetches that
bundle to resolve tool descriptions. The gateway's service role, as created by
the AgentCore CDK, has no permission to do so, and `tools/list` fails:

    HTTP 400 {"error": {"code": -32600, "message": "Config bundle fetch
    failed: ... is not authorized to perform:
    bedrock-agentcore:GetConfigurationBundleVersion ..."}}

The failure is invisible from an IAM user or any other caller without a bundle,
because nothing is fetched for them. It only appears once an AgentCore Runtime
calls the gateway.

Like `scripts/attach_interceptor.py`, this runs after `agentcore deploy`:

    agentcore deploy
    python3 scripts/grant_gateway_config_bundle.py --gateway-name SkyflowGateway

Bundle ARNs come from `agentcore/.cli/deployed-state.json` unless `--bundle-arn`
is given. Re-running is safe: the inline policy is replaced in place.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import boto3

sys.path.insert(0, str(Path(__file__).resolve().parent))

from attach_interceptor import find_gateway  # noqa: E402

INLINE_POLICY_NAME = "ReadRuntimeConfigBundles"
DEPLOYED_STATE = Path(__file__).resolve().parents[1] / "agentcore" / ".cli" / "deployed-state.json"

# The gateway resolves the caller's bundle at tools/list time. Reading a version
# is all it does; it never lists or writes.
ACTIONS = ["bedrock-agentcore:GetConfigurationBundleVersion"]


def bundle_arns_from_state(target: str) -> list[str]:
    if not DEPLOYED_STATE.exists():
        sys.exit(f"{DEPLOYED_STATE} not found; run `agentcore deploy` first")
    state = json.loads(DEPLOYED_STATE.read_text())
    try:
        bundles = state["targets"][target]["resources"]["configBundles"]
    except KeyError:
        sys.exit(f"No configBundles recorded for target {target!r} in {DEPLOYED_STATE}")

    arns = [b["bundleArn"] for b in bundles.values() if b.get("bundleArn")]
    if not arns:
        sys.exit(f"No config bundle ARNs for target {target!r}; nothing to grant")
    return sorted(arns)


def grant(role_arn: str, bundle_arns: list[str]) -> None:
    role_name = role_arn.rsplit("/", 1)[-1]
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ACTIONS, "Resource": bundle_arns}],
    }
    boto3.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName=INLINE_POLICY_NAME,
        PolicyDocument=json.dumps(document),
    )
    print(f"  granted {', '.join(ACTIONS)} to {role_name} on:")
    for arn in bundle_arns:
        print(f"    {arn.rsplit('/', 1)[-1]}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--gateway-name", required=True)
    parser.add_argument("--target", default="dev", help="deployment target name")
    parser.add_argument(
        "--bundle-arn",
        action="append",
        dest="bundle_arns",
        help="Config bundle ARN to grant. Repeatable. Defaults to every bundle in deployed state.",
    )
    parser.add_argument("--region", default=None)
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region) if args.region else boto3.Session()
    control = session.client("bedrock-agentcore-control")

    print(f"Looking up gateway {args.gateway_name!r}...")
    summary = find_gateway(control, args.gateway_name)
    gateway = control.get_gateway(gatewayIdentifier=summary["gatewayId"])
    role_arn = gateway.get("roleArn")
    if not role_arn:
        sys.exit("Gateway has no roleArn; nothing to grant to.")
    print(f"  roleArn={role_arn}")

    bundle_arns = args.bundle_arns or bundle_arns_from_state(args.target)
    grant(role_arn, bundle_arns)
    print("\nDone. A runtime with a config bundle can now call this gateway.")


if __name__ == "__main__":
    main()
