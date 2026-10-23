#!/usr/bin/env python3
"""Check, or repair by hand, the Skyflow interceptor on an AgentCore Gateway.

`agentcore deploy` attaches the interceptor itself. The AgentCore CLI cannot
declare interceptors, so agentcore/cdk/lib/cdk-stack.ts sets them on the
gateway's CloudFormation resource from the interceptor stack's exported
function ARN, and grants the gateway role both permissions listed below. Run
this with `--check` after every `agentcore deploy` to confirm it:

    python3 scripts/attach_interceptor.py --gateway-name agentflow-SkyflowGateway --check

Without `--check` it attaches the interceptor through `update-gateway`, outside
CloudFormation. That repairs a live gateway, but the next `agentcore deploy`
that changes the gateway sets it back to whatever the CDK app declares:

    python3 scripts/attach_interceptor.py \
        --gateway-name agentflow-SkyflowGateway \
        --function-arn arn:aws:lambda:us-east-1:...:function:... \
        --region us-east-1

Note the gateway name carries the project prefix: a gateway named
`SkyflowGateway` in `agentcore.json` is deployed as `agentflow-SkyflowGateway`.

Without `--check` it does three things:

1. Grants the gateway's service role `lambda:InvokeFunction` on that one
   function. Per the AgentCore docs this is an identity-based grant on the
   gateway role, not a Lambda resource policy, and it is deliberately scoped to
   a single ARN rather than a wildcard.
2. Grants that same role `bedrock-agentcore:GetConfigurationBundleVersion` on
   the project's config bundles. When a caller has a ConfigBundle the gateway
   fetches it to resolve tool descriptions; without this, a runtime calling the
   gateway fails at `tools/list` with HTTP 400. The AgentCore L3 constructs
   grant this to the runtime role only. It hides well: a caller with no
   bundle — an IAM user running `scripts/mcp_call.py` — triggers no fetch, so
   the gateway looks healthy from every direction except a runtime.
3. Calls `update-gateway` with `interceptorConfigurations`, preserving the
   gateway's existing settings. `update-gateway` replaces the whole resource,
   so every writable field that `get-gateway` returned is echoed back. The
   list of writable fields comes from the service model rather than from a
   hand-written tuple, because a field left out here — a Cedar policy engine,
   say, or a WAF configuration — is silently detached from the gateway.

Re-running is safe: role policies are replaced in place and the interceptor
configuration is overwritten with the same values.

`--check` changes nothing. It reports whether the interceptor is attached at
both points and exits non-zero if it is not. Pass `--function-arn` as well to
also confirm which function is attached.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

INVOKE_POLICY_NAME = "InvokeSkyflowInterceptor"
CONFIG_BUNDLE_POLICY_NAME = "ReadRuntimeConfigBundles"

# The gateway resolves the caller's bundle at tools/list time. Reading a version
# is all it does; it never lists or writes.
CONFIG_BUNDLE_ACTIONS = ["bedrock-agentcore:GetConfigurationBundleVersion"]

DEPLOYED_STATE = Path(__file__).resolve().parents[1] / "agentcore" / ".cli" / "deployed-state.json"


def find_gateway(control, name: str) -> dict:
    """Return the gateway summary whose name matches, or exit with a clear error."""
    paginator_kwargs: dict = {}
    seen: list[str] = []
    while True:
        resp = control.list_gateways(**paginator_kwargs)
        for item in resp.get("items", []):
            seen.append(item.get("name", "<unnamed>"))
            if item.get("name") == name:
                return item
        token = resp.get("nextToken")
        if not token:
            break
        paginator_kwargs = {"nextToken": token}

    sys.exit(f"No gateway named {name!r}. Found: {', '.join(seen) or '(none)'}")


def bundle_arns_from_state(target: str) -> list[str]:
    """Config bundle ARNs recorded for a deployment target.

    Returns empty rather than exiting: a project with no config bundle is
    legitimate, and the interceptor attach should still proceed.
    """
    if not DEPLOYED_STATE.exists():
        print(f"  no {DEPLOYED_STATE.name}; skipping the config bundle grant")
        return []
    state = json.loads(DEPLOYED_STATE.read_text())
    bundles = state.get("targets", {}).get(target, {}).get("resources", {}).get("configBundles", {})
    return sorted(b["bundleArn"] for b in bundles.values() if b.get("bundleArn"))


def put_policy(role_arn: str, policy_name: str, statements: list[dict]) -> str:
    role_name = role_arn.rsplit("/", 1)[-1]
    boto3.client("iam").put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_name


def grant_invoke(role_arn: str, function_arn: str) -> None:
    role_name = put_policy(
        role_arn,
        INVOKE_POLICY_NAME,
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function_arn}],
    )
    print(f"  granted lambda:InvokeFunction to {role_name} on {function_arn.rsplit(':', 1)[-1]}")


def grant_config_bundle_read(role_arn: str, bundle_arns: list[str]) -> None:
    role_name = put_policy(
        role_arn,
        CONFIG_BUNDLE_POLICY_NAME,
        [{"Effect": "Allow", "Action": CONFIG_BUNDLE_ACTIONS, "Resource": bundle_arns}],
    )
    print(f"  granted {', '.join(CONFIG_BUNDLE_ACTIONS)} to {role_name} on:")
    for arn in bundle_arns:
        print(f"    {arn.rsplit('/', 1)[-1]}")


def writable_gateway_fields(control) -> set[str]:
    """Every input field `update-gateway` accepts, from the installed service model.

    Read from botocore rather than listed by hand so a field added to the API
    later is preserved as soon as boto3 is upgraded, instead of being dropped
    until someone notices a gateway lost its policy engine.
    """
    model = control.meta.service_model.operation_model("UpdateGateway")
    return set(model.input_shape.members)


def build_update(control, gateway: dict, interceptor_configurations: list[dict]) -> dict:
    """The `update-gateway` call that changes only the interceptors.

    `update-gateway` replaces the resource, so anything not echoed back resets
    to its default. Copy every writable field the gateway currently has —
    `policyEngineConfiguration`, `wafConfiguration`, `kmsKeyArn` and the rest —
    and set the interceptors on top.
    """
    writable = writable_gateway_fields(control)
    update = {
        key: value
        for key, value in gateway.items()
        if key in writable and value not in (None, "", [], {})
    }
    update["gatewayIdentifier"] = gateway["gatewayId"]
    update["interceptorConfigurations"] = interceptor_configurations
    return update


def check_attached(gateway: dict, function_arn: str | None) -> list[str]:
    """Problems with the gateway's interceptor configuration, or none."""
    configs = gateway.get("interceptorConfigurations") or []
    if not configs:
        return ["no interceptor is attached; tool calls pass through uninspected"]
    problems = []
    points: set[str] = set()
    for config in configs:
        arn = ((config.get("interceptor") or {}).get("lambda") or {}).get("arn", "")
        if function_arn and arn != function_arn:
            problems.append(f"attached function is {arn.rsplit(':', 1)[-1] or '<none>'}, "
                            f"not {function_arn.rsplit(':', 1)[-1]}")
        points.update(config.get("interceptionPoints") or [])
    for point in ("REQUEST", "RESPONSE"):
        if point not in points:
            problems.append(f"not attached at {point}")
    return problems


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway-name", required=True, help="deployed name, including the project prefix")
    parser.add_argument("--function-arn", help="required unless --check")
    parser.add_argument("--region", default=None)
    parser.add_argument("--target", default="dev", help="deployment target, for the config bundle lookup")
    parser.add_argument(
        "--bundle-arn",
        action="append",
        dest="bundle_arns",
        help="Config bundle ARN to grant. Repeatable. Defaults to every bundle in deployed state.",
    )
    parser.add_argument(
        "--points",
        nargs="+",
        default=["REQUEST", "RESPONSE"],
        choices=["REQUEST", "RESPONSE"],
        help="Interception points to attach. Default: both.",
    )
    parser.add_argument(
        "--pass-request-headers",
        action="store_true",
        help="Include request headers in the interceptor payload. Off by default — "
        "headers carry bearer tokens and this interceptor does not need them.",
    )
    parser.add_argument("--skip-iam", action="store_true", help="Skip both role grants (already done).")
    parser.add_argument("--check", action="store_true",
                        help="Change nothing; exit 1 unless the interceptor is attached at both points.")
    args = parser.parse_args()
    if not args.check and not args.function_arn:
        parser.error("--function-arn is required unless --check is given")

    session = boto3.Session(region_name=args.region) if args.region else boto3.Session()
    control = session.client("bedrock-agentcore-control")

    print(f"Looking up gateway {args.gateway_name!r}...")
    summary = find_gateway(control, args.gateway_name)
    gateway_id = summary["gatewayId"]

    gateway = control.get_gateway(gatewayIdentifier=gateway_id)
    role_arn = gateway.get("roleArn")

    if args.check:
        problems = check_attached(gateway, args.function_arn)
        if problems:
            for problem in problems:
                print(f"  FAIL {problem}")
            sys.exit(1)
        print("  OK interceptor attached at REQUEST and RESPONSE")
        return
    print(f"  gatewayId={gateway_id}")
    print(f"  roleArn={role_arn}")

    if not args.skip_iam:
        if not role_arn:
            sys.exit("Gateway has no roleArn; cannot grant permissions.")
        grant_invoke(role_arn, args.function_arn)

        bundle_arns = args.bundle_arns or bundle_arns_from_state(args.target)
        if bundle_arns:
            grant_config_bundle_read(role_arn, bundle_arns)
        else:
            print("  no config bundles to grant")

    interceptor_configurations = [
        {
            "interceptor": {"lambda": {"arn": args.function_arn}},
            "interceptionPoints": args.points,
            "inputConfiguration": {"passRequestHeaders": args.pass_request_headers},
        }
    ]

    update = build_update(control, gateway, interceptor_configurations)
    preserved = sorted(
        key for key in update
        if key not in ("gatewayIdentifier", "interceptorConfigurations")
    )
    print(f"  preserving: {', '.join(preserved)}")

    try:
        control.update_gateway(**update)
    except ClientError as exc:
        sys.exit(f"update_gateway failed: {exc}")

    print(f"\nAttached interceptor at {', '.join(args.points)}.")
    print(f"  passRequestHeaders={args.pass_request_headers}")
    print("\nVerify with:")
    print(f"  aws bedrock-agentcore-control get-gateway --gateway-identifier {gateway_id}"
          + (f" --region {args.region}" if args.region else ""))


if __name__ == "__main__":
    main()
