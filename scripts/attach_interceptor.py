#!/usr/bin/env python3
"""Attach the Skyflow interceptor Lambda to an AgentCore Gateway.

The AgentCore CLI cannot declare interceptors, so this runs after
`agentcore deploy`:

    agentcore deploy
    python3 scripts/attach_interceptor.py \
        --gateway-name SkyflowGateway \
        --function-arn arn:aws:lambda:us-east-1:...:function:... \
        --region us-east-1

It does two things:

1. Grants the gateway's service role `lambda:InvokeFunction` on that one
   function. Per the AgentCore docs this is an identity-based grant on the
   gateway role, not a Lambda resource policy, and it is deliberately scoped to
   a single ARN rather than a wildcard.
2. Calls `update-gateway` with `interceptorConfigurations`, preserving the
   gateway's existing settings.

Re-running is safe: the role policy is replaced in place and the interceptor
configuration is overwritten with the same values.
"""

from __future__ import annotations

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError

INLINE_POLICY_NAME = "InvokeSkyflowInterceptor"


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


def grant_invoke(role_arn: str, function_arn: str) -> None:
    role_name = role_arn.rsplit("/", 1)[-1]
    iam = boto3.client("iam")
    document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "lambda:InvokeFunction",
                "Resource": function_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=INLINE_POLICY_NAME,
        PolicyDocument=json.dumps(document),
    )
    print(f"  granted lambda:InvokeFunction to {role_name} on {function_arn.rsplit(':', 1)[-1]}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway-name", required=True)
    parser.add_argument("--function-arn", required=True)
    parser.add_argument("--region", default=None)
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
    parser.add_argument("--skip-iam", action="store_true", help="Skip the role grant (already done).")
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region) if args.region else boto3.Session()
    control = session.client("bedrock-agentcore-control")

    print(f"Looking up gateway {args.gateway_name!r}...")
    summary = find_gateway(control, args.gateway_name)
    gateway_id = summary["gatewayId"]

    gateway = control.get_gateway(gatewayIdentifier=gateway_id)
    role_arn = gateway.get("roleArn")
    print(f"  gatewayId={gateway_id}")
    print(f"  roleArn={role_arn}")

    if not args.skip_iam:
        if not role_arn:
            sys.exit("Gateway has no roleArn; cannot grant invoke permission.")
        grant_invoke(role_arn, args.function_arn)

    interceptor_configurations = [
        {
            "interceptor": {"lambda": {"arn": args.function_arn}},
            "interceptionPoints": args.points,
            "inputConfiguration": {"passRequestHeaders": args.pass_request_headers},
        }
    ]

    # update_gateway replaces the resource, so echo back the fields it already
    # has rather than letting them reset to defaults.
    update: dict = {
        "gatewayIdentifier": gateway_id,
        "name": gateway["name"],
        "roleArn": role_arn,
        "protocolType": gateway.get("protocolType", "MCP"),
        "authorizerType": gateway.get("authorizerType", "NONE"),
        "interceptorConfigurations": interceptor_configurations,
    }
    for optional in ("description", "authorizerConfiguration", "protocolConfiguration",
                     "exceptionLevel", "kmsKeyArn"):
        if gateway.get(optional):
            update[optional] = gateway[optional]

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
