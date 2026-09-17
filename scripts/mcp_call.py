#!/usr/bin/env python3
"""Call an AgentCore Gateway's MCP endpoint with SigV4 auth.

The gateway is created with `authorizerType: AWS_IAM`, so requests must be
SigV4-signed for the `bedrock-agentcore` service. Handy for inspecting the tool
surface and for exercising the interceptor end to end.

    python3 scripts/mcp_call.py tools/list
    python3 scripts/mcp_call.py tools/call --name exa___web_search_exa \
        --arguments '{"query": "..."}'

The gateway URL is read from the deployed stack outputs unless --url is given.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

SERVICE = "bedrock-agentcore"
STACK_OUTPUT_KEY = "GatewaySkyflowGatewayUrlOutput"
DEFAULT_STACK = "AgentCore-agentflow-dev"
PROTOCOL_VERSION = "2025-06-18"


def gateway_url_from_stack(session: boto3.Session, stack_name: str) -> str:
    cfn = session.client("cloudformation")
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    for out in outputs:
        if out["OutputKey"] == STACK_OUTPUT_KEY:
            return out["OutputValue"]
    sys.exit(f"{STACK_OUTPUT_KEY} not found in stack {stack_name}")


def post(session: boto3.Session, url: str, region: str, body: dict, session_id: str | None, timeout: int = 60):
    """Send one signed JSON-RPC message. Returns (parsed_or_None, headers)."""
    payload = json.dumps(body).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id

    aws_request = AWSRequest(method="POST", url=url, data=payload, headers=headers)
    credentials = session.get_credentials().get_frozen_credentials()
    SigV4Auth(credentials, SERVICE, region).add_auth(aws_request)

    req = urllib.request.Request(url, data=payload, method="POST", headers=dict(aws_request.headers))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return parse_body(raw), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        sys.exit(f"HTTP {exc.code} from gateway:\n{detail[:2000]}")


def parse_body(raw: str):
    """Parse a JSON body, or the first data: frame of an SSE stream."""
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("{"):
        return json.loads(raw)
    for line in raw.splitlines():
        if line.startswith("data:"):
            chunk = line[len("data:"):].strip()
            if chunk:
                return json.loads(chunk)
    return {"_raw": raw[:2000]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("method", help="JSON-RPC method, e.g. tools/list or tools/call")
    parser.add_argument("--url", default=None)
    parser.add_argument("--stack", default=DEFAULT_STACK)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--name", help="tool name, for tools/call")
    parser.add_argument("--arguments", default="{}", help="JSON object of tool arguments")
    parser.add_argument("--names-only", action="store_true", help="tools/list: print tool names only")
    parser.add_argument("--timeout", type=int, default=60,
                        help="seconds to wait for the gateway; raise it when a large file is in play")
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region)
    url = args.url or gateway_url_from_stack(session, args.stack)

    # MCP handshake: initialize, then the initialized notification.
    init, headers = post(session, url, args.region, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "agentcore-mcp-call", "version": "0.1.0"},
        },
    }, None)
    session_id = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")

    post(session, url, args.region, {
        "jsonrpc": "2.0", "method": "notifications/initialized",
    }, session_id)

    if args.method == "tools/call":
        if not args.name:
            sys.exit("--name is required for tools/call")
        params = {"name": args.name, "arguments": json.loads(args.arguments)}
    else:
        params = {}

    result, _ = post(session, url, args.region, {
        "jsonrpc": "2.0", "id": 2, "method": args.method, "params": params,
    }, session_id, timeout=args.timeout)

    if args.names_only and result and "result" in result:
        for tool in result["result"].get("tools", []):
            print(tool.get("name"))
        return

    print(json.dumps(result, indent=2)[:8000])


if __name__ == "__main__":
    main()
