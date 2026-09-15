#!/usr/bin/env python3
"""Drive Flow's own MCP client against a live gateway.

Imports the same `mcp_client` package the deployed agent imports, so a green
run proves the real code path — discovery, credential choice and SigV4 signing
— against the real endpoint, not against fakes. `scripts/mcp_call.py` speaks
JSON-RPC to the gateway directly; this exercises the agent's client instead.

Needs the agent's virtualenv, which has mcp and strands:

    app/Flow/.venv/bin/python scripts/flow_mcp_check.py
    app/Flow/.venv/bin/python scripts/flow_mcp_check.py \
        --call exa___web_search_exa \
        --arguments '{"query": "...", "objective": "..."}'

The gateway URL comes from `agentcore/.cli/deployed-state.json` unless the
environment already advertises one, so the same variables a deployed runtime
sees can be set here to test a different gateway.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "app" / "Flow"))

DEPLOYED_STATE = REPO_ROOT / "agentcore" / ".cli" / "deployed-state.json"


def environment_advertises_an_endpoint() -> bool:
    if os.environ.get("MCP_ENDPOINTS", "").strip():
        return True
    return any(
        key.endswith("_URL") and key.startswith(("AGENTCORE_GATEWAY_", "GATEWAY_"))
        for key in os.environ
    )


def gateway_url_from_state(target: str, gateway: str) -> str:
    if not DEPLOYED_STATE.exists():
        sys.exit(f"{DEPLOYED_STATE} not found; run `agentcore deploy` first")
    state = json.loads(DEPLOYED_STATE.read_text())
    try:
        return state["targets"][target]["resources"]["mcp"]["gateways"][gateway]["gatewayUrl"]
    except KeyError:
        sys.exit(f"No gateway {gateway!r} under target {target!r} in {DEPLOYED_STATE}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--target", default="dev", help="deployment target name")
    parser.add_argument("--gateway", default="SkyflowGateway", help="gateway name")
    parser.add_argument("--call", help="tool name to invoke, e.g. exa___web_search_exa")
    parser.add_argument("--arguments", default="{}", help="JSON object of tool arguments")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s %(message)s")

    if not environment_advertises_an_endpoint():
        url = gateway_url_from_state(args.target, args.gateway)
        token = args.gateway.upper()
        os.environ[f"AGENTCORE_GATEWAY_{token}_URL"] = url
        os.environ[f"AGENTCORE_GATEWAY_{token}_AUTH_TYPE"] = "AWS_IAM"
        print(f"Using {args.gateway} from deployed state: {url}\n")

    # Imported after the environment is set: discovery reads it at call time,
    # but keeping the order obvious avoids a confusing edit later.
    from mcp_client.client import get_mcp_clients

    for client in get_mcp_clients():
        with client:
            tools = client.list_tools_sync()
            print(f"\n{len(tools)} tool(s):")
            for tool in tools:
                print(f"  {tool.tool_name}")

            if not args.call:
                continue

            print(f"\nCalling {args.call}...")
            result = client.call_tool_sync(
                tool_use_id="flow-mcp-check",
                name=args.call,
                arguments=json.loads(args.arguments),
            )
            print(f"status: {result['status']}")
            print(json.dumps(result.get("content"), indent=2, default=str)[:4000])


if __name__ == "__main__":
    main()
