#!/usr/bin/env python3
"""A loopback proxy that SigV4-signs MCP traffic to an AgentCore Gateway.

The MCP Inspector can send static headers but cannot SigV4-sign, and a gateway
with `authorizerType: AWS_IAM` needs a fresh signature over every request body.
This bridges the two: Inspector talks plain unauthenticated HTTP to
`http://127.0.0.1:8090/mcp`, and each request is signed and forwarded.

Signing goes through `mcp_client.sigv4`, the same code the deployed agent uses,
so what Inspector exercises is the agent's own auth path.

    app/Flow/.venv/bin/python scripts/gateway_proxy.py
    npx @modelcontextprotocol/inspector --server-url http://127.0.0.1:8090/mcp --transport http

SECURITY: anyone who can reach this port can call the gateway as you, with no
credential of their own. It binds 127.0.0.1 only and refuses any other host.
Stop it when you are done.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "app" / "Flow"))

import httpx  # noqa: E402

from mcp_client.endpoints import signing_region  # noqa: E402
from mcp_client.sigv4 import SigV4Auth  # noqa: E402

DEPLOYED_STATE = REPO_ROOT / "agentcore" / ".cli" / "deployed-state.json"

# Only loopback. A wildcard bind would hand the gateway to the network.
ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost"}

# Forwarded from Inspector to the gateway. Everything else is dropped: Host is
# httpx's to set, and an inbound Authorization must never survive, or it would
# be signed over and contradict the signature we add.
FORWARD_REQUEST_HEADERS = {
    "accept",
    "content-type",
    "last-event-id",
    "mcp-protocol-version",
    "mcp-session-id",
}

# Dropped on the way back: hop-by-hop, or invalidated by decoding the body.
STRIP_RESPONSE_HEADERS = {
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "transfer-encoding",
}


def gateway_url_from_state(target: str, gateway: str) -> str:
    if not DEPLOYED_STATE.exists():
        sys.exit(f"{DEPLOYED_STATE} not found; run `agentcore deploy` first")
    state = json.loads(DEPLOYED_STATE.read_text())
    try:
        return state["targets"][target]["resources"]["mcp"]["gateways"][gateway]["gatewayUrl"]
    except KeyError:
        sys.exit(f"No gateway {gateway!r} under target {target!r} in {DEPLOYED_STATE}")


class SigningProxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Set by main().
    target_url: str = ""
    client: httpx.Client

    def do_POST(self) -> None:
        self._forward("POST")

    def do_GET(self) -> None:
        self._forward("GET")

    def do_DELETE(self) -> None:
        self._forward("DELETE")

    def log_message(self, fmt: str, *args) -> None:
        # The default writes every request to stderr with a timestamp; _forward
        # already logs a line per request with the upstream status.
        pass

    def _forward(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() in FORWARD_REQUEST_HEADERS
        }

        try:
            with self.client.stream(
                method, self.target_url, content=body, headers=headers
            ) as upstream:
                streaming = "text/event-stream" in upstream.headers.get("content-type", "")
                # flush: this log is the point of the tool, and stdout is
                # block-buffered whenever it is piped rather than a tty.
                print(
                    f"  {method} -> {upstream.status_code}"
                    + ("  (stream)" if streaming else ""),
                    flush=True,
                )
                if streaming:
                    self._relay_stream(upstream)
                else:
                    self._relay_body(upstream)
        except httpx.HTTPError as exc:
            self._fail(502, f"upstream request failed: {exc}")

    def _response_headers(self, upstream: httpx.Response) -> list[tuple[str, str]]:
        return [
            (key, value)
            for key, value in upstream.headers.items()
            if key.lower() not in STRIP_RESPONSE_HEADERS
        ]

    def _relay_body(self, upstream: httpx.Response) -> None:
        payload = upstream.read()
        self.send_response(upstream.status_code)
        for key, value in self._response_headers(upstream):
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _relay_stream(self, upstream: httpx.Response) -> None:
        # An SSE body has no length known up front. Rather than chunk-encoding
        # it by hand, close the connection at the end and let the client read to
        # EOF, which is what SSE clients already expect.
        self.send_response(upstream.status_code)
        for key, value in self._response_headers(upstream):
            self.send_header(key, value)
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            for chunk in upstream.iter_bytes():
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # Inspector closed the stream; nothing to clean up.

    def _fail(self, status: int, message: str) -> None:
        payload = json.dumps({"error": message}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--url", default=None, help="gateway MCP URL; defaults to deployed state")
    parser.add_argument("--target", default="dev")
    parser.add_argument("--gateway", default="SkyflowGateway")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--region", default=None, help="signing region; defaults to the gateway host's")
    args = parser.parse_args()

    if args.host not in ALLOWED_HOSTS:
        sys.exit(
            f"Refusing to bind {args.host!r}. This proxy signs with your AWS credentials "
            "and has no authentication of its own, so it is loopback only."
        )

    url = args.url or gateway_url_from_state(args.target, args.gateway)
    region = args.region or signing_region(url)
    if not region:
        sys.exit("Could not determine a signing region; pass --region.")

    SigningProxy.target_url = url
    SigningProxy.client = httpx.Client(auth=SigV4Auth(region=region), timeout=60.0)

    server = ThreadingHTTPServer((args.host, args.port), SigningProxy)
    listen = f"http://{args.host}:{args.port}/mcp"

    print(f"Signing for {region}, forwarding to:\n  {url}\n")
    print(f"Listening on {listen}\n")
    print("Point the MCP Inspector at it:")
    print(f"  npx @modelcontextprotocol/inspector --server-url {listen} --transport http\n")
    print("Anyone who reaches this port calls the gateway as you. Ctrl-C to stop.\n", flush=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        thread.join()
    except KeyboardInterrupt:
        print("\nstopping")
        server.shutdown()


if __name__ == "__main__":
    main()
