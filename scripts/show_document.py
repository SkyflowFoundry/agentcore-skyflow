#!/usr/bin/env python3
"""Show a stored document beside the copy the gateway hands the agent.

This is Figure 4 of the blog post, and the check to run before recording. It
reads the original straight from the document bucket, asks the gateway for the
same document exactly as the agent would, downloads the copy behind the URL it
returns, and prints the two side by side.

    app/Flow/.venv/bin/python scripts/show_document.py samples/dispute-case-note.txt
    app/Flow/.venv/bin/python scripts/show_document.py samples/dispute-case-note.docx

Word documents are compared by their paragraphs. A PDF is not compared, since
its text is not worth extracting here: the clean copy is saved to a new local
file, and its path printed, so it can be opened without the signed link.

It exits non-zero when the swap did not happen: the gateway returned an error,
or a link to your own bucket, or a copy with the original values still in it.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

#: Values from the sample note that must not survive in the clean copy.
SAMPLE_VALUES = (
    "Mateo Jackson",
    "mateo_jackson@example.com",
    "555-0100",
    "4111 1111 1111 1111",
)


def text_of(data: bytes, key: str) -> list[str] | None:
    """The document's lines, or None for a format not compared here."""
    if key.endswith(".docx"):
        xml = zipfile.ZipFile(io.BytesIO(data)).read("word/document.xml").decode("utf-8")
        paragraphs = re.findall(r"<w:p[ >].*?</w:p>", xml, flags=re.S)
        lines = ["".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", p)) for p in paragraphs]
        return [_unescape(line) for line in lines]
    if key.endswith((".txt", ".csv", ".json", ".jsonl", ".xml")):
        return data.decode("utf-8", errors="replace").splitlines()
    return None


def _unescape(text: str) -> str:
    return text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'").replace("&amp;", "&")


def side_by_side(left: list[str], right: list[str]) -> str:
    """Two columns joined by an arrow, the layout of the blog's Figure 4."""
    width = max((len(line) for line in left), default=0) + 2
    rows = []
    for index in range(max(len(left), len(right))):
        a = left[index] if index < len(left) else ""
        b = right[index] if index < len(right) else ""
        arrow = "→" if a != b else " "
        rows.append(f"{a:<{width}}{arrow}   {b}".rstrip())
    return "\n".join(rows)


def leaked(lines: list[str]) -> list[str]:
    joined = "\n".join(lines)
    return [value for value in SAMPLE_VALUES if value in joined]


def clean_url(response: dict) -> str:
    """The URL the gateway returned, or exit with the gateway's error."""
    if response is None:
        sys.exit("FAIL the gateway returned no body")
    if "error" in response:
        sys.exit(f"FAIL the gateway withheld the document: {response['error'].get('message')}")
    result = response.get("result") or {}
    if result.get("isError"):
        sys.exit(f"FAIL the tool returned an error: {json.dumps(result)[:300]}")
    text = result["content"][0]["text"]
    return json.loads(text)["url"]


def save_copy(data: bytes, key: str, out_dir: str | None) -> Path:
    """Write the clean copy to a new file, so a rerun never overwrites one."""
    name = Path(key)
    fd, path = tempfile.mkstemp(prefix=f"{name.stem}-clean-", suffix=name.suffix, dir=out_dir)
    with open(fd, "wb") as out:
        out.write(data)
    return Path(path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("key", help="document key, for example samples/dispute-case-note.txt")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--stack", default=None, help="AgentCore stack, for the gateway URL")
    parser.add_argument("--url", default=None, help="gateway MCP URL; defaults to the stack output")
    parser.add_argument("--bucket", default=None, help="defaults to agentcore-skyflow-files-<account>")
    parser.add_argument("--timeout", type=int, default=300, help="seconds to wait for the gateway")
    parser.add_argument("--out-dir", default=None,
                        help="where a non-text clean copy is saved; defaults to the system temp directory")
    args = parser.parse_args()

    import boto3
    import mcp_call

    session = boto3.Session(region_name=args.region)
    account = session.client("sts").get_caller_identity()["Account"]
    bucket = args.bucket or f"agentcore-skyflow-files-{account}"
    url = args.url or mcp_call.gateway_url_from_stack(session, args.stack or mcp_call.DEFAULT_STACK)

    original = session.client("s3").get_object(Bucket=bucket, Key=args.key)["Body"].read()

    _, headers = mcp_call.post(session, url, args.region, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": mcp_call.PROTOCOL_VERSION, "capabilities": {},
                   "clientInfo": {"name": "show-document", "version": "0.1.0"}},
    }, None)
    session_id = headers.get("Mcp-Session-Id") or headers.get("mcp-session-id")
    mcp_call.post(session, url, args.region, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_id)
    print(f"Asking the gateway for {args.key} (a document can take a minute or more)...", file=sys.stderr)
    response, _ = mcp_call.post(session, url, args.region, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "s3___get_document", "arguments": {"key": args.key}},
    }, session_id, timeout=args.timeout)

    link = clean_url(response)
    host = urlsplit(link).hostname or ""
    if host.startswith(bucket):
        sys.exit(f"FAIL the agent got a link to your own bucket ({host}); the interceptor did not swap it")
    with urllib.request.urlopen(link, timeout=60) as resp:
        clean = resp.read()

    print(f"original  s3://{bucket}/{args.key}")
    print(f"agent     https://{host}/...  (Skyflow-hosted de-identified copy)\n")

    left, right = text_of(original, args.key), text_of(clean, args.key)
    if left is None or right is None:
        print(f"Not a text format, so not compared. The clean copy is saved at\n  {save_copy(clean, args.key, args.out_dir)}")
        return
    print(side_by_side(left, right))
    survivors = leaked(right)
    if survivors:
        sys.exit(f"\nFAIL still present in the clean copy: {survivors}")
    print("\nOK none of the sample's personal values survive in the copy the agent receives.")


if __name__ == "__main__":
    main()
