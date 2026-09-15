#!/usr/bin/env python3
"""Exercise the secret-safety hook: real fetches must still be denied,
authoring source code that calls Secrets Manager must be allowed."""

import json
import subprocess
import sys
from pathlib import Path

# Resolved from this file, not hardcoded: the suite has to run on any checkout,
# CI included.
HOOK = Path(__file__).resolve().parent / "secret-safety.py"

GSV = "get_secret" + "_value"          # split so this file is not itself a tripwire
CLI_GSV = "get-secret" + "-value"


def run(payload):
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    # A hook that fails to run writes nothing to stdout, which would read as
    # "allow" and let every deny case silently pass. Treat it as a hard error
    # so a broken hook cannot masquerade as a permissive one.
    if proc.returncode != 0:
        raise RuntimeError(
            f"hook exited {proc.returncode}\nstderr: {proc.stderr.strip()[:500]}"
        )
    return "deny" in proc.stdout


def bash(command):
    return {"tool_name": "Bash", "tool_input": {"command": command}}


CASES = [
    # (label, payload, expect_deny)

    # --- the original false positive -------------------------------------
    (
        "heredoc writing Lambda source that calls SM, then a python -c syntax check",
        bash(
            "cat > settings.py <<'PYEOF'\n"
            "import boto3\n"
            "_secrets = boto3.client('secretsmanager')\n"
            f"stored = _secrets.{GSV}(SecretId=arn)['SecretString']\n"
            "PYEOF\n"
            "python3 -c \"import ast; ast.parse(open('settings.py').read())\""
        ),
        False,
    ),
    (
        "heredoc writing docs that mention the CLI fetch command",
        bash(f"cat > README.md <<'EOF'\nRun: aws secretsmanager {CLI_GSV} --secret-id x\nEOF"),
        False,
    ),

    # --- must still be denied --------------------------------------------
    ("direct CLI fetch", bash(f"aws secretsmanager {CLI_GSV} --secret-id skyflow/key"), True),
    ("CLI fetch with interleaved flags",
     bash(f"aws --region us-east-1 secretsmanager --output json {CLI_GSV} --secret-id x"), True),
    ("CLI batch fetch", bash(f"aws secretsmanager batch-{CLI_GSV} --secret-id-list x"), True),
    ("heredoc PIPED to python containing an SDK call",
     bash(f"cat <<'EOF' | python3\nimport boto3\nboto3.client('secretsmanager').{GSV}(SecretId='x')\nEOF"),
     True),
    ("inline python -c with an SDK call",
     bash(f"python3 -c \"import boto3; boto3.client('secretsmanager').{GSV}(SecretId='x')\""), True),
    ("secrets agent HTTP endpoint",
     bash("curl http://localhost:2773/secretsmanager/get?secretId=x"), True),
    ("structured MCP call",
     {"tool_name": "mcp__aws__call_aws",
      "tool_input": {"service_name": "secretsmanager", "operation_name": "GetSecretValue"}},
     True),
    ("CLI fetch chained after a read-only command",
     bash(f"cat notes.txt && aws secretsmanager {CLI_GSV} --secret-id x"), True),

    # --- should remain allowed -------------------------------------------
    ("grep that merely mentions the API name", bash(f"grep -r '{GSV}' src/"), False),
    ("unrelated CLI call", bash("aws secretsmanager describe-secret --secret-id x"), False),
    ("creating a secret (not fetching)",
     bash("aws secretsmanager create-secret --name x --secret-string 'y'"), False),
]


def main():
    if not HOOK.exists():
        print(f"hook not found at {HOOK}", file=sys.stderr)
        return 1

    failures = 0
    for label, payload, expect_deny in CASES:
        got_deny = run(payload)
        ok = got_deny == expect_deny
        want = "DENY" if expect_deny else "ALLOW"
        got = "DENY" if got_deny else "ALLOW"
        print(f"  [{'ok ' if ok else 'FAIL'}] want={want:<5} got={got:<5}  {label}")
        if not ok:
            failures += 1

    print()
    print(f"{len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
