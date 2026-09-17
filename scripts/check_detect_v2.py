#!/usr/bin/env python3
"""Confirm Detect v2 is enabled on the vault, end to end with a presigned URL.

v2 is beta and feature-flagged per vault, and the file interceptor depends on
it entirely: only v2 accepts `dataSource: PRESIGNED_URL`. This checks the flag
and then proves the whole path, rather than assuming either.

    app/Flow/.venv/bin/python scripts/check_detect_v2.py

It uploads a small text file containing synthetic PII to a scratch bucket,
presigns it, sends the URL to Skyflow, polls the run, and downloads the result.
The API key is read from Secrets Manager and never printed.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

import boto3

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "gateway" / "interceptor" / "src"))

from skyflow_client import SkyflowClient, build_file_configuration  # noqa: E402

SECRET_NAME = "skyflow/detect-api-key"

SAMPLE = (
    "Claim intake note\n"
    "Policyholder: Priya Raman\n"
    "Email: priya.raman@example.net\n"
    "Phone: 555-0188\n"
    "Address: 1400 Pine Street, Seattle, WA\n"
    "Summary: water damage reported on the second floor.\n"
)


def load_api_key(session: boto3.Session, secret_name: str) -> str:
    stored = session.client("secretsmanager").get_secret_value(SecretId=secret_name)["SecretString"]
    try:
        parsed = json.loads(stored)
    except json.JSONDecodeError:
        return stored.strip()
    if isinstance(parsed, dict):
        return (parsed.get("apiKey") or parsed.get("api_key") or "").strip()
    if isinstance(parsed, str):
        return parsed.strip()
    return stored.strip()


def ensure_bucket(s3, bucket: str, region: str) -> None:
    try:
        s3.head_bucket(Bucket=bucket)
        print(f"  bucket {bucket} exists")
        return
    except Exception:
        pass
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)
    # Nothing here should ever be public: the whole point is that access is by
    # presigned URL only.
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    print(f"  created bucket {bucket} (public access blocked)")


CDK_CONTEXT = (
    Path(__file__).resolve().parents[1]
    / "gateway" / "interceptor" / "cdk" / "cdk.context.json"
)


def resolve_vault(url: str | None, vault_id: str | None) -> tuple[str, str]:
    """Vault identifiers from the flags, falling back to the CDK context file.

    They are not credentials but they name real infrastructure, so they live in
    the gitignored context file rather than in this script.
    """
    if url and vault_id:
        return url, vault_id
    try:
        context = json.loads(CDK_CONTEXT.read_text())
    except FileNotFoundError:
        sys.exit(
            f"No {CDK_CONTEXT} and no --vault-url/--vault-id. "
            "Copy cdk.context.json.example and fill it in."
        )
    resolved_url = url or context.get("skyflowVaultUrl", "")
    resolved_id = vault_id or context.get("skyflowVaultId", "")
    if not resolved_url or not resolved_id:
        sys.exit(f"{CDK_CONTEXT} is missing skyflowVaultUrl or skyflowVaultId")
    return resolved_url, resolved_id


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--bucket", default=None, help="defaults to agentcore-skyflow-files-<account>")
    parser.add_argument("--key", default="samples/claim-intake.txt")
    parser.add_argument("--expires", type=int, default=900, help="presigned URL lifetime, seconds")
    parser.add_argument(
        "--vault-url",
        default=None,
        help="defaults to skyflowVaultUrl in gateway/interceptor/cdk/cdk.context.json",
    )
    parser.add_argument(
        "--vault-id",
        default=None,
        help="defaults to skyflowVaultId in gateway/interceptor/cdk/cdk.context.json",
    )
    parser.add_argument("--secret-name", default=SECRET_NAME)
    args = parser.parse_args()

    vault_url, vault_id = resolve_vault(args.vault_url, args.vault_id)

    session = boto3.Session(region_name=args.region)
    account = session.client("sts").get_caller_identity()["Account"]
    bucket = args.bucket or f"agentcore-skyflow-files-{account}"

    print("1. staging a file with synthetic PII")
    s3 = session.client("s3")
    ensure_bucket(s3, bucket, args.region)
    s3.put_object(Bucket=bucket, Key=args.key, Body=SAMPLE.encode(), ContentType="text/plain")
    signed = s3.generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": args.key}, ExpiresIn=args.expires
    )
    print(f"  s3://{bucket}/{args.key}, presigned for {args.expires}s")

    client = SkyflowClient(
        vault_url=vault_url,
        vault_id=vault_id,
        api_key=load_api_key(session, args.secret_name),
        timeout_seconds=30.0,
    )

    print("\n2. submitting the presigned URL to Detect v2")
    run_id = client.deidentify_file_url(signed, "txt", build_file_configuration())
    print(f"  runId={run_id}")

    print("\n3. polling")
    import time

    deadline = time.monotonic() + 180
    result = client.wait_for_run(run_id, lambda: deadline - time.monotonic(), reserve_seconds=1.0)
    print(f"  status={result.status} {result.message}")
    for out in result.outputs:
        print(f"    {out.file_type or '(untyped)'}.{out.extension}")

    if not result.succeeded:
        sys.exit("Run did not succeed.")

    document = result.first_document()
    if document is None:
        sys.exit("Run succeeded but returned no document output.")

    print("\n4. fetching the de-identified file")
    with urllib.request.urlopen(document.url, timeout=60) as resp:
        body = resp.read().decode("utf-8", "replace")
    print("-" * 60)
    print(body[:2000])
    print("-" * 60)

    leaked = [v for v in ("Priya", "Raman", "priya.raman@example.net", "555-0188") if v in body]
    if leaked:
        print(f"\nSTILL PRESENT IN OUTPUT: {leaked}")
    else:
        print("\nNone of the seeded PII values survive in the output.")


if __name__ == "__main__":
    main()
