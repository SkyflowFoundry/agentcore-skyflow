#!/usr/bin/env python3
"""Create the document bucket the `s3` gateway target reads from.

Nothing else creates it. The AgentCore CLI has no bucket resource and the
interceptor stack does not own documents, so this is a deploy step of its own:

    python3 scripts/create_documents_bucket.py --region us-east-1
    python3 scripts/create_documents_bucket.py --region us-east-1 --upload-samples

The name defaults to `agentcore-skyflow-files-<account>`, which is what the
`s3` target derives when the SSM parameter `/agentcore/s3-target/bucket` is not
set, and what the shipped policy's `urlPatterns` match. Pass `--bucket` to use
another name and set that parameter to match.

Public access is blocked. The whole design is that documents are reached by
presigned URL only: the target presigns them for the interceptor, and Skyflow
returns the de-identified copy from its own bucket.

Re-running is safe: an existing bucket is left as it is.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

DEFAULT_BUCKET_PREFIX = "agentcore-skyflow-files-"
SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def ensure_bucket(s3, bucket: str, region: str) -> bool:
    """Create `bucket` with public access blocked. Returns True if created."""
    try:
        s3.head_bucket(Bucket=bucket)
        print(f"  bucket {bucket} exists")
        return False
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("404", "NoSuchBucket", "NotFound"):
            raise

    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        # us-east-1 rejects a LocationConstraint; every other region needs one.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)
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
    return True


def upload_samples(s3, bucket: str) -> None:
    """Upload the synthetic sample documents under `samples/`."""
    for path in sorted(SAMPLES.iterdir()):
        if not path.is_file() or path.name == "README.md":
            continue
        key = f"samples/{path.name}"
        s3.upload_file(str(path), bucket, key)
        print(f"  uploaded s3://{bucket}/{key}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--region", default=None)
    parser.add_argument("--bucket", default=None, help=f"defaults to {DEFAULT_BUCKET_PREFIX}<account>")
    parser.add_argument(
        "--upload-samples",
        action="store_true",
        help="also upload samples/ so the demo prompts work straight away",
    )
    args = parser.parse_args()

    session = boto3.Session(region_name=args.region) if args.region else boto3.Session()
    region = session.region_name
    if not region:
        parser.error("no region: pass --region or configure a default")

    bucket = args.bucket or f"{DEFAULT_BUCKET_PREFIX}{session.client('sts').get_caller_identity()['Account']}"
    s3 = session.client("s3")

    print(f"Document bucket in {region}:")
    ensure_bucket(s3, bucket, region)
    if args.upload_samples:
        upload_samples(s3, bucket)

    if args.bucket:
        print(
            "\nThe s3 target derives a different name by default. Point it here with:\n"
            f"  aws ssm put-parameter --name /agentcore/s3-target/bucket --type String "
            f"--value {bucket} --region {region} --overwrite\n"
            "and update files.urlPatterns in gateway/interceptor/config/policy.json to match."
        )


if __name__ == "__main__":
    main()
