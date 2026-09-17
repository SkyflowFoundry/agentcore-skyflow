"""S3 documents exposed as MCP tools through AgentCore Gateway.

This target exists so the interceptor has a realistic source of files to work
on. `get_document` hands back a presigned URL rather than the bytes, which is
what real document stores such as S3 and Box and Google Drive all do. The
RESPONSE interceptor then swaps that URL for one pointing at a de-identified
copy before the agent ever sees it.

The gateway invokes this function with the tool arguments as the event and the
tool name in the client context, prefixed with the target name and `___`.
Returning bytes here would defeat the whole design because the Lambda response
limit would cap document size and the agent would receive the original content.
"""

import logging
import os

import boto3
from botocore.config import Config

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TOOL_NAME_SEPARATOR = "___"
#: Optional SSM parameter naming the document bucket. Without it the bucket name
#: is derived from the account so a fresh deployment needs no setup.
BUCKET_PARAMETER = "/agentcore/s3-target/bucket"
DEFAULT_BUCKET_PREFIX = "agentcore-skyflow-files-"
DEFAULT_EXPIRES_IN = 900
MAX_EXPIRES_IN = 3600
MAX_KEYS = 100

# Presigning must use the regional SigV4 endpoint so the URL carries a
# signature the interceptor and Skyflow can both follow.
_s3 = boto3.client("s3", config=Config(signature_version="s3v4"))
_ssm = boto3.client("ssm")


_bucket_cache: dict[str, str] = {}


def bucket_name(context) -> str:
    """The document bucket, resolved once per container.

    LambdaComputeConfig has no environment block, so configuration arrives
    through SSM the same way the interceptor's policy does. The parameter is
    optional and the fallback derives a per-account name from the function ARN,
    which keeps the demo working in a fresh account with nothing to set up.
    """
    override = os.environ.get("DOCUMENTS_BUCKET")
    if override:
        return override

    account = context.invoked_function_arn.split(":")[4]
    if "value" not in _bucket_cache:
        try:
            parameter = _ssm.get_parameter(Name=BUCKET_PARAMETER)["Parameter"]["Value"]
            _bucket_cache["value"] = parameter.strip()
        except Exception:
            # A missing parameter is the normal case rather than an error.
            logger.info("no %s parameter; deriving the bucket from the account", BUCKET_PARAMETER)
            _bucket_cache["value"] = f"{DEFAULT_BUCKET_PREFIX}{account}"
    return _bucket_cache["value"]


def tool_name(context) -> str:
    """Strip the target prefix the gateway adds to every tool name."""
    raw = (context.client_context.custom or {}).get("bedrockAgentCoreToolName", "")
    if TOOL_NAME_SEPARATOR in raw:
        return raw.split(TOOL_NAME_SEPARATOR, 1)[1]
    return raw


def list_documents(bucket: str, arguments: dict) -> dict:
    prefix = arguments.get("prefix") or ""
    response = _s3.list_objects_v2(Bucket=bucket, Prefix=prefix, MaxKeys=MAX_KEYS)
    documents = [
        {
            "key": item["Key"],
            "size_bytes": item["Size"],
            "last_modified": item["LastModified"].isoformat(),
        }
        for item in response.get("Contents", [])
        if not item["Key"].endswith("/")
    ]
    return {"bucket": bucket, "prefix": prefix, "documents": documents}


def get_document(bucket: str, arguments: dict) -> dict:
    key = (arguments.get("key") or "").strip()
    if not key:
        raise ValueError("key is required")

    expires_in = int(arguments.get("expires_in") or DEFAULT_EXPIRES_IN)
    expires_in = max(1, min(expires_in, MAX_EXPIRES_IN))

    head = _s3.head_object(Bucket=bucket, Key=key)
    url = _s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expires_in,
    )
    return {
        "key": key,
        "url": url,
        "expires_in": expires_in,
        "content_type": head.get("ContentType", "application/octet-stream"),
        "size_bytes": head.get("ContentLength", 0),
    }


def lambda_handler(event, context):
    bucket = bucket_name(context)
    name = tool_name(context)
    arguments = event if isinstance(event, dict) else {}

    logger.info("tool=%s bucket=%s", name, bucket)

    if name == "list_documents":
        return list_documents(bucket, arguments)
    if name == "get_document":
        return get_document(bucket, arguments)
    raise ValueError(f"unknown tool: {name}")
