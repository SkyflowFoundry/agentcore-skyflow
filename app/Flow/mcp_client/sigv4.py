"""SigV4 request signing for httpx, so the agent can reach an AWS_IAM gateway.

A gateway created with `authorizerType: AWS_IAM` accepts SigV4-signed requests
only — there is no bearer token to inject, and no token to rotate. Signing is
attached as an httpx auth hook rather than as pre-computed headers because the
MCP transport sends several requests over a connection's life (the handshake
POST, the `initialized` notification, each `tools/call`, the SSE GET and the
terminating DELETE) and every one has to carry its own signature over its own
body.
"""

from __future__ import annotations

import logging
from collections.abc import Generator

import httpx
from botocore.auth import SigV4Auth as BotocoreSigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import Session, get_session

logger = logging.getLogger(__name__)

#: Signing name for AgentCore Gateway, per the service model.
SERVICE = "bedrock-agentcore"


class SigV4Auth(httpx.Auth):
    """Sign outgoing requests with the caller's AWS credentials."""

    # The canonical request hashes the payload, so httpx has to have read the
    # request body before auth_flow runs.
    requires_request_body = True

    def __init__(self, region: str, service: str = SERVICE, session: Session | None = None):
        self._region = region
        self._service = service
        # Held unfrozen on purpose: inside an AgentCore runtime these are
        # refreshable container credentials, and freezing once at construction
        # would pin a set that expires while the agent is still running.
        # botocore rather than boto3: botocore is a declared dependency of the
        # agent, boto3 only arrives transitively, and nothing here needs a
        # service client.
        self._credentials = (session or get_session()).get_credentials()
        if self._credentials is None:
            raise RuntimeError(
                f"No AWS credentials available to sign requests to {service} in {region}"
            )

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        aws_request = AWSRequest(
            method=request.method,
            url=str(request.url),
            data=request.content,
            headers=dict(request.headers),
        )
        BotocoreSigV4Auth(
            self._credentials.get_frozen_credentials(), self._service, self._region
        ).add_auth(aws_request)

        # add_auth contributes Authorization and X-Amz-Date, plus
        # X-Amz-Security-Token for temporary credentials. Copying the whole
        # header set back keeps the request and its signature in agreement.
        request.headers.update(dict(aws_request.headers))
        yield request
