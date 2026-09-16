"""AgentCore Gateway interceptor: Skyflow de-identify on the way out, re-identify on the way back.

One Lambda serves both interception points. A gateway allows at most one REQUEST
and one RESPONSE interceptor, and both are configured against this same ARN with
`interceptionPoints: ["REQUEST", "RESPONSE"]`. The two paths are distinguished by
the presence of `gatewayResponse` in the event, exactly as the AWS pass-through
example does.

Payload shapes (see gateway-interceptors-types in the AgentCore docs):

- MCP targets   -> `event["mcp"]`, bodies are parsed JSON-RPC objects.
- HTTP targets  -> `event["http"]`, bodies are base64-encoded strings. This
  covers AgentCore Runtime targets, `passthrough` targets, and inference
  targets. Not handled here: prefer an `mcpServer` target so tool calls arrive
  as parsed MCP. HTTP events pass through untouched.

Behaviour worth knowing:

- Only `tools/call` is transformed. `tools/list`, `initialize` and friends pass
  through — a tool schema is not user data.
- On MCP, a REQUEST short circuit still invokes the RESPONSE interceptor (unlike
  HTTP, which skips it). The response path therefore tolerates an error body
  with no `result`.
- With response streaming enabled the RESPONSE interceptor fires once per
  JSON-RPC event. Each event is transformed independently; only the first may
  set headers or status code, so this function never returns them.
"""

from __future__ import annotations

import json
import logging
import os

import payload as payload_utils
import settings
from policy import Policy, PolicySet
from skyflow_client import SkyflowClient, SkyflowError

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

OUTPUT_VERSION = "1.0"
JSONRPC_INTERNAL_ERROR = -32603

#: Cap on a logged payload. A web search result runs to tens of kilobytes and
#: the point is to see the shape and the tokens, not to archive the body.
MAX_LOGGED_PAYLOAD = 4000


# ---------------------------------------------------------------- entry point


def lambda_handler(event: dict, context) -> dict:
    """Dispatch on payload shape, then on interception point."""
    if "mcp" in event:
        mcp = event.get("mcp") or {}
        if mcp.get("gatewayResponse"):
            return _on_response(mcp)
        return _on_request(mcp)

    if "http" in event:
        # AgentCore Runtime, passthrough and inference targets. Bodies are
        # base64 and carry no MCP framing, so there is no tool identity to
        # match policy against. Pass through rather than guess.
        logger.info("http_payload_passthrough")
        return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {}}

    logger.warning("unknown_payload_shape keys=%s", sorted(event.keys()))
    return {"interceptorOutputVersion": OUTPUT_VERSION, "mcp": {}}


# ------------------------------------------------------------- request path


def _on_request(mcp: dict) -> dict:
    body = (mcp.get("gatewayRequest") or {}).get("body") or {}

    if body.get("method") != "tools/call":
        return _pass_request(body)

    params = body.get("params") or {}
    qualified_name = params.get("name") or ""
    arguments = params.get("arguments")

    if not isinstance(arguments, (dict, list)):
        return _pass_request(body)

    try:
        policy_set = settings.load_policy()
    except Exception:
        logger.exception("policy_load_failed direction=request tool=%s", qualified_name)
        # No policy means no informed decision. Blocking is the safe default;
        # this mirrors fail_closed and cannot be overridden by config, because
        # the config itself is what failed to load.
        return _short_circuit(body, "Interceptor policy unavailable")

    server, tool = policy_set.split_tool_name(qualified_name)
    policy = policy_set.resolve(server, tool)
    action = policy.request.action

    logger.info(
        "request_intercept server=%s tool=%s action=%s token_type=%s",
        server, tool, action, policy.request.token_type,
    )

    if action == "none":
        return _pass_request(body)

    try:
        transformed, count = _apply(arguments, policy, policy.request.action, policy.request.token_type)
    except SkyflowError as exc:
        return _on_failure_request(body, policy, exc, server, tool)
    except Exception as exc:  # defensive: never leak an unhandled trace to the caller
        logger.exception("request_transform_error server=%s tool=%s", server, tool)
        return _on_failure_request(body, policy, exc, server, tool)

    logger.info("request_transformed server=%s tool=%s fields=%d", server, tool, count)
    if policy.should_log_upstream(action):
        _log_upstream("request", server, tool, transformed)

    new_body = dict(body)
    new_body["params"] = {**params, "arguments": transformed}
    return _pass_request(new_body)


def _on_failure_request(body: dict, policy: Policy, exc: Exception, server: str, tool: str) -> dict:
    if policy.failure.on_error == "fail_open":
        logger.warning("request_fail_open server=%s tool=%s err=%s", server, tool, exc)
        return _pass_request(body)
    logger.error("request_fail_closed server=%s tool=%s err=%s", server, tool, exc)
    return _short_circuit(body, "Sensitive-data processing failed; call blocked")


# ------------------------------------------------------------ response path


def _on_response(mcp: dict) -> dict:
    gateway_response = mcp.get("gatewayResponse") or {}
    body = gateway_response.get("body") or {}
    request_body = (mcp.get("gatewayRequest") or {}).get("body") or {}

    streaming = bool(gateway_response.get("isStreamingResponse"))

    if request_body.get("method") != "tools/call":
        return _pass_response(gateway_response, streaming)

    result = body.get("result")
    if not isinstance(result, (dict, list)):
        # An error body, or our own REQUEST short circuit coming back around.
        # Nothing to redact, and no result to damage.
        return _pass_response(gateway_response, streaming)

    params = request_body.get("params") or {}
    qualified_name = params.get("name") or ""

    try:
        policy_set = settings.load_policy()
    except Exception:
        logger.exception("policy_load_failed direction=response tool=%s", qualified_name)
        return _error_response(body, "Interceptor policy unavailable", streaming)

    server, tool = policy_set.split_tool_name(qualified_name)
    policy = policy_set.resolve(server, tool)
    action = policy.response.action

    logger.info(
        "response_intercept server=%s tool=%s action=%s streaming=%s",
        server, tool, action, streaming,
    )

    if action == "none":
        return _pass_response(gateway_response, streaming)

    # Before the transform, not after: this is the form the upstream server
    # returned, still carrying tokens. The transformed version has the original
    # values back in it and must never reach a log.
    if policy.should_log_upstream(action):
        _log_upstream("response", server, tool, result)

    try:
        transformed, count = _apply(result, policy, policy.response.action, policy.response.token_type)
    except SkyflowError as exc:
        return _on_failure_response(gateway_response, body, policy, exc, server, tool, streaming)
    except Exception as exc:
        logger.exception("response_transform_error server=%s tool=%s", server, tool)
        return _on_failure_response(gateway_response, body, policy, exc, server, tool, streaming)

    logger.info("response_transformed server=%s tool=%s fields=%d", server, tool, count)

    new_body = dict(body)
    new_body["result"] = transformed
    return _build_response(new_body, gateway_response, streaming)


def _on_failure_response(
    gateway_response: dict,
    body: dict,
    policy: Policy,
    exc: Exception,
    server: str,
    tool: str,
    streaming: bool,
) -> dict:
    if policy.failure.on_error == "fail_open":
        logger.warning("response_fail_open server=%s tool=%s err=%s", server, tool, exc)
        return _pass_response(gateway_response, streaming)

    # Note the asymmetry: a failed `deidentify` here would leak real data if
    # passed through, whereas a failed `reidentify` would only return tokens.
    # fail_closed blocks both so the behaviour stays predictable; set
    # `failure.onError` to fail_open per-tool where returning tokens is fine.
    logger.error("response_fail_closed server=%s tool=%s err=%s", server, tool, exc)
    return _error_response(body, "Sensitive-data processing failed; response withheld", streaming)


# ----------------------------------------------------------------- transform


def _log_upstream(direction: str, server: str, tool: str, node) -> None:
    """Log the upstream-facing form of a payload.

    Callers must gate this on `Policy.should_log_upstream`, which is what knows
    whether the payload is the tokenized side. This function only serializes.
    """
    try:
        rendered = json.dumps(node, default=str)[:MAX_LOGGED_PAYLOAD]
    except Exception:  # noqa: BLE001 - a diagnostic must not break the call
        rendered = "<unserializable>"
    logger.info("upstream_%s server=%s tool=%s payload=%s", direction, server, tool, rendered)


def _apply(node, policy: Policy, action: str, token_type: str):
    """Run one Skyflow action across every in-scope string in `node`."""
    client: SkyflowClient = settings.build_client()

    if action == "deidentify":
        vault_entities = policy.entities if token_type == "vault_token" else None

        def transform(text: str) -> str:
            return client.deidentify(text, policy.entities, vault_entities).processed_text

    elif action == "reidentify":

        def transform(text: str) -> str:
            return client.reidentify(text).text

    else:
        raise ValueError(f"unsupported action {action!r}")

    return payload_utils.transform_strings(node, policy.scope, transform)


# ------------------------------------------------------------ output helpers


def _pass_request(body: dict) -> dict:
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {"transformedGatewayRequest": {"body": body}},
    }


def _build_response(body: dict, gateway_response: dict, streaming: bool) -> dict:
    transformed: dict = {"body": body}
    # Subsequent streaming events have already sent headers and status to the
    # client; returning them is ignored, so omit them entirely.
    if not streaming:
        transformed["statusCode"] = gateway_response.get("statusCode", 200)
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {"transformedGatewayResponse": transformed},
    }


def _pass_response(gateway_response: dict, streaming: bool) -> dict:
    return _build_response(gateway_response.get("body") or {}, gateway_response, streaming)


def _jsonrpc_error(body: dict, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": body.get("id"),
        "error": {"code": JSONRPC_INTERNAL_ERROR, "message": message},
    }


def _short_circuit(request_body: dict, message: str) -> dict:
    """Answer the caller directly without calling the target.

    The gateway responds with this immediately. On MCP the RESPONSE interceptor
    is still invoked afterwards, which `_on_response` handles by finding no
    `result` and passing through.
    """
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {
            "transformedGatewayResponse": {
                "statusCode": 200,
                "body": _jsonrpc_error(request_body, message),
            }
        },
    }


def _error_response(body: dict, message: str, streaming: bool) -> dict:
    transformed: dict = {"body": _jsonrpc_error(body, message)}
    if not streaming:
        transformed["statusCode"] = 200
    return {
        "interceptorOutputVersion": OUTPUT_VERSION,
        "mcp": {"transformedGatewayResponse": transformed},
    }
