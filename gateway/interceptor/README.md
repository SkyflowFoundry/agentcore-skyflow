# Skyflow interceptor

De-identifies tool-call arguments on the way out and re-identifies tool results
on the way back, conditionally per server and per tool.

Port of [`SkyflowFoundry/context-forge-skyflow`](https://github.com/SkyflowFoundry/context-forge-skyflow)
onto AgentCore Gateway. The Context Forge plugin ran in-process on
`tool_pre_invoke` / `tool_post_invoke`; here the same two hook points are
AgentCore's REQUEST and RESPONSE interceptors, backed by one Lambda.

```
Flow (agent)
   │ MCP
   ▼
┌──────────────── Gateway ────────────────┐
│  REQUEST  interceptor ──► Skyflow de-identify
│      │                                  │
│      ▼                                  │
│   target: exa ──► https://mcp.exa.ai/mcp│
│      │                                  │
│  RESPONSE interceptor ──► Skyflow re-identify
└─────────────────────────────────────────┘
```

## Layout

```
interceptor/
├── src/                    # Lambda source — stdlib + boto3 only, no bundling
│   ├── handler.py          # entry point; dispatches REQUEST vs RESPONSE
│   ├── policy.py           # policy model, matching, validation
│   ├── payload.py          # find and rewrite eligible strings
│   ├── skyflow_client.py   # Detect string endpoints, retry/backoff
│   └── settings.py         # SSM policy + Secrets Manager key, both cached
├── config/policy.json      # the redaction policy — source of truth
├── cdk/                    # standalone CDK app (Lambda + SSM parameter)
└── tests/                  # offline tests; no AWS, no Skyflow
```

The Lambda has **no third-party dependencies**. `boto3` ships with the runtime
and everything else is stdlib, so there is no layer, no bundling step, and
`cdk deploy` uploads `src/` as-is. That is why this uses dataclasses rather than
the pydantic models of the Context Forge original.

## Policy

Lives in `config/policy.json`, published to SSM, re-read by the Lambda once its
cache TTL expires (default 60s) — so a rule change takes effect without
redeploying the function.

```json
{
  "defaults": {
    "request":  { "action": "deidentify", "tokenType": "vault_token" },
    "response": { "action": "reidentify" },
    "entities": ["name", "email_address", "phone_number"],
    "scope":    { "minLength": 8, "includeKeys": ["*"], "excludeKeys": ["api_key"] },
    "failure":  { "onError": "fail_closed" }
  },
  "toolNameSeparator": "___",
  "overrides": [
    { "servers": ["exa"], "tools": ["get_code_context*"],
      "request": { "action": "none" }, "response": { "action": "none" } }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `action` | `deidentify`, `reidentify`, or `none` |
| `tokenType` | `vault_token` (persisted, restorable) or `counter` (ephemeral, **one-way**) |
| `entities` | Skyflow Detect entity types to look for |
| `scope` | Which strings are eligible: key globs plus a minimum length |
| `failure.onError` | `fail_closed` blocks the call; `fail_open` passes the original through |
| `overrides` | `servers` **and** `tools` fnmatch globs; first match wins; whole sub-blocks replace |

### The two directions

**Shield the tool** — `request: deidentify`, `response: reidentify`. The agent
sees real data; the upstream never does. This is the default here, because it
round-trips and is therefore verifiable end to end.

**Shield the model** — `response: deidentify`, `request: reidentify`. The tool
sees real data; the model context never does. Useful when results carry PII the
agent has no need to read — the shipped policy applies this to Exa's `crawling`
and `company_research` tools, whose results are scraped web content.

### Validation rule

Re-identify only resolves **vault tokens**. Counter tokens cannot be reversed,
so a policy that mints `counter` in one direction and re-identifies in the other
is rejected at load — by `put_policy.py` before it reaches SSM, and by the
Lambda if it somehow gets there.

## Deploy

One-time: store the long-lived Skyflow API key.

```bash
aws secretsmanager create-secret \
  --name skyflow/detect-api-key \
  --secret-string '<SKYFLOW_API_KEY>' \
  --region us-east-1
```

Then:

```bash
# 1. gateway and its targets
agentcore deploy --target dev -y

# 2. interceptor Lambda + policy parameter
cd gateway/interceptor/cdk
cp cdk.context.json.example cdk.context.json   # fill in your vault URL and ID
npm install && npm run build
npx cdk deploy --require-approval never

# 3. attach it to the gateway (also grants the gateway role invoke
#    on the Lambda and read on the project's config bundles)
#    Note the gateway name is prefixed with the project name.
python3 scripts/attach_interceptor.py \
  --gateway-name agentflow-SkyflowGateway \
  --function-arn <InterceptorFunctionArn from step 2> \
  --region us-east-1
```

Account and region come from `agentcore/aws-targets.json`, so the Lambda always
lands in the same region as the gateway. Override with `-c account= -c region=`.

Vault identifiers live in `cdk.context.json`, which is gitignored — they are not
credentials, but they name real infrastructure and do not belong in a shared
repo. `cdk.context.json.example` is the template. The Skyflow API key is never
in either file; it lives only in Secrets Manager, referenced by the
`skyflowSecretName` in `cdk.json`.

Scripts that call AWS need `botocore[crt]` alongside boto3 when the credential
chain uses the login provider:

```bash
uv run --with boto3 --with 'botocore[crt]' python scripts/attach_interceptor.py ...
```

That ephemeral environment can still fail to refresh an `aws login` session
(`CreateOAuth2Token ... authorization grant is invalid, expired, revoked, or
malformed`) even while the AWS CLI works. The agent's own virtualenv has both
packages at versions known to refresh correctly, so it is the reliable option:

```bash
app/Flow/.venv/bin/python scripts/attach_interceptor.py ...
```

## Seeing what the upstream server actually received

`logUpstreamPayloads` logs the two snapshots that carry tokens rather than
original values:

- the request **after** de-identification — literally the bytes the gateway
  sends upstream;
- the response **before** re-identification — what the upstream sent back.

The other two forms are never logged, and that is the whole safety argument:
the inbound request is raw user data, and the outbound response has the
original values restored.

It is a policy field, so it flips without a redeploy:

```bash
# gateway/interceptor/config/policy.json
"defaults": { ..., "logUpstreamPayloads": true }

python3 scripts/put_policy.py          # picked up within the cache TTL, 60s
```

Scope it to one tool instead of everything with an override:

```json
{"servers": ["exa"], "tools": ["web_search_exa"], "logUpstreamPayloads": true}
```

Read it back:

```bash
aws logs filter-log-events \
  --log-group-name <interceptor log group> \
  --filter-pattern upstream_request \
  --region us-east-1 --query 'events[].message' --output text
```

```
upstream_request server=exa tool=web_search_exa payload={"query":
  "[NAME_AJbrIud] [EMAIL_ADDRESS_nJFlbfH] [PHONE_NUMBER_VVwjCfV]
   [LOCATION_y3wQt7I] product launch", "objective": "Find coverage of the
   launch by the person named in the query"}
```

Two limits worth stating plainly:

- **Tokenized is not the same as safe.** The payload is only as redacted as
  detection was complete. Anything Skyflow did not recognize is in the log in
  the clear, so this is a debugging aid rather than a guarantee.
- **Nothing is logged when the action is `none`.** With no transform the
  "upstream" payload *is* the original, so logging it would write user data to
  CloudWatch. `Policy.should_log_upstream` enforces that, not the caller.

Log retention on the interceptor group is one week.

## Verify a live gateway

`scripts/mcp_call.py` speaks MCP to the gateway with SigV4 auth:

```bash
uv run --with boto3 --with 'botocore[crt]' python scripts/mcp_call.py tools/list --names-only
uv run --with boto3 --with 'botocore[crt]' python scripts/mcp_call.py tools/call \
  --name exa___web_search_exa --arguments '{"query": "...", "objective": "..."}'
```

To see exactly what the upstream receives, invoke the function directly with a
synthetic interceptor event — the output holds tokens rather than real values,
so it is safe to read:

```bash
aws lambda invoke --region us-east-1 --function-name <fn> \
  --cli-binary-format raw-in-base64-out --payload file://event.json out.json
```

The interceptor deliberately never logs payloads, so CloudWatch shows which
action ran and how many fields changed, but not their contents.

## Iterating on policy

```bash
python3 scripts/put_policy.py --dry-run     # validate and print the effective rules
python3 scripts/put_policy.py --region us-east-1
```

## Tests

Offline, stdlib `unittest`, no AWS and no Skyflow. Fakes stand in for the Detect
client and both boto3 clients, so every assertion is deterministic.

```bash
uv run --with boto3 python -m unittest discover \
  -s gateway/interceptor/tests -t gateway/interceptor/tests
```

| Suite | Covers |
| --- | --- |
| `test_handler.py` | Dispatch, direction routing, overrides, fail-closed/open, streaming, round trip |
| `test_policy.py` | Parsing, scope globs, override precedence, tool-name splitting, validation |
| `test_payload.py` | Traversal, write-back, non-mutation, parallelism and its cap, error propagation |
| `test_skyflow_client.py` | Request shape, retry and backoff, and that error bodies never leak |
| `test_settings.py` | Policy cache TTL, API key parsing, lazy boto3 construction |

Each file also runs standalone (`python3 tests/test_policy.py`).

CI runs these on every push and PR via `.github/workflows/tests.yml`, alongside
the hook tests, policy validation, and a CDK typecheck plus credential-free
synth that asserts the Lambda bundle still carries no dependencies.

## Tool naming

Confirmed against a live gateway: targets namespace their tools with `___`, so
`exa___web_search_exa` resolves to server `exa`, tool `web_search_exa`.

The gateway's own semantic tool-search, `x_amz_bedrock_agentcore_search`, has
**no** server prefix and therefore resolves to server `""`. The shipped policy
excludes it explicitly — its arguments are a query over tool descriptions, and
tokenizing those would break tool discovery.

## Known gaps

- **One Skyflow call per eligible string.** Fields within a payload are
  redacted in parallel (up to 8), but a wide payload still costs several calls.
- **Streaming is untested.** The handler omits headers and status on streaming
  events as the docs require, but this has not been exercised against a
  streaming gateway. Leave streaming off initially.
- **`counter` tokens are unused in practice.** Every shipped rule mints
  `vault_token`s, which persist in the vault. Nothing prunes them.
