# Gateway

Code for AgentCore Gateway: the **interceptors** that run on every invocation,
and the functions that back code-defined **targets**.

Gateways and their targets are declared in `agentcore/agentcore.json` under
`agentCoreGateways[]`. Interceptors are not — see below.

```
gateway/
├── interceptor/        # Skyflow de-identify / re-identify interceptor
└── targets/
    └── s3/             # documents in S3, returned as presigned URLs
```

The `s3` target exists so the interceptor has real documents to work on. Its
`get_document` tool returns a presigned URL rather than the bytes, which is what
S3 and Box and Google Drive all do, and which is the case the file rule handles.
Returning bytes would cap document size at the Lambda response limit and would
hand the agent the original content.

## Interceptors — the pre/post hook

A gateway can run a Lambda on every invocation, at two points:

- **REQUEST** — before the gateway calls the target. Validate, transform, or
  authorize. Returning a `transformedGatewayResponse` short-circuits the call.
- **RESPONSE** — after the target responds, before the caller sees it. Filter,
  redact, or rewrite.

Both can **modify** the payload, not merely allow or deny it. At most one of
each per gateway, and one Lambda can serve both by listing
`interceptionPoints: ["REQUEST", "RESPONSE"]`.

### Interceptors cannot be declared in `agentcore.json`

The AgentCore CLI has no field for them, so `agentcore/cdk/lib/cdk-stack.ts`
sets `InterceptorConfigurations` on the gateway's CloudFormation resource
directly. An interceptor attached only by calling `update-gateway` does not
survive: the next change to any gateway property makes CloudFormation send
`UpdateGateway` without it. The order is:

```bash
cd gateway/interceptor/cdk && npm run cdk deploy -- ...   # creates the Lambda and exports its ARN
agentcore deploy                                          # creates the gateway with the interceptor attached
python3 scripts/attach_interceptor.py --gateway-name agentflow-SkyflowGateway --check
```

The gateway's **service role** needs `lambda:InvokeFunction` on the interceptor
function — an identity-based grant, not a Lambda resource policy. Scope it to
the specific function ARN, never a wildcard. The same CDK stack grants it.

### Payload shape depends on the target type

This catches people out. The interceptor receives one of two shapes:

| Target types | Event key | Body format |
| --- | --- | --- |
| `lambda`, `mcpServer`, `openApiSchema`, `smithyModel`, `apiGateway` | `mcp` | Parsed JSON-RPC object |
| `httpRuntime` (AgentCore Runtime), `passthrough`, inference | `http` | Base64-encoded string |

To front an external MCP server, prefer **`mcpServer`** over `passthrough`.
Both reach the same upstream, but `passthrough` delivers the `http` shape —
base64 bodies with no MCP framing, so there is no tool name or arguments to
match a policy against. The interceptor blocks `http`-shaped calls unless the
policy sets `httpPayloads.action` to `passthrough`; see
`interceptor/README.md`. Inference targets are the exception. The policy's
`inference` block shields the model calls they carry, because a model request
has a known shape even without MCP framing.

Other behaviour worth knowing:

- Every MCP method arrives at the same handler, `tools/list` included. Dispatch
  on `body.method`; a tool schema is not user data.
- On MCP, a REQUEST short-circuit **still invokes** the RESPONSE interceptor.
  On HTTP it does not.
- With response streaming enabled, RESPONSE fires once per JSON-RPC event and
  only the first may set headers or status code.
- Lambda synchronous invocation caps request and response at 6 MB combined.
  `payloadFilter` can drop `RESPONSE_BODY`, but only for the `http` shape.
- Headers are withheld unless `passRequestHeaders` is true. Leave it off unless
  needed — headers carry bearer tokens. The Skyflow interceptor blanks
  credential headers from the event on entry either way, so turning it on
  cannot put a caller's token in its log group.
- The gateway may retry an interceptor, so handlers must be idempotent.

## Targets — where tools come from

Declared in `agentCoreGateways[].targets[]` (`agentcore/.llm-context/agentcore.ts:372`).

| Target type | Use |
| --- | --- |
| `mcpServer` | Front an existing MCP server, with outbound auth from the Token Vault |
| `lambda` | Your own tool implementation; `compute.implementation.path` points into `targets/` |
| `openApiSchema` / `smithyModel` / `apiGateway` | Expose an existing API as tools |
| `httpRuntime` | An AgentCore Runtime in this project, by name |
| `passthrough` | Transparent proxy; see the payload-shape caveat above |
| `connector` | Managed `web-search` or `bedrock-knowledge-bases` |

Code-backed targets run on either `LambdaComputeConfig`
(`agentcore.ts:405`) or `AgentCoreRuntimeComputeConfig` (`agentcore.ts:415`).

## Calling the gateway from an agent

An in-project gateway reaches every runtime in the project automatically — no
`connections[]` entry required. Deploy injects `AGENTCORE_GATEWAY_<NAME>_URL`
and `AGENTCORE_GATEWAY_<NAME>_AUTH_TYPE` into each runtime's environment and
grants the execution role `bedrock-agentcore:InvokeGateway` on the gateway ARN.
A gateway in another project or account is reached the same way through a
runtime `connections[]` entry, which injects `GATEWAY_<ID>_*` instead.

With `authorizerType: AWS_IAM` there is no token to fetch, store or rotate: the
agent SigV4-signs each request for service `bedrock-agentcore`. The signing
region comes from the gateway host rather than `AWS_REGION`, because a gateway
reached over a connection can live in another region and a signature is only
valid for the region that serves it.

Signing is attached as an httpx auth hook
(`app/Flow/mcp_client/sigv4.py`), not as pre-computed headers — one MCP
connection sends several requests (the handshake POST, `notifications/initialized`,
each `tools/call`, the SSE GET, the terminating DELETE) and every one needs its
own signature over its own body.

`agentcore fetch access` returns the URL and, for a JWT gateway, a token. The
IAM case needs neither.

Setting `MCP_ENDPOINTS` replaces discovery outright. That is how you point the
agent straight at an upstream server to compare behaviour with the gateway —
and its interceptors — taken out of the path.

### The gateway needs to read the caller's config bundle

When a caller that has a ConfigBundle invokes a gateway, the gateway fetches
that bundle to resolve tool descriptions. The gateway's service role, as the
AgentCore CDK creates it, cannot, and `tools/list` fails:

```
HTTP 400 {"error":{"code":-32600,"message":"Config bundle fetch failed: ...
is not authorized to perform: bedrock-agentcore:GetConfigurationBundleVersion ..."}}
```

The *runtime* role gets this permission; the *gateway* role does not.
`agentcore/cdk/lib/cdk-stack.ts` grants it on the project's config bundles
alongside the Lambda invoke grant. A project with no config bundle skips it.

Worth knowing how this hides: a caller with no config bundle — an IAM user
running `scripts/mcp_call.py`, say — triggers no fetch at all, so the gateway
looks healthy from every direction except the one that matters. It only appears
once a runtime calls it.

Strands also reports it as `Connection to the MCP server was closed`, which is
why `mcp_client/diagnostics.py` logs the body of any 4xx or 5xx from an MCP
endpoint. Without that the status code never reaches the log. The body is
masked first: a SigV4 signature mismatch is answered with the canonical
request, which lists every signed header with its value, the caller's session
token among them, so credential-shaped content is replaced with `<redacted>`
before the line is written.

To exercise that client against the live gateway without deploying:

```bash
app/Flow/.venv/bin/python scripts/flow_mcp_check.py
app/Flow/.venv/bin/python scripts/flow_mcp_check.py \
    --call exa___web_search_exa \
    --arguments '{"query": "...", "objective": "..."}'
```

It imports the agent's own `mcp_client` package, so it covers discovery,
credential choice and signing rather than re-implementing them the way
`scripts/mcp_call.py` does.

## Poking at it with the MCP Inspector

The [MCP Inspector](https://modelcontextprotocol.io/docs/2026-07-28/tools/inspector)
can send static headers but cannot SigV4-sign, and a signature covers the
request body, so no fixed header works against an `AWS_IAM` gateway.
`scripts/gateway_proxy.py` bridges the gap: it listens on loopback, signs each
request with `mcp_client.sigv4` — the agent's own signer — and forwards.

Inspector needs Node 22.19 or newer; `nvm use 24` is enough.

```bash
# terminal 1
app/Flow/.venv/bin/python scripts/gateway_proxy.py

# terminal 2
npx @modelcontextprotocol/inspector --server-url http://127.0.0.1:8090/mcp --transport http
```

The CLI client is the quickest way to check a change:

```bash
npx @modelcontextprotocol/inspector --cli \
  --server-url http://127.0.0.1:8090/mcp --transport http \
  --method tools/call --tool-name exa___web_search_exa \
  --tool-arg 'query=...' --tool-arg 'objective=...'
```

Two things to keep in mind:

- **The proxy signs as you, not as the runtime.** Credentials come from
  botocore's default chain, so Inspector exercises your IAM identity while the
  deployed agent uses its execution role. A call that works in Inspector can
  still fail in the agent.
- **It has no authentication of its own.** Anyone who can reach the port calls
  the gateway with your credentials, which is why it refuses to bind anything
  but loopback. Stop it when you are done.

Inspector opens an SSE stream with `GET /mcp`, which this gateway answers 405.
That is expected and harmless — responses come back on the POST instead.

## Policy engine — allow/deny

`AgentCoreGateway.policyEngineConfiguration` (`agentcore.ts:354`) binds a Cedar
policy engine in `LOG_ONLY` or `ENFORCE` mode, with policies declared in
`policyEngines[]` (`agentcore.ts:515`). Cedar decides whether a call proceeds; it
cannot rewrite a payload. Pair it with an interceptor when you need both.

Start in `LOG_ONLY` to see what would have been blocked.

## Adding a gateway

```bash
agentcore add gateway
agentcore add gateway-target
agentcore validate
agentcore deploy
agentcore fetch access          # gateway URL + token
```
