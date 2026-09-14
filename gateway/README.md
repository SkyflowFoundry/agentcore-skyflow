# Gateway

Source for AgentCore Gateway targets — the Lambda / AgentCore-Runtime functions that back
custom tools, and any proxy or interception logic sitting between an agent and an upstream
MCP server.

Gateways themselves are **declared** in `agentcore/agentcore.json` under `agentCoreGateways[]`.
This directory only holds the *code* those declarations point at, via
`targets[].compute.implementation.path`.

```
gateway/
└── targets/
    └── <target-name>/     # one dir per code-backed target
```

## Four seams for proxying / intercepting MCP tool calls

Schema reference: `agentcore/.llm-context/agentcore.ts`.

### 1. `mcpServer` target — front an existing MCP server

`AgentCoreGatewayTarget.targetType: 'mcpServer'` + `endpoint` + `outboundAuth`
(`agentcore.ts:372`). The gateway registers the upstream server's tools as its own and
handles outbound credentials from the Token Vault. You get auth, logging, and policy
enforcement for free. **No code, no mutation** — calls pass through unchanged.

### 2. `passthrough` target — transparent proxy

`targetType: 'passthrough'` + `PassthroughConfig { endpoint, protocolType: 'MCP', stickinessConfiguration }`
(`agentcore.ts:494`). Thinner than `mcpServer`: the gateway forwards the MCP protocol
wholesale rather than modelling individual tools. `stickinessConfiguration` pins a caller to
one upstream session. **No code, no mutation.**

### 3. Code target — full intercept (read *and* rewrite)

This is the one to reach for when you need to see and change requests and responses.

`targetType: 'lambda'`, with `toolDefinitions[]` describing the tool surface you expose and
`compute` pointing at your handler:

- `LambdaComputeConfig` — `host: 'Lambda'`, `implementation: { language: 'TypeScript' | 'Python', path, handler }`,
  plus `timeout`, `memorySize`, `iamPolicy` (`agentcore.ts:403`)
- `AgentCoreRuntimeComputeConfig` — `host: 'AgentCoreRuntime'`, Python only, for
  longer-running or stateful interceptors (`agentcore.ts:414`)

Your handler receives the tool call, does whatever it likes — redact arguments, call the real
upstream MCP server, filter or transform the response, emit telemetry — and returns the
result. `path` is relative to the project root, so point it at `gateway/targets/<name>/`.

### 4. Policy engine — gate without touching the payload

`AgentCoreGateway.policyEngineConfiguration: { policyEngineName, mode: 'LOG_ONLY' | 'ENFORCE' }`
(`agentcore.ts:354`), with the engine and its Cedar policies declared in `policyEngines[]`
(`agentcore.ts:515`). Allow/deny decisions on tool invocation. Cannot rewrite a call — pair it
with seam 3 when you need both.

Start in `LOG_ONLY` to see what would have been blocked before switching to `ENFORCE`.

## Adding a gateway

```bash
agentcore add gateway
agentcore add gateway-target
agentcore validate
agentcore deploy
agentcore fetch access          # gateway URL + token for MCP_ENDPOINTS / MCP_BEARER_TOKEN
```
