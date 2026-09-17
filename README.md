# Skyflow de-identification inside an AgentCore Gateway

This project puts Skyflow between an AI agent and the tools it calls. An Amazon
Bedrock AgentCore Gateway fronts every MCP tool server and a Lambda interceptor
rewrites each request and response as it passes through. You decide for each tool
which side is allowed to see sensitive values and the interceptor enforces that
decision in both directions.

The interceptor is the part worth reading. Everything else in this repository
exists to give it something real to sit in front of.

## Capabilities

1. **Tool arguments are de-identified before they leave AWS.** A search for a
   customer by name reaches the upstream server as `[NAME_AJbrIud]` and the
   result comes back with the real name restored before the agent reads it.
2. **The direction is configurable for each tool.** The same machinery can be
   turned around so that the tool sees real data and the model never does. That
   matters when a tool returns scraped web content full of personal data the
   agent has no reason to read.
3. **Files behind signed URLs are de-identified before the agent opens them.**
   The gateway hands the signed URL to Skyflow and swaps in a new signed URL
   pointing at a cleaned copy. The bytes never pass through our code so file size
   does not matter.
4. **Nothing in the agent knows any of this is happening.** The agent discovers
   its gateway from an injected environment variable and signs each request with
   SigV4. Pointing it at a different endpoint takes one environment variable.

## Architecture

```text
Flow (agent runtime)
   │  MCP over HTTPS, SigV4-signed
   ▼
┌──────────────────── AgentCore Gateway ────────────────────┐
│                                                           │
│   REQUEST interceptor ──────► Skyflow Detect              │
│        │                      de-identify arguments       │
│        ▼                                                  │
│   target: exa ──────────────► https://mcp.exa.ai/mcp      │
│        │                                                  │
│   RESPONSE interceptor ─────► Skyflow Detect              │
│        │                      re-identify results         │
│        │                      or de-identify a file URL   │
└────────┼──────────────────────────────────────────────────┘
         ▼
   the agent sees the result
```

One Lambda serves both interception points. It reads its policy from SSM
Parameter Store and its Skyflow API key from Secrets Manager. Both are cached
with a sixty second time to live so a policy change takes effect without a
redeploy.

## Repository layout

```text
agentcore/                  # repo root
├── agentcore/
│   ├── agentcore.json      # every resource in the project: runtime, gateway, targets, memory
│   ├── aws-targets.json    # account and region for each deployment target
│   └── cdk/                # generated CDK app; do not hand-edit
├── app/Flow/               # the agent runtime
│   ├── main.py             # entrypoint
│   ├── mcp_client/         # gateway discovery, SigV4 signing, error diagnostics
│   └── model/load.py       # Bedrock model selection
├── gateway/
│   └── interceptor/
│       ├── src/            # Lambda source: stdlib and boto3 only
│       ├── config/         # policy.json is the source of truth for redaction rules
│       ├── cdk/            # standalone CDK app for the Lambda and its SSM parameter
│       └── tests/          # offline tests that touch neither AWS nor Skyflow
├── scripts/                # attach the interceptor, publish policy, call the gateway
└── tests/flow/             # agent tests, kept outside app/ so they do not ship
```

## Prerequisites

1. Node.js 20 or later for the CDK apps.
2. Python 3.10 or later with [uv](https://docs.astral.sh/uv/getting-started/installation/).
3. AWS credentials that can deploy Lambda and SSM and IAM and AgentCore resources.
4. A Skyflow vault with Detect enabled and a long-lived API key.

## Deploying

The interceptor cannot be declared in `agentcore.json` because the AgentCore CLI
has no field for it. That forces a three step order and every step depends on the
one before it.

**Step 0 stores the Skyflow API key.** You only do this once.

```bash
aws secretsmanager create-secret \
  --name skyflow/detect-api-key \
  --secret-string '<SKYFLOW_API_KEY>' \
  --region us-east-1
```

**Step 1 creates the gateway and its targets.**

```bash
agentcore deploy --target dev -y
```

**Step 2 creates the interceptor Lambda and its policy parameter.**

```bash
cd gateway/interceptor/cdk
cp cdk.context.json.example cdk.context.json   # fill in your vault URL and vault ID
npm install && npm run build
npx cdk deploy --require-approval never
```

**Step 3 attaches the Lambda to the gateway and grants the two IAM permissions it
needs.**

```bash
python3 scripts/attach_interceptor.py \
  --gateway-name agentflow-SkyflowGateway \
  --function-arn <InterceptorFunctionArn printed by step 2> \
  --region us-east-1
```

The deployed gateway name carries the project name as a prefix so `SkyflowGateway`
becomes `agentflow-SkyflowGateway`.

Step 3 grants the gateway's service role two things. The first is
`lambda:InvokeFunction` on the interceptor so the gateway can call it. The second
is permission to read the caller's configuration bundle because `tools/list`
fails without it when the caller is a runtime.

## Policy

The policy lives at `gateway/interceptor/config/policy.json` and it is the source
of truth. Publishing it takes two commands and no redeploy.

```bash
python3 scripts/put_policy.py --dry-run          # validate and print the effective rules
python3 scripts/put_policy.py --region us-east-1 # publish to SSM
```

The Lambda picks up the change within its sixty second cache window. Validation
runs the same parser the Lambda uses so a typo fails at your terminal rather than
on a live call. CI runs the same validation on every pull request.

## Verification

`scripts/mcp_call.py` speaks MCP to the gateway with SigV4 authentication.

```bash
uv run --with boto3 --with 'botocore[crt]' python scripts/mcp_call.py tools/list --names-only

uv run --with boto3 --with 'botocore[crt]' python scripts/mcp_call.py tools/call \
  --name exa___web_search_exa \
  --arguments '{"query": "...", "objective": "..."}'
```

To see what the upstream server actually received you can turn on
`logUpstreamPayloads` in the policy. It logs the request after de-identification
and the response before re-identification. Those two snapshots carry tokens
rather than original values. The other two forms are never logged because the
inbound request is raw user data and the outbound response has the real values
restored.

## Tests

Every test runs offline. Fakes stand in for the Skyflow client and for both boto3
clients so nothing reaches AWS or Skyflow.

```bash
# interceptor
uv run --with boto3 python -m unittest discover \
  -s gateway/interceptor/tests -t gateway/interceptor/tests

# agent
uv run --with boto3 python -m unittest discover -s tests/flow -t tests/flow
```

CI runs four jobs on every push and pull request.

1. The interceptor unit tests.
2. The agent unit tests.
3. The secret-safety hook tests.
4. A CDK typecheck and a credential-free synth that asserts the Lambda bundle
   still carries no third-party dependencies.

## Documentation

| Path | What it covers |
| --- | --- |
| `gateway/README.md` | How AgentCore interceptors and targets work, including the payload shape trap that catches people out |
| `gateway/interceptor/README.md` | The policy model, both redaction directions, file handling, deployment and debugging |
| `app/Flow/README.md` | The agent runtime, its environment variables and how it discovers the gateway |
| `AGENTS.md` | Context for AI coding assistants working in this repository |

## Limitations

1. **Each eligible string costs one Skyflow call.** Fields within a payload are
   processed in parallel up to a limit of eight so a wide payload still costs
   several calls.
2. **Files are processed one at a time.** A response carrying three files takes
   roughly three times as long as a response carrying one.
3. **The gateway's interceptor deadline is undocumented and unmeasured.** Polling
   is bounded by the Lambda's own remaining time so it fails predictably. A large
   PDF has not been tried.
4. **Streaming is untested.** The handler omits headers and status on streaming
   events as the documentation requires but nothing has exercised it against a
   streaming gateway.
5. **Nothing prunes vault tokens.** Every shipped rule mints tokens that persist
   in the vault.

## References

1. [Amazon Bedrock AgentCore](https://aws.amazon.com/bedrock/agentcore/)
2. [AgentCore CLI](https://github.com/aws/agentcore-cli)
3. [AgentCore CDK constructs](https://github.com/aws/agentcore-l3-cdk-constructs)
