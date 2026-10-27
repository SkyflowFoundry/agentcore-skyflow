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
│   target: s3  ──────────────► documents as presigned URLs │
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
│   └── cdk/                # generated CDK app; one deliberate hand edit, see AGENTS.md
├── app/Flow/               # the agent runtime
│   ├── main.py             # entrypoint
│   ├── mcp_client/         # gateway discovery, SigV4 signing, error diagnostics
│   └── model/load.py       # Bedrock model selection
├── gateway/
│   ├── targets/s3/         # documents in S3 exposed as MCP tools
│   └── interceptor/
│       ├── src/            # Lambda source: stdlib and boto3 only
│       ├── config/         # policy.json is the source of truth for redaction rules
│       ├── cdk/            # standalone CDK app for the Lambda and its SSM parameter
│       └── tests/          # offline tests that touch neither AWS nor Skyflow
├── samples/                # the synthetic card-dispute case note, as txt, docx and pdf
├── scripts/                # check the interceptor, publish policy, call the gateway, demo helpers
├── tests/flow/             # agent tests, kept outside app/ so they do not ship
└── ui/                     # web console: Cognito login + chat UI for the Flow agent
```

## Prerequisites

1. Node.js 20 or later for the CDK apps.
2. Python 3.10 or later with [uv](https://docs.astral.sh/uv/getting-started/installation/).
3. AWS credentials that can deploy Lambda and SSM and IAM and AgentCore resources.
4. A Skyflow vault with Detect enabled and a long-lived API key.

## Deploying

The interceptor cannot be declared in `agentcore.json` because the AgentCore CLI
has no field for it. The CDK app that `agentcore deploy` runs attaches it to the
gateway instead, using the function ARN that the interceptor stack exports. That
fixes the order: the interceptor stack deploys first and `agentcore deploy`
second. Two one-time steps come before either.

**Step 0a points the project at your account.** The committed
`agentcore/aws-targets.json` carries a placeholder account. Replace it with your
own account ID; the region must be one where AgentCore is available.

```bash
# agentcore/aws-targets.json
[{"name": "dev", "account": "<YOUR_ACCOUNT_ID>", "region": "us-east-1"}]
```

**Step 0b stores the Skyflow API key and creates the document bucket.** The
`s3` target reads documents from `agentcore-skyflow-files-<account>` and nothing
else creates that bucket. Both commands are safe to re-run.

```bash
aws secretsmanager create-secret \
  --name skyflow/detect-api-key \
  --secret-string '<SKYFLOW_API_KEY>' \
  --region us-east-1

uv run --with boto3 python scripts/create_documents_bucket.py \
  --region us-east-1 --upload-samples
```

**Step 1 creates the interceptor Lambda and its policy parameter.**

```bash
cd gateway/interceptor/cdk
cp cdk.context.json.example cdk.context.json   # fill in your vault URL and vault ID
npm install && npm run build
npx cdk deploy --require-approval never
cd -
```

**Step 2 creates the gateway with the interceptor attached.**

```bash
agentcore deploy --target dev -y
```

The AgentCore stack imports the `SkyflowInterceptorStack-InterceptorFunctionArn`
export that step 1 creates. CloudFormation stops the deploy with
`No export named SkyflowInterceptorStack-InterceptorFunctionArn found` when step
1 has not run. The same stack grants the gateway's service role the two
permissions the interceptor needs.

1. `lambda:InvokeFunction` on the interceptor lets the gateway call it.
2. `bedrock-agentcore:GetConfigurationBundleVersion` on the project's
   configuration bundles lets `tools/list` succeed when the caller is a runtime.

The deployed gateway name carries the project name as a prefix so `SkyflowGateway`
becomes `agentflow-SkyflowGateway`. Step 2 also writes
`agentcore/.cli/deployed-state.json`, which the helper scripts read. It is not
committed because it names one deployment.

**Step 3 confirms the interceptor is attached.** Run this after every
`agentcore deploy`:

```bash
python3 scripts/attach_interceptor.py --gateway-name agentflow-SkyflowGateway --check
```

It changes nothing and exits non-zero if the interceptor is missing at either
point. A failure after a successful step 2 means the gateway resource in
`agentcore/cdk/lib/cdk-stack.ts` has lost its interceptor configuration. Running
the script without `--check` repairs the live gateway, but the next deploy that
changes the gateway removes the interceptor again until the CDK app is fixed.

The import also holds the order in reverse. CloudFormation will not delete the
interceptor stack or change its exported ARN while the AgentCore stack imports
it, so tear the AgentCore stack down first.

To attach a Lambda that was deployed some other way, put its ARN in
`agentcore/cdk/cdk.context.json` as `interceptorFunctionArn`. That file is
gitignored and `agentcore deploy` reads it. The gateway then uses that ARN and no
longer waits for the interceptor stack.

```json
{ "interceptorFunctionArn": "arn:aws:lambda:us-east-1:<account>:function:<name>" }
```

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

## Logging

The interceptor logs one line per decision at `INFO` and never logs a
credential: the Skyflow API key, AWS signatures, a caller's Authorization header
and credential-shaped fields inside a payload are all kept out of CloudWatch
regardless of `LOG_LEVEL` or `logUpstreamPayloads`. The settings and the
guarantees are laid out in `gateway/interceptor/README.md` under Logging.

## Verification

`scripts/mcp_call.py` speaks MCP to the gateway with SigV4 authentication.

```bash
uv run --with boto3 --with 'botocore[crt]' python scripts/mcp_call.py tools/list --names-only

uv run --with boto3 --with 'botocore[crt]' python scripts/mcp_call.py tools/call \
  --name exa___web_search_exa \
  --arguments '{"query": "...", "objective": "..."}'
```

To see what the upstream server actually received you can turn on
`logUpstreamPayloads` in the policy, once the interceptor stack has been
deployed with `-c allowUpstreamPayloadLogging=true`. It logs the request after
de-identification and the response before re-identification. Those two
snapshots carry tokens rather than original values. The other two forms are
never logged because the inbound request is raw user data and the outbound
response has the real values restored. A tool whose response is
de-identified, such as `web_fetch_exa`, logs no response at all, because
its upstream side holds the original content.

## Tests

Every test runs offline. Fakes stand in for the Skyflow client and for both boto3
clients so nothing reaches AWS or Skyflow.

```bash
# interceptor
uv run --with boto3 python -m unittest discover \
  -s gateway/interceptor/tests -t gateway/interceptor/tests

# agent
uv run --with boto3 python -m unittest discover -s tests/flow -t tests/flow

# the interceptor attachment in the AgentCore CDK app
(cd agentcore/cdk && npm ci && npm test)
```

CI runs five jobs on every push and pull request.

1. The interceptor unit tests.
2. The agent unit tests.
3. The secret-safety hook tests.
4. An interceptor CDK typecheck and a credential-free synth that asserts the
   Lambda bundle still carries no third-party dependencies.
5. An AgentCore CDK typecheck and the tests that pin the interceptor's
   attachment to the gateway.

## Documentation

| Path | What it covers |
| --- | --- |
| `docs/DEMO.md` | How to prove the de-identification works against the deployed stack |
| `docs/RECORDING.md` | The script for recording the blog demo: setup, three scenes, screenshots and teardown |
| `gateway/README.md` | How AgentCore interceptors and targets work, including the payload shape trap that catches people out |
| `gateway/interceptor/README.md` | The policy model, both redaction directions, file handling, deployment and debugging |
| `app/Flow/README.md` | The agent runtime, its environment variables and how it discovers the gateway |
| `ui/README.md` | The web console: Cognito login and a chat UI that talks to the Flow agent |
| `AGENTS.md` | Context for AI coding assistants working in this repository |

## Limitations

1. **Each eligible string costs one Skyflow call.** Fields within a payload are
   processed in parallel up to a limit of eight so a wide payload still costs
   several calls.
2. **Files are processed one at a time.** A response carrying three files takes
   roughly three times as long as a response carrying one.
3. **Document size is capped at 512 KiB by the shipped policy.** That number
   comes from a shared Skyflow trial environment and is not a product limit.
   Production Detect runs on GPUs and is far faster, so raise `maxFileBytes`
   once you know the throughput of the vault you are pointing at.
4. **Only text formats keep a reversible token.** A PDF or an image is still
   de-identified but it comes back with one-way counters because Skyflow cannot
   store a vault token for those formats.
5. **Streaming is untested.** The handler omits headers and status on streaming
   events as the documentation requires but nothing has exercised it against a
   streaming gateway.
6. **Nothing prunes vault tokens.** Every shipped rule mints tokens that persist
   in the vault.

## References

1. [Amazon Bedrock AgentCore](https://aws.amazon.com/bedrock/agentcore/)
2. [AgentCore CLI](https://github.com/aws/agentcore-cli)
3. [AgentCore CDK constructs](https://github.com/aws/agentcore-l3-cdk-constructs)
