# Demo

This walks through proving that the gateway de-identifies a document before the
agent can read it. Everything here runs against the deployed stack so there is
nothing to build first.

To record the demo for the blog post, follow `docs/RECORDING.md` instead. It
uses the same sample and adds the setup, scene-by-scene prompts and teardown.

Run every command from the repository root.

Two values differ per deployment. Export them once and every command below works
as written.

```bash
export BUCKET="agentcore-skyflow-files-$(aws sts get-caller-identity --query Account --output text)"
export SKYFLOW_GATEWAY_URL=$(aws cloudformation describe-stacks \
  --stack-name AgentCore-agentflow-dev --region us-east-1 \
  --query "Stacks[0].Outputs[?OutputKey=='GatewaySkyflowGatewayUrlOutput'].OutputValue" \
  --output text)
```

## Deploying this in your own account

Everything below assumes the stack is already deployed. If you are starting from
a fresh clone in a different AWS account then five things need your values
before you deploy.

1. `agentcore/aws-targets.json` names the account and region to deploy into. It
   ships with a placeholder account.
2. `gateway/interceptor/cdk/cdk.context.json` names your Skyflow vault. Copy
   `cdk.context.json.example` and fill in `skyflowVaultUrl` and `skyflowVaultId`.
   The file is gitignored because it names real infrastructure.
3. Your Skyflow API key goes into Secrets Manager under `skyflow/detect-api-key`.
4. The document bucket has to exist. `scripts/create_documents_bucket.py`
   creates `agentcore-skyflow-files-<account>` with public access blocked and
   `--upload-samples` puts the sample documents in it. Nothing else creates it.
5. The `destinations` map in `gateway/interceptor/config/policy.json` names the
   vault table and columns that store the original values. It ships as
   `table1.{entity}_entity` which matches a vault whose columns follow that
   convention. Change it to match your schema or vault tokens will fail the run
   with `<name> schema not found`.

The S3 target derives the bucket name `agentcore-skyflow-files-<account>` from
its own function ARN, so the default name needs no configuration. Set the SSM
parameter `/agentcore/s3-target/bucket` to point it somewhere else, and change
`files.urlPatterns` in the policy to match.

Deploy the interceptor stack before `agentcore deploy`. The gateway imports the
interceptor's function ARN from that stack and attaches it in the same deploy,
so `agentcore deploy` fails with `No export named
SkyflowInterceptorStack-InterceptorFunctionArn found` until the interceptor
stack exists. The last command confirms the interceptor is attached at both
interception points and changes nothing.

```bash
(cd gateway/interceptor/cdk && npm ci && npm run build && npx cdk deploy --require-approval never)
agentcore deploy --target dev -y
python3 scripts/attach_interceptor.py --gateway-name agentflow-SkyflowGateway --check
```

Run the check again after every later `agentcore deploy`.

## The quickest check

Ask the agent for a document.

```bash
agentcore invoke --target dev "Get a download link for samples/dispute-case-note.txt and tell me the exact URL."
```

The agent returns a URL. Look at the host.

1. A host you do not own is a Skyflow bucket and means the swap worked. Skyflow
   returns the de-identified copy from a bucket in its own account, so the host
   depends on the vault's environment; a trial vault returned
   `try-sb1-uw2-detect-input.s3.us-west-2.amazonaws.com`.
2. A host that starts with `agentcore-skyflow-files-` is your own
   bucket and means the interceptor did not fire. The agent is holding a link to
   the original document. Check whether the interceptor is attached with
   `python3 scripts/attach_interceptor.py --gateway-name agentflow-SkyflowGateway --check`.

## Prove the contents changed

Compare what is stored against what the agent receives.

```bash
# what is actually stored in your bucket
aws s3 cp s3://$BUCKET/samples/dispute-case-note.txt -
```

```
Card dispute case note
Case: DSP-20481
Customer: Mateo Jackson
Email: mateo_jackson@example.com
Phone: 555-0100
Card: 4111 1111 1111 1111
Merchant: AnyCompany Electronics, London
Notes: Disputes a £249.00 charge on 12 September. Order never arrived.
```

```bash
# what the agent receives
app/Flow/.venv/bin/python scripts/mcp_call.py tools/call \
  --name s3___get_document \
  --arguments '{"key": "samples/dispute-case-note.txt"}' \
  | python3 -c "
import json,sys,urllib.request
d = json.load(sys.stdin)
url = json.loads(d['result']['content'][0]['text'])['url']
print(urllib.request.urlopen(url, timeout=60).read().decode())
"
```

```
Card dispute case note
Case: DSP-20481
Customer: [NAME_KhpdiUQ]
Email: [EMAIL_ADDRESS_n6Eg15w]
Phone: [PHONE_NUMBER_OBUs3N7]
Card: [CREDIT_CARD_20Nsush]
Merchant: AnyCompany Electronics, [LOCATION_ybLHA45]
Notes: Disputes a £249.00 charge on 12 September. Order never arrived.
```

That output is illustrative. The suffixes differ on every run, and exactly
which spans become tokens is Detect's call, so a date may or may not be caught.
The document rule uses the default entity list, which includes `location`, so
London is tokenized in the document even though the web search rule keeps it.

The long random suffix tells you which kind of token you got.

1. `[NAME_KhpdiUQ]` is a vault token. Someone with vault permissions can recover
   the original out of band.
2. `[NAME_1]` is a counter. Nothing can reverse it.

## Which formats keep a reversible token

Three formats were run end to end through the deployed gateway. The token shape
in the output tells you which kind you got.

| Format | Result | Token |
| --- | --- | --- |
| `txt` | de-identified | `[NAME_KhpdiUQ]` vault token |
| `docx` | de-identified | `[NAME_KhpdiUQ]` vault token |
| `pdf` | de-identified | `[NAME_1]` counter |

A PDF still gets de-identified and the original values are gone from the output.
It cannot carry a vault token because Skyflow only stores reversible tokens for
`txt` and `json` and `csv` and `xml` and `jsonl` and `docx` and `xlsx` and
`pptx`. Anything else downgrades to a one-way counter and the interceptor logs
`vault_token_downgraded` when it happens.

Try them yourself:

```bash
agentcore invoke --target dev "Get a download link for samples/dispute-case-note.docx"
agentcore invoke --target dev "Get a download link for samples/dispute-case-note.pdf"
```

## How large a document can be

That depends on the vault you point at rather than on anything in this
repository.

These timings came from a shared Skyflow trial environment:

| Size | Time | Result |
| --- | --- | --- |
| 137 bytes | about 5 seconds | de-identified |
| 446 KiB | about 94 seconds | de-identified |
| 2.2 MiB | never finished inside 295 seconds | refused |

Do not quote those as product numbers. A trial environment shares
under-resourced capacity. Production Detect runs the model on GPUs and is far
faster, so a production vault handles much larger documents in the same wall
clock.

The gateway itself held the connection open for 298 seconds without giving up,
so nothing in AgentCore is imposing the ceiling.

The policy refuses anything above `maxFileBytes` which ships at 512 KiB to suit
the trial vault above. The refusal costs about five seconds because the
interceptor asks the store for the size before submitting anything. Without that
guard the caller waits for the full timeout and gets the same refusal.

Measure your own vault and raise the limit in
`gateway/interceptor/config/policy.json`.

## Test your own document

```bash
echo "Patient: Maria Alvarez, mrn 44821, seen in Denver on 3 March." > /tmp/note.txt
aws s3 cp /tmp/note.txt s3://$BUCKET/samples/note.txt
agentcore invoke --target dev "Get a download link for samples/note.txt"
```

Detection covers name and email address and phone number and SSN and credit card
and date of birth and location. Anything outside that list passes through
untouched.

## Change the rules and watch the behaviour change

The policy lives at `gateway/interceptor/config/policy.json` and the S3 rule is
the override for `get_document`. It looks like this:

```json
{
  "servers": ["s3"],
  "tools": ["get_document"],
  "request": {"action": "none"},
  "response": {"action": "none"},
  "files": {
    "action": "deidentify",
    "directions": ["response"],
    "fields": ["content[*].text.url"],
    "urlPatterns": [
      "https://agentcore-skyflow-files-*.s3.amazonaws.com/*",
      "https://agentcore-skyflow-files-*.s3.*.amazonaws.com/*",
      "https://agentcore-skyflow-files-*.s3.dualstack.*.amazonaws.com/*"
    ],
    "maxFiles": 1,
    "tokenType": "vault_token",
    "destinations": {"default": "table1.{entity}_entity"}
  }
}
```

Change `tokenType` to `counter` and publish it. `scripts/demo_policy.py` does
exactly that edit without touching the file:

```bash
app/Flow/.venv/bin/python scripts/demo_policy.py one-way-documents --region us-east-1
```

Wait about sixty seconds for the interceptor cache to expire and call again. The
tokens become `[NAME_1]` instead of `[NAME_KhpdiUQ]`. No redeploy is involved.

Once you have seen that, put the shipped policy back:

```bash
app/Flow/.venv/bin/python scripts/demo_policy.py reset --region us-east-1
```

Set `"action": "none"` inside the `files` block and the agent starts receiving
links to your original documents again. That is the clearest demonstration of
what the feature is doing.

## Two things that will confuse you

1. The returned URL expires after thirty minutes so fetch it promptly.
2. Each call creates a new de-identified copy so the URL differs every time even
   for the same document.

## When it fails

A failure returns this rather than a document:

```json
{"error": {"code": -32603, "message": "Sensitive-data processing failed; response withheld"}}
```

That is the policy failing closed on purpose because returning the original
would leak the data the interceptor exists to protect. The reason is in the
interceptor log group, whose name is a stack output.

```bash
LOG_GROUP=$(aws cloudformation describe-stacks \
  --stack-name SkyflowInterceptorStack --region us-east-1 \
  --query "Stacks[0].Outputs[?OutputKey=='InterceptorLogGroupName'].OutputValue" \
  --output text)

aws logs filter-log-events \
  --log-group-name "$LOG_GROUP" \
  --region us-east-1 \
  --start-time $(python3 -c "import time; print(int((time.time()-600)*1000))") \
  --query 'events[].message' --output text | tr '\t' '\n' | grep -i fail
```

Three causes account for most failures. The log line carries Skyflow's own
message for each.

1. `Missing Destination for entity NAME in DetectConfigV2` means the policy asks
   for vault tokens without naming a `table.column` for every entity.
2. `<name> schema not found` means a destination names a table that the vault
   does not have.
3. A run that fails only for documents containing a card number usually means
   the vault has no column for that entity, such as `table1.credit_card_entity`.
   Add the column or a `destinations` entry pointing at one that exists.

If the call fails with `not allowed by files.urlPatterns`, the document URL's
host matched none of the allowlist's patterns. The log names the host.

## Browsing the gateway from your own MCP client

AWS ships a proxy that signs requests for you, so any MCP client that speaks
stdio can talk to the gateway without implementing SigV4.

```bash
uvx mcp-proxy-for-aws@latest \
  "$SKYFLOW_GATEWAY_URL" \
  --service bedrock-agentcore
```

This repository wires that up as an MCP server named `skyflow-gateway` in
`.mcp.json`. It reads `SKYFLOW_GATEWAY_URL` from your environment so the config
carries no one deployment's URL. Export it before starting your client and your
coding assistant can list and call the gateway's tools directly. Every call still passes through the interceptor, which means a
document you fetch that way comes back de-identified exactly as it does for the
agent.

The proxy uses your local AWS credentials. It needs
`bedrock-agentcore:InvokeGateway` on the gateway.

## Using it from the AgentCore console

The deployed runtime is named `Flow` and it appears in the Amazon Bedrock
AgentCore console under Agent Runtime. This prints the console link for whatever
is deployed now:

```bash
RUNTIME_ID=$(aws cloudformation describe-stacks \
  --stack-name AgentCore-agentflow-dev --region us-east-1 \
  --query "Stacks[0].Outputs[?contains(OutputKey, 'RuntimeIdOutput')].OutputValue" \
  --output text)
echo "https://us-east-1.console.aws.amazon.com/bedrock-agentcore/agents/$RUNTIME_ID?region=us-east-1"
```

The link has the shape
`https://<region>.console.aws.amazon.com/bedrock-agentcore/agents/<runtime-id>?region=<region>`
where the runtime id looks like `agentflow_Flow-XXXXXXXXXX`. The suffix is
assigned at creation so it differs in every account.

Open it and use the test pane to send the same prompts.

```
Get a download link for samples/dispute-case-note.txt
```

The console shows the agent's tool calls, so you can watch it call
`s3___get_document` and see the URL it received. That URL points at a Skyflow
bucket rather than yours, which is the whole demonstration.

Traces appear under Observability once transaction search has indexed them,
which takes about ten minutes after a deployment.

## What runs where

1. `agentcore invoke` calls the deployed Flow runtime which discovers the
   gateway from an injected environment variable.
2. `scripts/mcp_call.py` skips the agent and speaks MCP to the gateway directly
   with SigV4 authentication. Use it when you want to see the raw response. Pass
   `--timeout` when a large document is in play because it defaults to sixty
   seconds.
3. `mcp-proxy-for-aws` does the same signing for any stdio MCP client.
4. The interceptor Lambda reads its policy from SSM Parameter Store at
   `/agentcore/interceptor/skyflow-policy` and caches it for sixty seconds.
5. The S3 target resolves its bucket from the SSM parameter
   `/agentcore/s3-target/bucket` and falls back to
   `agentcore-skyflow-files-<account>` when that parameter does not exist.
