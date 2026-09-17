# Demo

This walks through proving that the gateway de-identifies a document before the
agent can read it. Everything here runs against the deployed stack so there is
nothing to build first.

Run every command from the repository root.

## The quickest check

Ask the agent for a document.

```bash
agentcore invoke --target dev "Get a download link for samples/claim-note.txt and tell me the exact URL."
```

The agent returns a URL. Look at the host.

1. A host of `try-sb1-uw2-detect-input.s3.us-west-2.amazonaws.com` is a Skyflow
   bucket and means the swap worked.
2. A host of `agentcore-skyflow-files-<account>.s3.amazonaws.com` is your own
   bucket and means the interceptor did not fire. The agent is holding a link to
   the original document.

## Prove the contents changed

Compare what is stored against what the agent receives.

```bash
# what is actually stored in your bucket
aws s3 cp s3://agentcore-skyflow-files-571930033416/samples/claim-note.txt -
```

```
Claim note
Customer: Daniel Okonkwo
Email: daniel.okonkwo@example.com
Phone: 555-0133
Notes: follow up about the Chicago policy renewal.
```

```bash
# what the agent receives
app/Flow/.venv/bin/python scripts/mcp_call.py tools/call \
  --name s3___get_document \
  --arguments '{"key": "samples/claim-note.txt"}' \
  | python3 -c "
import json,sys,urllib.request
d = json.load(sys.stdin)
url = json.loads(d['result']['content'][0]['text'])['url']
print(urllib.request.urlopen(url, timeout=60).read().decode())
"
```

```
Claim note
Customer: [NAME_AJbrIud]
Email: [EMAIL_ADDRESS_nJFlbfH]
Phone: [PHONE_NUMBER_VVwjCfV]
Notes: follow up about the [LOCATION_y3wQt7I] policy renewal.
```

The long random suffix tells you which kind of token you got.

1. `[NAME_AJbrIud]` is a vault token. Someone with vault permissions can recover
   the original out of band.
2. `[NAME_1]` is a counter. Nothing can reverse it.

## Which formats keep a reversible token

Three formats were run end to end through the deployed gateway. The token shape
in the output tells you which kind you got.

| Format | Result | Token |
| --- | --- | --- |
| `txt` | de-identified | `[NAME_AJbrIud]` vault token |
| `docx` | de-identified | `[NAME_AJbrIud]` vault token |
| `pdf` | de-identified | `[NAME_1]` counter |

A PDF still gets de-identified and the original values are gone from the output.
It cannot carry a vault token because Skyflow only stores reversible tokens for
`txt` and `json` and `csv` and `xml` and `jsonl` and `docx` and `xlsx` and
`pptx`. Anything else downgrades to a one-way counter and the interceptor logs
`vault_token_downgraded` when it happens.

Try them yourself:

```bash
agentcore invoke --target dev "Get a download link for samples/claim-note.docx"
agentcore invoke --target dev "Get a download link for samples/claim-note.pdf"
```

## How large a document can be

Skyflow processes roughly five kilobytes per second, which sets a practical
ceiling on a synchronous interceptor.

| Size | Time | Result |
| --- | --- | --- |
| 137 bytes | about 5 seconds | de-identified |
| 446 KiB | about 94 seconds | de-identified |
| 2.2 MiB | never finished inside 295 seconds | refused |

The gateway itself held the connection open for 298 seconds without giving up,
so the limit is Skyflow throughput rather than a gateway deadline.

The policy refuses anything above `maxFileBytes` which ships at 512 KiB. The
refusal costs about five seconds because the interceptor asks the store for the
size before submitting anything. Without that guard the caller waits five
minutes and gets the same refusal.

Raise the limit in `gateway/interceptor/config/policy.json` if your documents are
larger and you can tolerate the wait.

## Test your own document

```bash
echo "Patient: Maria Alvarez, mrn 44821, seen in Denver on 3 March." > /tmp/note.txt
aws s3 cp /tmp/note.txt s3://agentcore-skyflow-files-571930033416/samples/note.txt
agentcore invoke --target dev "Get a download link for samples/note.txt"
```

Detection covers name and email address and phone number and SSN and credit card
and date of birth and location. Anything outside that list passes through
untouched.

## Change the rules and watch the behaviour change

The policy lives at `gateway/interceptor/config/policy.json` and the S3 rule is
the third entry in `overrides`. It looks like this:

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
    "urlPatterns": ["https://agentcore-skyflow-files-*.s3.amazonaws.com/*"],
    "maxFiles": 1,
    "tokenType": "vault_token",
    "destinations": {"default": "table1.{entity}_entity"}
  }
}
```

Change `tokenType` to `counter` and publish it.

```bash
python3 scripts/put_policy.py --dry-run          # validate and print the rules
app/Flow/.venv/bin/python scripts/put_policy.py --region us-east-1
```

Wait about sixty seconds for the interceptor cache to expire and call again. The
tokens become `[NAME_1]` instead of `[NAME_AJbrIud]`. No redeploy is involved.

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
interceptor log group.

```bash
aws logs filter-log-events \
  --log-group-name SkyflowInterceptorStack-InterceptorLogsB7A4CDFF-hDwhIMMQrqT4 \
  --region us-east-1 \
  --start-time $(python3 -c "import time; print(int((time.time()-600)*1000))") \
  --query 'events[].message' --output text | tr '\t' '\n' | grep -i fail
```

Two causes account for most failures.

1. `Missing Destination for entity NAME in DetectConfigV2` means the policy asks
   for vault tokens without naming a `table.column` for every entity.
2. `<name> schema not found` means a destination names a table that the vault
   does not have.

## Browsing the gateway from your own MCP client

AWS ships a proxy that signs requests for you, so any MCP client that speaks
stdio can talk to the gateway without implementing SigV4.

```bash
uvx mcp-proxy-for-aws@latest \
  https://agentflow-skyflowgateway-k7lrzhryea.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp \
  --service bedrock-agentcore
```

This repository wires that up as an MCP server named `skyflow-gateway` in
`.mcp.json`, so your coding assistant can list and call the gateway's tools
directly. Every call still passes through the interceptor, which means a
document you fetch that way comes back de-identified exactly as it does for the
agent.

The proxy uses your local AWS credentials. It needs
`bedrock-agentcore:InvokeGateway` on the gateway.

## Using it from the AgentCore console

The deployed runtime is named `Flow` and it appears in the Amazon Bedrock
AgentCore console under Agent Runtime in `us-east-1`. Open it and use the test
pane to send the same prompts.

```
Get a download link for samples/claim-note.txt
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
