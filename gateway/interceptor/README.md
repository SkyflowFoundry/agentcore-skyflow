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
│   ├── envelope.py         # decode MCP text blocks around the file swap
│   ├── file_urls.py        # find file references and name their format
│   ├── logsafe.py          # keep credentials out of the log group
│   ├── skyflow_client.py   # Detect string and file endpoints, retry/backoff
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
  "httpPayloads": { "action": "block" },
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
| `httpPayloads.action` | `block` (default) or `passthrough`, for HTTP-shaped targets the interceptor cannot redact. Gateway-wide; see below |

### The two directions

**Shield the tool** — `request: deidentify`, `response: reidentify`. The agent
sees real data; the upstream never does. This is the default here, because it
round-trips and is therefore verifiable end to end.

**Shield the model** — `response: deidentify`, `request: reidentify`. The tool
sees real data; the model context never does. Useful when results carry PII the
agent has no need to read — the shipped policy applies this to Exa's
`web_fetch_exa` tool, whose result is scraped web content.

Shield the model should mint **one-way** tokens, which is how the shipped rule
is set. All rules share one vault, so a vault token minted here can be
re-identified by any other rule whose response re-identifies. A tool that
echoes its input back would then hand the scraped originals to the model.
Counter tokens cannot be reversed by anything.

Per-tool `entities` narrow what counts as sensitive for one tool. The shipped
rule for `web_search_exa` leaves out `location`, so a search for a customer's
dispute with a merchant in London still names London: the customer's name is
what identifies them, and the city is what makes the search useful.

### HTTP-shaped targets are blocked

AgentCore Runtime, `passthrough` and inference targets reach the interceptor as
`event["http"]`: a base64 body with no MCP framing, so there is no tool call to
match a policy against and nothing to redact. The interceptor therefore
refuses them by default. A request is answered with a 403 whose error code is
`SENSITIVE_DATA_UNINSPECTED`, before the target is called, and a response is
replaced with the same. Each refusal logs `http_payload_blocked` at WARNING
with the target name (the first path segment only).

To accept that such a target is not protected, set
`"httpPayloads": {"action": "passthrough"}`. Its traffic then goes through
untouched, and every call logs `http_payload_passthrough` at WARNING so the
gap stays visible. The stack turns both log lines into the
`SkyflowInterceptor/HttpPayloadBlocked` and `HttpPayloadPassthrough` metrics,
and alarms on the second; see [Metrics and alarms](#metrics-and-alarms).

The setting is gateway-wide rather than per tool. An HTTP response event
carries no request, so on the way back there is no target name to match an
override against, and a per-target rule could only be half enforced.

### When SSM or Skyflow misbehaves

- **A failed policy refresh serves the last good policy.** If SSM throttles, or
  someone publishes a policy that does not parse, the Lambda keeps using the
  policy it last loaded and logs `policy_refresh_failed ...
  action=serving_last_good`. It asks SSM again after ten seconds rather than on
  every call. After `POLICY_MAX_STALE_SECONDS` (default one hour, CDK context
  `policyMaxStaleSeconds`) it stops and fails closed. A cold Lambda with no
  policy at all always fails closed.
- **A rotated API key is picked up on the first 401.** The client re-reads the
  secret once and retries. A key that is simply wrong is re-read at most once
  every thirty seconds, so a bad key cannot turn every call into a Secrets
  Manager read.
- **File endpoint errors are readable.** A Detect v2 error such as `Missing
  Destination for entity NAME` reaches the log, with any URL in it cut to its
  host because a presigned URL's query string is a credential. String endpoint
  errors stay opaque because their bodies can echo the submitted text.
- **The Skyflow timeout is configurable.** `SKYFLOW_TIMEOUT_SECONDS`, default
  five, CDK context `skyflowTimeoutSeconds`. Raise it if large fetched pages
  fail closed on a slow vault.

### Validation rule

Re-identify only resolves **vault tokens**. Counter tokens cannot be reversed,
so a policy that mints `counter` in one direction and re-identifies in the other
is rejected at load — by `put_policy.py` before it reaches SSM, and by the
Lambda if it somehow gets there.

## Deploy

One-time: set your account in `agentcore/aws-targets.json`, store the
long-lived Skyflow API key, and create the document bucket the `s3` target
reads from. Nothing else creates the bucket.

```bash
aws secretsmanager create-secret \
  --name skyflow/detect-api-key \
  --secret-string '<SKYFLOW_API_KEY>' \
  --region us-east-1

uv run --with boto3 python scripts/create_documents_bucket.py \
  --region us-east-1 --upload-samples
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

## Files

Tools that deal in documents return a signed URL, not the bytes. String
redaction never sees the contents, so it does nothing useful for them.

The interceptor instead replaces the reference. It sends the signed URL it
received to Skyflow Detect, waits for the run to finish, and swaps in the URL of
the de-identified copy. The agent only ever receives the clean version and never
holds a link to the original.

```
S3 / Box  ──signed URL──▶  gateway  ──▶  interceptor
                                            │  POST /v2/detect/deidentify/file
                                            │    dataSource: PRESIGNED_URL
                                            │  GET  /v2/detect/runs/{runId}
                                            ▼
                              new signed URL, de-identified  ──▶  agent
```

The bytes never pass through the Lambda, so neither the 6 MB synchronous
invocation limit nor the size of the document applies. This needs **Detect v2**,
which is beta and feature-flagged per vault: only v2 accepts `PRESIGNED_URL`.
`scripts/check_detect_v2.py` confirms it end to end against a real bucket.

This is a one-way transform. It governs what the agent is allowed to see, not a
round trip — there is no re-identify step for files.

The de-identified copy comes back in a Skyflow-owned bucket, which is the point
rather than a caveat: the file stays in an approved region while the agent
asking for it may not be.

### Which token replaces a detected entity

A file rule names its own token type. Leaving `tokenType` out means inherit it
from the string rule for the same direction, which is how this behaved before
the field existed.

```json
{"files": {"action": "deidentify", "tokenType": "vault_token", "...": "..."}}
```

Naming it matters because a file rule usually sits alongside `"action": "none"`
on the string rule, and a rule that does nothing still carries the default of
`counter`. The S3 rule hit exactly that and asked Skyflow for counters while
vault tokens were available.

### Where a vault token stores the original

A vault token has to put the original value somewhere. Skyflow rejects a
vault-token file run with `Missing Destination for entity NAME in
DetectConfigV2` unless every entity names a `destination`. The Detect v2 spec
documents the field on `Detect_Entity` as a string described as "Target
destination of the entity to be stored in vault". It does not state the format.
The format is `table.column` and the API only tells you so by failing the run
with `invalid tableColumn format: name`.

```json
{
  "files": {
    "action": "deidentify",
    "tokenType": "vault_token",
    "destinations": {
      "default": "table1.{entity}_entity",
      "ssn": "table1.ssn_secure"
    }
  }
}
```

Each key is an entity name and each value is a `table.column` string. The key
`default` supplies a template for any entity not named and `{entity}` is
replaced with the entity name. A named entity wins over the template.

The template cannot spell `ALL` because there is no `all` column, so an empty
`entities` list needs an explicit `all` entry.

Two things the API checks at different times, which is why the policy checks
both up front:

1. A missing destination fails at submit with HTTP 400.
2. A malformed or nonexistent one submits with HTTP 200 and fails inside the
   run, which reaches a caller as a fail-closed error much later.

`put_policy.py --dry-run` rejects a rule that asks for vault tokens without
covering every entity, and it rejects a value that is not `table.column`.

Counter tokens persist nothing so they take no destination. A format that cannot
take vault tokens downgrades to counters and drops the destination with it.

### How large a document can be

That depends entirely on the throughput of the vault you point at, so
`maxFileBytes` is a per-deployment setting rather than a fixed limit.

These timings came from a shared Skyflow trial environment:

| Size | Time | Result |
| --- | --- | --- |
| 137 bytes | about 5 seconds | de-identified |
| 446 KiB | about 94 seconds | de-identified |
| 2.2 MiB | never finished inside 295 seconds | refused |

Do not read those as product limits. A trial environment shares under-resourced
capacity. Production Detect runs the model on GPUs and is far faster, so a
production vault will carry much larger documents in the same wall clock.

The shipped `maxFileBytes` of 512 KiB is sized for the trial environment above.
Measure your own vault and raise it.

The useful finding is where the ceiling is *not*. The gateway held the
connection open for 298 seconds without giving up, so the binding constraint is
whatever Skyflow takes rather than a gateway deadline. The Lambda timeout is 300
seconds for the same reason.

`maxFileBytes` refuses anything larger before submitting it. The interceptor asks
the document store for the size first, which costs about a second and turns a
long wait into an immediate refusal.

```json
{"files": {"action": "deidentify", "maxFileBytes": 524288, "...": "..."}}
```

The size probe is a ranged GET for one byte rather than a HEAD. A presigned S3
URL is signed for a single method, so a HEAD against a URL signed for GetObject
comes back 403 and the size reads as unknown. An unknown size is allowed through
because a store that refuses the probe should not block de-identification.

### Which formats keep a reversible token

Vault tokens are stored for `txt` and `json` and `csv` and `xml` and `jsonl` and
`docx` and `xlsx` and `pptx`. Every other format downgrades to a one-way counter
and the interceptor logs `vault_token_downgraded` so the downgrade is not
silent.

A PDF is still de-identified and the original values are gone from the output. It
simply cannot be reversed afterwards.

### Tool results wrap their payload in a text block

An MCP tool result does not hand back structured JSON. It hands back a JSON
string inside a text content block:

```json
{"content": [{"type": "text", "text": "{\"key\": \"claim.txt\", \"url\": \"https://...\"}"}]}
```

String redaction is fine with that: the whole blob is one string, Skyflow scans
it as such, and the block costs one call. File handling is not, because swapping
a URL needs the URL to be a field value rather than a substring of one.

The interceptor therefore parses each JSON text block only around the file swap,
and only when a file rule applies to the direction. Field paths address the
decoded structure, so the URL in the example above is at `content[*].text.url`
rather than at `url`. The block is re-serialized before string redaction runs,
so redaction still sees the one string the agent will read. Decoding it for
redaction too would split the block into fields, and a `scope` written for prose
would then skip a seven-character name or a phone number as too short, or skip
a `url` value that carries a name.

The freshly issued URL inside a re-serialized block is masked with a placeholder
while the block is at Skyflow and put back afterwards. If the placeholder does
not come back intact the call fails closed rather than return a dead link.

A block that is prose rather than JSON is left alone. A block that parses to a
bare number or string is also left alone because re-encoding it would turn a
plain string into a quoted one. Non-ASCII text is re-serialized as it was,
not as `\uXXXX` escapes, because the model reads the string rather than the
parsed value.

### Configuring it

Off unless a `files` block says otherwise. Put it in an override to scope it to
one server or tool, or in `defaults` to cover everything.

```json
{
  "servers": ["s3"],
  "tools": ["*"],
  "files": {
    "action": "deidentify",
    "directions": ["response"],
    "fields": ["url", "content[*].url"],
    "urlPatterns": [
      "https://my-bucket.s3.amazonaws.com/*",
      "https://my-bucket.s3.*.amazonaws.com/*"
    ],
    "maxFiles": 2,
    "configuration": { "detect": { "entities": [ ... ] } }
  }
}
```

| Field | Meaning |
| --- | --- |
| `directions` | Which side carries the file. A download returns one in the response; an upload sends one in the request. |
| `fields` | Where the reference is, relative to the tool's arguments or its result. `content[*].url` covers a list. Naming fields stops the scan. |
| `urlPatterns` | **Required.** The allowlist of places a file may come from, as `https://host/path` globs. Every URL is checked against it before the interceptor fetches it or hands it to Skyflow. Also finds references when `fields` is absent, and flags strays when it is not. |
| `maxFiles` | Cap per call. Each file is a separate run and they are processed in order. |

S3 presigns on more than one host form. The default boto3 client uses the
global `bucket.s3.amazonaws.com`; a client configured for virtual-hosted
addressing uses `bucket.s3.<region>.amazonaws.com`, and a dual-stack client
`bucket.s3.dualstack.<region>.amazonaws.com`. The allowlist fails the call when
a URL matches none of its patterns, so list every form your store produces. The
shipped rule lists all three.

The shipped bucket pattern ends in `*` so the demo works in any account. Anyone
can create a bucket whose name starts the same way, so in production name your
bucket exactly.
| `configuration` | Inline Detect configuration, forwarded as given with `vaultId` injected. Anything the Detect API accepts works here without a code change. |

Configurations are inline rather than referenced by `configurationId`: a
vault-stored config would have to be updated and rolled out separately from the
policy that depends on it.

### Behaviour worth knowing

- **A rule needs `urlPatterns`, even with `fields`.** Named fields say where to
  look, not what is safe to fetch. The size probe requests the URL from inside
  AWS and Skyflow fetches it from its own network, so the patterns are the
  only thing between a tool's response and those requests.
- **A pattern is matched part by part, not as one glob.** It must be
  `https://`, with no port, user, query or fragment. In the host, `*` stands
  for part of one label and cannot cross a dot, so
  `https://files-*.s3.amazonaws.com/*` does not match
  `https://files-x.evil.com/.s3.amazonaws.com/a.pdf`. The last two host
  labels must be literal, so `*.com` or `*` alone are refused when the policy
  loads. The path is a glob that may cross `/`. The query string is not
  matched, because a presigned URL's changes on every call.
- **A URL no pattern allows fails the call.** In a named field it blocks the
  call under `fail_closed`, because skipping it would hand the agent the
  original document. When scanning, a string that fails the patterns is just
  not a file reference. Either way it is never fetched or submitted. Only the
  host goes in the log line, since the rest of a presigned URL is its
  signature.
- **The size probe is HTTPS-only, follows no redirects, and only connects to
  public addresses.** The address check is on the socket's actual peer, after
  DNS and before TLS, so loopback, link-local (including 169.254.169.254),
  private ranges and DNS rebinding are all refused, and the call fails
  closed. A redirect ends the probe with the size unknown. It does not follow
  the `Location`.
- **Exceeding `maxFiles` fails the call** rather than processing the first few.
  A partial swap hands back some originals alongside some redacted copies.
- **Named fields still get a stray check.** The rest of the response is matched
  against `urlPatterns` and anything found is logged, not acted on, so a tool
  that changes its response shape shows up rather than passing files through
  silently.
- **A named field that is absent is not an error.** Tools legitimately return
  responses with no attachment.
- **A swapped URL is excluded from string redaction.** Tokenizing a freshly
  issued signed URL would produce a dead link. A URL at its own field is
  skipped by path; one inside a re-serialized text block is masked and
  restored, and the call fails closed if the mask does not survive.
- **The format comes from the extension in the URL path**, ignoring query
  parameters, since a presigned URL carries its signature after the path. An
  unrecognised extension fails the call: `dataFormat` is how Skyflow picks a
  processor.
- **`VAULT_TOKEN` only applies to `txt`, `json`, `csv`, `xml`, `jsonl`, `docx`,
  `xlsx` and `pptx`.** Other formats fall back to counters. This affects whether
  the original stays recoverable out of band, not what the agent sees.
- **Polling is bounded by the Lambda's remaining time**, because the gateway's
  own interceptor deadline is not documented. A run that outlives the budget
  fails closed.

## Logging

Everything the interceptor writes goes to its CloudWatch log group, named by the
`InterceptorLogGroupName` stack output, kept for 30 days by default (CDK
context `logRetentionDays`). There are
four settings that change what lands there, and one guarantee that holds under
every combination of them.

| Setting | Where it is set | What it changes |
| --- | --- | --- |
| `LOG_LEVEL` | Lambda environment variable; not set by the stack, so `INFO` | How much the interceptor's own code logs. `INFO` is one line per decision: which tool, which action, how many fields changed, which file run. `WARNING` and above are failures only. `DEBUG` adds nothing today and is reserved for future diagnostics. |
| `logUpstreamPayloads` | Policy, per default or per override; live within the cache TTL | Adds the two tokenized payload snapshots described in the next section, capped at 4000 characters. Ships `false`, and has no effect unless the next setting is also on. |
| `ALLOW_UPSTREAM_PAYLOAD_LOGGING` | Lambda environment variable, set by the stack from `cdk deploy -c allowUpstreamPayloadLogging=true`; defaults to `false` | Whether `logUpstreamPayloads` is honoured at all. The policy lives in SSM and changes without a deploy, so this keeps payload logging a deployed decision rather than a parameter edit. While it is off and a policy asks for payload logging, the Lambda logs one `upstream_payload_logging_refused` warning per execution environment. |
| `passRequestHeaders` | `scripts/attach_interceptor.py --pass-request-headers`; gateway-side | Whether the caller's HTTP headers arrive in the event at all. Ships off. It changes what the Lambda receives, not what it logs. |

What is never logged, whatever the settings:

- **The Skyflow API key and AWS credentials.** `LOG_LEVEL` applies to the
  interceptor's loggers only. The AWS SDK loggers are held at `INFO` or above,
  because botocore at `DEBUG` prints every response body and every SigV4
  signing step, and the response body of `GetSecretValue` is the Skyflow API
  key. `logsafe.configure_logging` enforces this and a test pins it.
- **The caller's Authorization header.** With `passRequestHeaders` on, the
  event carries it. The handler blanks `Authorization`, `Cookie`, `X-Api-Key`,
  `X-Amz-Security-Token` and any header whose name mentions a token, secret or
  credential before doing anything else, so no later log line can print one.
  The interceptor never reads headers, and the gateway forwards its own copy
  upstream, so nothing is lost.
- **Credential fields inside a logged payload.** The shipped `scope.excludeKeys`
  keeps `api_key` and `authorization` out of tokenization so a tool that needs
  them still works. Before an upstream snapshot is serialized, those keys, any
  key containing `token`, `secret`, `password` or `credential`, and any value
  shaped like `Bearer …`, `Basic …` or a SigV4 signature are replaced with
  `<redacted>`. The payload sent upstream is untouched; only the log copy is.
- **The upstream side of a transform that restores or receives originals.**
  A response with `action: deidentify` is the upstream returning real data
  for the interceptor to redact, and a request with `action: reidentify`
  sends real data upstream. Neither direction has a tokenized upstream form,
  so `logUpstreamPayloads` logs nothing for it.
- **PII with a recognisable shape.** As a backstop for values detection
  missed, strings in a logged snapshot have email addresses, SSNs, Luhn-valid
  card numbers and 10 to 15 digit phone numbers replaced with
  `<redacted:email>`, `<redacted:ssn>`, `<redacted:card>` and
  `<redacted:phone>`. Shapes are all it knows: names, addresses and dates of
  birth that detection missed are not caught.
- **Skyflow error bodies.** A failed Detect call logs its status code and path.
  The body can echo the submitted text, which is the data being protected.
- **Anything with `action: none`.** With no transform there is no tokenized
  form to show, so `logUpstreamPayloads` logs nothing for that direction.

Two things sit outside the interceptor's control and are worth knowing:

- **Headers never travel inside a body.** In both interceptor payload shapes
  the caller's headers arrive only under `gatewayRequest.headers`, and only
  when `passRequestHeaders` is on. The base64 `body` of the `http` shape is
  the HTTP body alone, and the `rawGatewayRequest.body` of the `mcp` shape is
  the unparsed request body. The one place header values do land in a body is
  an AWS signature-mismatch error, which echoes the canonical request the
  service computed, signed header values included. The agent's
  `mcp_client/diagnostics.py` masks those before logging the body.
- **The gateway's own application logs carry payloads.** With AgentCore
  Observability application logging enabled on the gateway, its log stream
  records tool calls with their `responseBody` verbatim. That is the gateway's
  log group rather than the interceptor's, and it is written regardless of any
  setting here. Leave gateway application logs off in production, or treat that
  log group with the same care as the vault.

## Seeing what the upstream server actually received

`logUpstreamPayloads` logs the two snapshots that carry tokens rather than
original values:

- the request **after** de-identification — literally the bytes the gateway
  sends upstream;
- the response **before** re-identification — what the upstream sent back.

The other two forms are never logged, and that is the whole safety argument:
the inbound request is raw user data, and the outbound response has the
original values restored.

That holds only for those two pairings of direction and action, so they are
the only ones logged. A tool whose response is `deidentify`, such as
`web_fetch_exa`, gets its original content back from the upstream server;
there is no tokenized snapshot of it, so its response logs nothing. The same
goes for a request whose action is `reidentify`.

Turning it on takes two steps. The stack has to allow it, which is a deploy:

```bash
cd gateway/interceptor/cdk
npx cdk deploy -c allowUpstreamPayloadLogging=true
```

Then the policy field chooses which tools, and flips without a redeploy:

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
- **Nothing is logged unless the upstream side carries tokens.** With
  `action: none`, a `deidentify` response or a `reidentify` request, the
  "upstream" payload *is* the original, so logging it would write user data to
  CloudWatch. `Policy.should_log_upstream` enforces that, not the caller.

### Metrics and alarms

The stack turns the log lines that matter into CloudWatch metrics in the
`SkyflowInterceptor` namespace (CDK context `metricNamespace`), and alarms on
any occurrence in a five-minute window.

| Metric | Counts | Alarm |
| --- | --- | --- |
| `FailClosed` | Calls withheld because de-identification could not complete | Yes |
| `FailOpen` | Calls let through unprotected by a `fail_open` rule after an error | Yes |
| `PolicyUnavailable` | Policy loads that failed, and refreshes serving a stale policy | Yes |
| `HttpPayloadBlocked` | HTTP-shaped events refused | No: blocking is the intended outcome |
| `HttpPayloadPassthrough` | HTTP-shaped events let through uninspected | Yes |

The alarms change state on their own. To be told, deploy with
`-c alarmTopicArn=<SNS topic ARN>`. A test checks that every term a metric
filter counts is still logged by the Lambda, so a renamed log line cannot
silently disable an alarm.

Active X-Ray tracing is on, so each invocation shows up in X-Ray and
CloudWatch Application Signals with its duration, including time spent waiting
on Skyflow.

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

With `logUpstreamPayloads` off, which is how the policy ships, the interceptor
logs no payloads at all: CloudWatch shows which action ran and how many fields
changed, but not their contents. Turn it on per tool while debugging and turn it
back off, and redeploy without `allowUpstreamPayloadLogging` when you are done,
for the reasons given in the section above.

## Iterating on policy

`put_policy.py` publishes the policy minified and refuses one that would not
fit the parameter. A Standard-tier SSM parameter holds 4 KB, and the dry run
prints how much of it the policy uses. Past that, deploy the stack with
`-c policyParameterTier=advanced` and publish with `--tier advanced` for 8 KB.
Advanced parameters are billed.

A second interceptor in the same account and region needs its own parameter
and stack name, or the two overwrite each other's policy:

```bash
npx cdk deploy -c stackName=SkyflowInterceptorStaging \
  -c policyParameterName=/agentcore/interceptor/staging-policy
python3 scripts/put_policy.py --parameter-name /agentcore/interceptor/staging-policy
```

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
| `test_http_payloads.py` | HTTP-shaped events (SC-16091): blocked by default on both directions, explicit passthrough, WARNING logs without bodies or full paths, policy parsing |
| `test_handler.py` | Dispatch, direction routing, overrides, fail-closed/open, streaming, round trip |
| `test_policy.py` | Parsing, scope globs, override precedence, tool-name splitting, validation |
| `test_payload.py` | Traversal, write-back, non-mutation, parallelism and its cap, error propagation |
| `test_skyflow_client.py` | Request shape, retry and backoff, and that error bodies never leak |
| `test_settings.py` | Policy cache TTL, serving the last good policy, API key parsing and refresh, lazy boto3 construction |
| `test_skyflow_files.py` | Detect v2 submit-by-URL, run polling and its deadline, output selection |
| `test_file_url_safety.py` | The file URL allowlist (SC-16092): pattern parsing, wildcard confinement, parser-confusion URLs, non-public addresses, no redirects or non-HTTPS handlers in the probe |
| `test_file_interception.py` | URL swapping, named fields, stray warnings, format detection, fail-closed paths, token types and destinations, size limits, the MCP text envelope |
| `test_envelope.py` | Decoding a JSON text content block and encoding it back |
| `test_upstream_logging.py` | Which payload snapshots may be logged for each direction and action, and which must never be; the deploy-time gate |
| `test_metric_terms.py` | Every log term the stack's metric filters count is still logged by the Lambda |
| `test_logsafe.py` | `LOG_LEVEL` never reaching the AWS SDK loggers, credential and PII-shape masking in logged payloads, header scrubbing on entry |

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

1. **One Skyflow call per eligible string.** Fields within a payload are
   redacted in parallel up to a limit of eight, so a wide payload still costs
   several calls.
2. **Files are processed one at a time.** A `maxFiles` above one serialises the
   runs, so raising it multiplies the time a call takes.
3. **Document size is capped at 512 KiB by the shipped policy.** That number is
   sized for a shared trial vault rather than being a product limit. Measure
   your own throughput and raise `maxFileBytes`.
4. **Only text formats keep a reversible token.** A PDF or an image is still
   de-identified but it comes back with one-way counters.
5. **Streaming is untested.** The handler omits headers and status on streaming
   events as the documentation requires but nothing has exercised it against a
   streaming gateway. Leave streaming off.
6. **Nothing prunes vault tokens.** Every de-identification writes tokens that
   persist in the vault.
