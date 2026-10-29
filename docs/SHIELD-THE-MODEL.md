# Plan: shield the model on inference traffic

## Status

Built on 28 October 2026 and not yet deployed. A spike on a scratch gateway answered the open behaviour questions first. Its results are under [Spike results](#spike-results). The finished code then ran end to end on a second scratch gateway. Those results are under [Live verification](#live-verification). SkyflowGateway is unchanged until the deploy steps in `gateway/interceptor/README.md` run.

## Decisions

1. **Naming.** This completes "Shield the model". The mode keeps sensitive data out of everything the model reads, from any source the policy names: message contents, attached files and tool results.
2. **Streaming.** Losing word-by-word streaming while shielding is on is acceptable.
3. **Attachments.** Formats that Detect can only redact are redacted rather than blocked.
4. **Default.** Flow sends its model calls through the gateway by default.

## Goal

Keep every sensitive value away from the model provider while the user still reads real values. That covers everything the model reads.

1. The user's prompt.
2. The system prompt.
3. The whole conversation history, including earlier answers.
4. Files attached to a message, such as text documents, PDFs and images.
5. Tool calls and tool results. The existing tool rules already cover these.

The model's answer is re-identified on its way back, so the user and the agent see real values again.

## Problem

"Shield the model" today covers only tool results. A tool rule with `response: deidentify` replaces sensitive values before the agent reads what the tool returned. The shipped policy does this for Exa's `web_fetch_exa`.

Everything else in the goal reaches the model provider in the clear. Flow calls Amazon Bedrock directly through Strands' `BedrockModel`, so those calls never pass the gateway and the interceptor never sees them.

## What changed in AgentCore

AgentCore Gateway now has [inference targets](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-targets-inference.html). The gateway fronts model traffic on its `/inference` path and routes each request by the `model` field in the body.

1. **Connectors** exist for `bedrock-runtime`, `bedrock-mantle`, `openai` and `anthropic`.
2. **Four client dialects** are accepted. They are Bedrock `InvokeModel` and `InvokeModelWithResponseStream`, OpenAI Chat Completions, OpenAI Responses and Anthropic Messages. Bedrock's Converse API is not one of them.
3. **Interceptors see inference traffic** as the `http` payload with base64 bodies.
4. **The response event carries no request.** `gatewayRequest` is null on the way back.

The interceptor refuses every `http` payload today with `SENSITIVE_DATA_UNINSPECTED`. An inference target added to SkyflowGateway now would be blocked.

## Spike results

The spike created a scratch gateway with IAM inbound auth, one `bedrock-runtime` connector target and a pass-through interceptor that logged the shape of every event. It sent fictional data through Anthropic Messages and Bedrock `InvokeModel` against `global.anthropic.claude-sonnet-5`. Then it deleted everything.

| Question | Answer |
| --- | --- |
| Does the interceptor see inference calls? | Yes. Every call invoked it twice, once as a request and once as a response. That includes `GET /v1/models` and calls that failed with 400. |
| What path does it see? | The path without the `/inference` prefix. Messages arrive as `/v1/messages` and InvokeModel as `/model/<model id>/invoke` or `/invoke-with-response-stream`. |
| Can it rewrite the prompt? | Yes. The model answered about the placeholder the interceptor put in place of the name. |
| Can it rewrite the answer? | Yes, for both a JSON answer and a streamed one. The client received the rewritten text. |
| Does the response interceptor see streams? | Yes, buffered. It receives the whole server-sent event stream at once. For a ten-word answer that was 12 `content_block_delta` events. The client receives nothing until the model has finished. |
| Do the request and response share an ID? | Yes. Both invocations of a call carry the same `REQUEST_ID` in the Lambda client context. `GATEWAY_ARN`, `GATEWAY_ACCOUNT_ID` and `SOURCE_IP` come with it. |
| Can the response be scoped by model? | Not reliably. The request named an inference-profile ARN and the response's `model` field said only `claude-sonnet-5`. |
| What does an InvokeModel stream look like? | `application/vnd.amazon.eventstream`. That is AWS's binary framing with checksums, not text. |
| How big are the bodies? | A ten-turn history was 3 KB of base64. A message with one text document and one small PNG was 11 KB. |
| How long does Skyflow Detect take? | Measured through the deployed interceptor with a warm Lambda. One turn took 0.3 s. Ten turns sent as 20 separate strings took 1.0 s. The same ten turns joined into one string took 0.5 s. Twenty turns joined took 0.9 s. A cold Lambda added about 1.7 s to its first call. |

The spike also found three constraints.

1. **Thinking blocks are signed.** Claude's answers include `thinking` blocks with a `signature`. The interceptor must pass them through untouched on both sides or the next turn fails validation.
2. **Tokens split across stream deltas.** A plain replace on the raw stream missed a placeholder that straddled two deltas. Re-identifying a stream has to join each content block's deltas first.
3. **The model notices tokens.** Given a bare placeholder the model said the name looked like placeholder text. A short system note that explains the tokens will probably be needed.

## Decision

Teach the interceptor one more kind of `http` payload: inference calls on the known inference paths. On the way in it de-identifies everything the model will read. On the way out it re-identifies what the model wrote. Every other `http` payload stays blocked as it is today.

Together with the existing tool rules this covers every place sensitive data can enter the model's context.

## Rejected options

1. **De-identify inside Flow with a Strands hook.** It would protect only Flow. The gateway is the one place that every agent's model traffic can pass whatever framework it uses, which is the argument the blog makes for tools.
2. **Amazon Bedrock Guardrails sensitive-information filters.** They mask or block values one way. They cannot give the user the real values back, and they cannot keep the same value mapped to the same token across turns. Skyflow's vault tokens can do both. Guardrails remain a sensible layer next to this one.
3. **Scoping responses by the model name in the answer.** The spike showed that the name in the answer does not match the name in the request.

## Design

### Policy

A new top-level `inference` block sits beside `defaults` and `overrides` in `policy.json`. Overrides match model globs instead of server and tool globs.

```json
"inference": {
  "models": ["*"],
  "request": {
    "action": "deidentify",
    "tokenType": "vault_token",
    "parts": ["system", "user", "assistant", "tool_call", "tool_result", "document", "image"],
    "systemNote": true
  },
  "response": {
    "action": "reidentify",
    "parts": ["text", "tool_call"],
    "only": "minted_for_request"
  },
  "entities": ["name", "email_address", "phone_number", "credit_card", "location"],
  "scope": { "minLength": 3 },
  "attachments": { "maxBytes": 2097152 },
  "failure": { "onError": "fail_closed" }
},
"inferenceOverrides": [
  { "models": ["*haiku*"], "request": { "action": "deidentify", "parts": ["user", "tool_result"] } }
]
```

| Field | What it scopes |
| --- | --- |
| `models` | Globs matched against the `model` in the request body or the model id in an InvokeModel path. A call whose model matches no rule is blocked. |
| `request.action` | `deidentify` or `none`. |
| `request.tokenType` | `vault_token` so the answer can be re-identified, or `counter` for one-way tokens that the user also sees. |
| `request.parts` | Which parts are de-identified. `system` is the system prompt. `user` and `assistant` are the turns. `tool_call` is the arguments of earlier tool calls. `tool_result` is what tools returned. `document` is an attached document and `image` an attached image. Tool definitions and thinking blocks are never touched. |
| `request.systemNote` | Adds one sentence to the system prompt saying that bracketed tokens stand for real values and should be used as written. |
| `response.action` | `reidentify` or `none`. |
| `response.parts` | `text` is the model's prose. `tool_call` is the arguments of a tool call the model makes. The agent then sends that call through the gateway's tool rules. |
| `response.only` | `minted_for_request` re-identifies only tokens that the request side minted for this call. `any_vault_token` re-identifies every vault token, as the tool path does today. |
| `attachments` | A size limit for attached files, decoded. A larger one is refused, and the de-identified file is held to the same limit. Lambda takes 6 MB in and 6 MB out, and the event holds base64 of a JSON body that itself holds base64. |
| `entities` and `scope` | As for tools. `entities` defaults to the policy's default entities and must not be empty while the request de-identifies. Only `scope.minLength` applies to conversation text, and it defaults to 3. |
| `failure.onError` | As for tools, but only for Skyflow failures. A body the interceptor cannot parse is always refused. |

An override replaces whole sub-blocks, as overrides for tools do. A `request` block in an override that leaves out `action` means `none`, so the example names it.

### Carrying the decision to the response

The response event carries no request and the answer's model name is unreliable. So the request side writes a small record under the gateway's `REQUEST_ID` into a DynamoDB table with a time to live of fifteen minutes. The record holds the rule that applied and the tokens it minted. The response side reads the record and applies the same rule. It re-identifies only those tokens when `response.only` is `minted_for_request`.

A response with no record is left to `httpPayloads`, which blocks it by default. The request side therefore writes a record for every inference call it lets through, including `GET /v1/models` and calls whose rule does nothing.

### What gets de-identified

1. **Text parts** go to Skyflow Detect's string API. Each distinct string goes once, eight at a time in parallel. The spike showed that joining them into fewer requests would cost about half as much, but joining is not built yet.
2. **Text documents** are strings and go the same way.
3. **PDFs, images and Office files** go to Skyflow Detect's v2 file API as `dataSource: BASE64` and always one way. A PDF comes back with counter tokens such as `NAME_1`. An image comes back with the values blacked out. Neither can be restored, which matches the decision above. A small PDF took about a second.
4. **A per-container cache** keeps the result for any string it has already de-identified while the Lambda stays warm. Vault tokens are deterministic, so the cache returns what Detect would. Earlier turns of a conversation then cost almost nothing on later calls. It holds at most 4096 strings and 32 million characters.

### Dialect adapters

Each dialect gets a small adapter that lists the parts to transform and writes the results back. Adapters live in a new `src/inference.py`.

1. **Anthropic Messages is built.** Claude models on Bedrock serve it through the `bedrock-runtime` connector. The adapter covers JSON answers and buffered streams. For a stream it joins each content block's deltas, re-identifies the joined text and writes it back as one delta. `count_tokens` requests are de-identified too.
2. **Bedrock `InvokeModel` is built for JSON answers from Claude.** Its body is the Anthropic payload for Claude models, so it reuses the first adapter. Other model families send their own bodies, such as Llama's `prompt`, so a body without `anthropic_version` and `messages` is refused. A streamed InvokeModel answer uses AWS event-stream framing, which is not parsed yet, so such a call is refused while the rule re-identifies. Any other path under `/v1/` or `/model/` is refused too, so it cannot fall through to `httpPayloads`.
3. **OpenAI Chat Completions and Responses are not built.** They are refused while a rule does anything.

### Streaming

The gateway buffers every inference response before the interceptor sees it. With shielding on, the user receives the whole answer when the model finishes instead of word by word. The demo UI shows its pending indicator for longer and then the full answer. That is the cost of re-identifying the answer at the gateway.

### Flow

Flow sends its model calls through the gateway by default. `model/load.py` returns a Strands model that sends Anthropic Messages to `<gateway>/inference`, and `MODEL_VIA_GATEWAY=0` switches back to calling Bedrock directly. Without exactly one IAM gateway or a `MODEL_GATEWAY_URL` it refuses to start rather than skip the shield. `agentcore dev` injects the deployed gateway too, so local development goes through it. The Anthropic SDK's own retries are off, because each retry would run the model and Skyflow again, and Strands already retries throttled calls. It reuses the SigV4 `httpx` auth in `mcp_client/sigv4.py`, because SkyflowGateway uses IAM inbound auth. Strands' Anthropic model needs the `anthropic-version` header, which the Anthropic SDK sends by itself.

### Infrastructure

The project schema can express inference only as a `passthrough` target, not as an inference connector. Two CDK changes in `gateway/interceptor/cdk` cover it.

1. `SkyflowInterceptorStack` gains the DynamoDB table for per-request records, with put and get grants for the interceptor and its name in `INFERENCE_RECORD_TABLE`.
2. A new `SkyflowInferenceStack` adds a `bedrock-runtime` connector target on SkyflowGateway with `GATEWAY_IAM_ROLE` outbound auth. It also grants the gateway role `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream` and the seven list calls that the inference target documentation names for model discovery. CDK 2.261 does not model inference targets yet, so the target configuration is a CloudFormation property override. CloudFormation itself supports it.

The deliberate exception in `agentcore/cdk/lib/cdk-stack.ts` stays as it is.

## Steps

Steps 1 to 7 are done. Step 8 is half done. Step 9 is done except for the blog.

1. Add the `inference` policy model, its validation and its tests to `src/policy.py`.
2. Add the Anthropic Messages adapter for text parts with tests for JSON bodies and buffered streams. Thinking blocks must pass through byte for byte.
3. Route inference paths in `src/handler.py` and keep every other `http` payload blocked.
4. Add the per-request record table and `response.only`.
5. Add the inference target stack and its IAM grants.
6. Add `MODEL_VIA_GATEWAY` to Flow with tests in `tests/flow/`.
7. Add attachments: text documents first, then PDFs and images through Detect's file API.
8. Add the InvokeModel adapter and then the OpenAI adapters. InvokeModel JSON is done. InvokeModel streams and the OpenAI dialects remain.
9. Update the interceptor README and `AGENTS.md` and the shipped policy. Then decide whether the blog should describe this.

## Live verification

The finished interceptor code ran on a scratch gateway on 28 October 2026. It used the shipped policy, its own record table and a `bedrock-runtime` target, against `bedrock/global.anthropic.claude-sonnet-5`. All data was fictional. Everything was deleted afterwards.

| Check | Result |
| --- | --- |
| A prompt asking for the customer's name reversed and then his email | The model wrote the token reversed as `]duIrbJA_EMAN[`, so it never saw the name. The real email came back, so the answer was re-identified. |
| The same as a stream | The same result, from a buffered stream. |
| A ten-turn history | The real email came back. |
| A forced tool call | The tool-call arguments came back with the real email. |
| A text document | The real email came back. |
| A PDF | The model read `NAME_1` and `EMAIL_ADDRESS_1`. |
| A PNG | The model reported the name and email as blacked out. |
| Flow's own `load_model()` in a two-turn Strands agent | Both turns answered with the real values, in 2 to 3 seconds each. |
| The interceptor's logs | No line contained any of the fictional values. |

With the system note on, the model still sometimes remarked that a value was a placeholder. The note reduces this but does not prevent it.

## Verification

1. Unit tests cover every part and dialect plus the cache and the failure modes.
2. A live call through SkyflowGateway with a name and an email address in the prompt shows tokens in the provider-facing request. The upstream logging already shows this for tools.
3. The same call returns the real values in Flow's answer.
4. A ten-turn conversation keeps the same token for the same customer on every turn.
5. A PDF and an image attached to a message reach the model with their values replaced.

## Open questions

1. **The blog.** Once this ships, the "Shield the model" row in the blog's table could widen to cover the prompt and history and attachments as well as tool results.
2. **Response scope.** The shipped policy restores only tokens minted for the call. Tools still restore any vault token. Should the tool path move to minted-only too?
