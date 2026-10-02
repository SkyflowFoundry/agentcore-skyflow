# Blog outline: Skyflow + Amazon Bedrock AgentCore Gateway

Status: outline for internal review. First draft follows once this is agreed.

| Item | Value |
| --- | --- |
| Working title | Keep sensitive data out of agent tool calls with Skyflow and Amazon Bedrock AgentCore Gateway |
| Alternate titles | *De-identify agent tool traffic at the gateway with Skyflow and Amazon Bedrock AgentCore*; *Protect PII in every agent tool call with Skyflow and Amazon Bedrock AgentCore Gateway* |
| Level / categories | Advanced (300). Amazon Bedrock AgentCore, AWS Lambda, Amazon S3, Partner Solutions, Security, Technical How-to |
| Format | No code. Three diagrams, one demo video (2 to 3 min), before/after screenshots |
| Target length | 2,000 to 2,500 words. Stardog runs about 5,600 with code; ours carries no code |
| Skyflow author | Joe McCarron, Head of Developer Advocacy & Product Lead |
| AWS authors | TBD. Ask our AWS contact who joins from their side (usually a partner SA) |
| Skyflow POC for the draft | Logan McConnell, Head of Partnerships, logan.mcconnell@skyflow.com |
| CTA | AWS Marketplace listing, the CloudFormation template, Skyflow Detect docs, SDKs, deployment models |

Style notes from the reference posts:

- **Stardog:** opens with a one-paragraph "In this post we show…", then a "By the end of this post you will know" list. It names a concrete use case early, builds the post around a reference architecture, labels GA versus beta openly, compares deployment models, and closes with a numbered "Where to start" and a "Further reading" list.
- **Quick:** follows one persona through the post and drops in a short video or quote at each beat. We borrow the persona device and the customer quote.
- **AWS naming:** spell out full service names on first use (Amazon Bedrock AgentCore Gateway, AWS Systems Manager Parameter Store, AWS Secrets Manager), then use the short form.

---

## 0. Standfirst (about 80 words)

"In this post we show how to protect sensitive data in every tool call an AI agent makes by adding Skyflow Detect to Amazon Bedrock AgentCore Gateway as a request and response interceptor." Then one sentence on the three protection modes, one on "no change to the agent or its tools", and one saying it deploys from AWS Marketplace with a CloudFormation template.

## 1. Introduction: agents act through tools, and tools move data (about 300 words)

- **Shift:** agents have moved from answering questions to taking action. Taking action means calling tools: MCP servers, SaaS APIs, document stores, web search.
- **Point:** every tool call is a data flow. Most enterprise controls govern what goes into and out of the *model*: prompt filters, Amazon Bedrock Guardrails, output review. Far fewer govern what goes into and out of the *tools*.
- **Why the gateway:** AgentCore Gateway is where every tool call converges, regardless of which agent framework or model made it. That makes it the natural enforcement point for data privacy, just as an API gateway became the enforcement point for API security.
- **"By the end of this post you will know":**
  - Where sensitive data leaks in an agent's tool traffic, in both directions.
  - How the Skyflow interceptor uses AgentCore Gateway's request and response interception points to de-identify and re-identify data in flight.
  - How the same approach protects documents behind signed URLs without the file passing through your code.
  - How it fits with AgentCore Policy, Amazon Bedrock Guardrails and AgentCore Identity.
  - How to deploy it from AWS Marketplace, and what is GA versus preview today.

## 2. The customer problem: sensitive data in agent tool traffic (about 350 words)

Make the three failure modes concrete, one short paragraph each.

1. **Outbound leakage to tools.** The model writes the tool arguments. When a user asks about a customer, the customer's name, account number or email goes straight into a query sent to a third-party MCP server. That server is outside your AWS account, your compliance scope and your data-processing agreements.
2. **Inbound exposure to the model.** Tool results return whatever the tool found: scraped web pages, CRM records, case notes. That data then lands in the model context, conversation memory, traces and logs, even when the task never needed it. With cross-Region inference, the model call may also be served from a different Region than the one the data came from. That's a residency question regulated customers already ask.
3. **Documents are invisible to string redaction.** Document tools (Amazon S3, Box, Google Drive) return a signed URL, not text. Anything that inspects strings sees a link and passes it through. The agent then opens the original document.

Then explain why the usual answers fall short:

- **Patching each agent** doesn't scale across frameworks and teams, and it can't reach third-party tools.
- **Allow and deny controls** such as Cedar policies in AgentCore Policy decide *whether* a call happens, not *what data it carries*.
- **Model guardrails** cover model input and output. They don't cover the request that leaves for a tool or the document a tool returns.

## 3. Example use case: a customer-servicing agent at a global bank (about 350 words)

**Anonymized customer description** (confirm with the account team that even anonymized use is cleared):

> "A global financial services group headquartered in the UK, with retail, corporate and investment banking operations serving tens of millions of customers across the UK, Europe and the US."

Run one persona through the post, as the Quick post does:

- **Persona:** a card-dispute operations analyst using an internal agent to investigate disputed transactions.
- **Workflow:**
  1. The analyst asks the agent to research a merchant and the customer's dispute history. The agent calls a web-search MCP server and an internal case store.
  2. The agent pulls the dispute case note, a document in Amazon S3, to summarize it.
- **The "before" picture:**
  - The customer's name and contact details go to the search provider.
  - Scraped merchant pages bring unrelated personal data into the model context.
  - The agent opens the original case note with the customer's full name, email, phone number and card details.
- **The "after" picture:**
  - The search provider receives `[NAME_AJbrIud]`, and the analyst still sees the real name in the agent's answer.
  - Web content reaches the model already de-identified.
  - The agent receives a link to a de-identified copy of the case note, stored in an approved Region.
- **Customer quote:** request one from the anonymized bank, or use a Skyflow executive quote as a fallback. Placeholder: *[QUOTE TBD — attributed to "Head of AI Platform at a global bank" if approved]*.

Why this use case: banking combines all three failure modes, strict residency rules (UK GDPR, EU GDPR) and a regulator who expects a demonstrable control rather than a promise.

## 4. Solution overview (about 450 words)

### What it is

A Skyflow-built interceptor for AgentCore Gateway. One AWS Lambda function serves both of the gateway's interception points:

- **REQUEST** runs before the gateway calls a tool.
- **RESPONSE** runs after the tool answers and before the agent sees the result.

At each point, the interceptor calls Skyflow Detect to find sensitive entities and replace them with tokens, or to restore the original values. Skyflow Vault keeps the originals so the tokens can be reversed.

### Three protection modes (the core of the post)

| Mode | Request | Response | Who sees real data | Example |
| --- | --- | --- | --- | --- |
| Shield the tool | De-identify arguments | Re-identify results | Agent and user; the tool never does | Web search with a customer's name |
| Shield the model | Pass through (or re-identify) | De-identify results | The tool; the model never does | Scraped web pages, CRM lookups |
| Shield the document | — | Swap the signed URL for one pointing at a de-identified copy | Nobody on the agent side | Case notes and statements in Amazon S3 |

Three properties to explain for the document mode:

- **The file bytes never pass through the interceptor.** Skyflow fetches the file from the signed URL and returns a new signed URL to the cleaned copy. File size isn't limited by Lambda payload limits.
- **The clean copy is stored in a Skyflow-managed location in an approved Region.** The agent can run anywhere without carrying the original.
- **It is one way by design.** It governs what the agent is allowed to see.

### Properties to emphasize

- **No change to the agent or its tools.** The agent discovers the gateway, signs requests with its IAM role and calls tools as before. The interceptor is invisible to it.
- **Policy-driven, per tool.** The policy sets per server and per tool:
  - which direction is protected
  - which entity types to detect (name, email, phone, SSN, card number, date of birth, location)
  - whether tokens are reversible (vault tokens) or one way (counters)
- **Changes without a redeploy.** The policy lives in AWS Systems Manager Parameter Store and takes effect in about a minute.
- **Secure by default:**
  - Fails closed: if de-identification fails, the call is withheld rather than sent in the clear.
  - Only fetches files from an allowlist of locations.
  - Refuses traffic it can't inspect rather than passing it silently.
  - Never writes credentials or original values to its logs.
- **AWS-native operations:**
  - The API key is in AWS Secrets Manager.
  - Logs and metrics go to Amazon CloudWatch, with one structured log line per decision.
  - There are metric filters for alarms.

## 5. Reference architecture (diagram 1, about 200 words)

**Diagram 1: reference architecture**

- **Left:** a user, then an agent on AgentCore Runtime (any framework; ours is Strands Agents).
- **Center:** AgentCore Gateway with the REQUEST interceptor, the targets and the RESPONSE interceptor drawn inside it. The interceptor Lambda sits beside the gateway with arrows to Parameter Store (policy) and Secrets Manager (API key).
- **Targets on the right:**
  - a third-party web-search MCP server
  - an Amazon S3 document store exposed as an MCP tool
- **Far right, outside the AWS account boundary:** Skyflow Detect and Skyflow Vault, with a note on Region choice.
- **Bottom:** CloudWatch logs and metrics.

The text walks the numbered arrows in order.

## 6. How it works (diagrams 2 and 3, about 400 words)

**Diagram 2: sequence for a tool call (shield the tool)**

1. The agent calls `web_search` with a customer's name.
2. The REQUEST interceptor calls Skyflow Detect, and Detect returns tokens.
3. The gateway calls the MCP server with tokens only.
4. The server responds. The response contains tokens where relevant.
5. The RESPONSE interceptor re-identifies the tokens through Skyflow.
6. The agent receives the result with real values restored.

**Diagram 3: sequence for a document (shield the document)**

1. The agent calls `get_document`.
2. The S3 tool returns a presigned URL.
3. The RESPONSE interceptor checks the URL against its allowlist and the file against its size limit.
4. The interceptor hands the URL to Skyflow Detect, which fetches the file and de-identifies it.
5. Skyflow returns a new signed URL to the clean copy.
6. The agent receives only the new URL.

**Before/after screenshot.** Show the stored case note and the copy the agent receives side by side, using the real demo output. The anonymized version should use banking content (see open items).

```
Customer: Daniel Okonkwo              →   Customer: [NAME_AJbrIud]
Email: daniel.okonkwo@example.com     →   Email: [EMAIL_ADDRESS_nJFlbfH]
Phone: 555-0133                       →   Phone: [PHONE_NUMBER_VVwjCfV]
```

Explain the token shapes in one sentence each:

- `[NAME_AJbrIud]` is a vault token, recoverable by an authorized user.
- `[NAME_1]` is a one-way counter.

**Formats** (state plainly):

- Text and Office formats keep reversible vault tokens: TXT, JSON, CSV, XML, JSONL, DOCX, XLSX, PPTX.
- PDFs and images are fully de-identified but receive one-way tokens, so the originals can't be restored from those files.

**Performance** (sample numbers; mark them as such in the draft; to be replaced after production testing):

| Document size | Time to de-identify | Notes |
| --- | --- | --- |
| 137 bytes | about 5 seconds | |
| 446 KiB | about 94 seconds | shared trial environment |
| 2.2 MiB | did not finish inside 295 seconds | shared trial environment |

Also include:

- AgentCore Gateway held the connection open for 298 seconds without timing out, so the gateway is not the limit.
- The interceptor checks file size before submitting, so an oversized file is refused in about a second rather than timing out.

> Draft note: these figures come from a shared trial environment. Production Skyflow Detect runs on GPUs and is substantially faster. Replace them with production measurements before publishing.

## 7. Demo video (embedded after section 6; 2 to 3 minutes)

Storyboard:

1. **(0:00 to 0:20) Set the scene:** the dispute analyst persona and the agent in the AgentCore console test pane.
2. **(0:20 to 0:50) Shield the tool:** the agent searches the web with a customer's name. Cut to the interceptor log showing what the upstream server received (tokens), then back to the agent's answer (real name).
3. **(0:50 to 1:40) Shield the document:**
   - The analyst asks for the case note. The console trace shows `get_document` returning a URL whose host is a Skyflow bucket, not ours.
   - Open the original and the clean copy side by side.
4. **(1:40 to 2:20) Policy change, no redeploy:**
   - Switch the token type to one-way counters, or turn file protection off, in the policy. Publish it and wait a minute.
   - Rerun the same prompt to show the behavior change.
   - Turn protection back on.
5. **(2:20 to 2:40) Wrap-up:** one line per mode, then the Marketplace call to action.

The policy edit in step 4 should be shown in a UI or as a single highlighted line, so the no-code framing holds.

## 8. How it fits with the rest of AgentCore (about 250 words)

Position the interceptor as complementary to AWS services, not overlapping with them. This is where AWS reviewers look first.

| Control | Answers | Use with the Skyflow interceptor |
| --- | --- | --- |
| AgentCore Policy (Cedar) | May this principal call this tool? | Cedar decides whether the call happens; Skyflow decides what data it carries |
| Amazon Bedrock Guardrails | Is this model input or output acceptable? | Guardrails cover the model boundary; Skyflow covers the tool boundary |
| AgentCore Identity / IAM | Who is calling, with what credential? | The interceptor needs no new credentials; agents keep signing with IAM |
| AgentCore Observability / CloudWatch | What happened? | Interceptor decisions are logged and metered alongside gateway traces |

## 9. Deployment and integration paths (about 300 words)

### Deploying from AWS Marketplace

Describe the recommended packaging (see open item 1). One paragraph on what the CloudFormation template deploys:

- the interceptor Lambda function
- the policy parameter
- the reference to the API key secret
- CloudWatch metrics
- the attachment to a gateway, with least-privilege IAM

Inputs: a gateway, a Skyflow vault and an API key.

### Integration paths

1. **Existing AgentCore Gateway:** attach the interceptor to the gateway you already run. No change to agents or tools.
2. **New agents:** put tools behind AgentCore Gateway from day one and attach the interceptor.
3. **MCP servers outside AWS:** front them as gateway MCP server targets so their traffic passes the interceptor. Note that targets the interceptor can't inspect are blocked by default, not silently passed through.
4. **Document stores:** any tool that returns signed URLs (Amazon S3, Box, Google Drive) is covered by an allowlist entry in the policy.

### Skyflow deployment models (modeled on Stardog's "Cloud compared to self-managed")

One paragraph on Skyflow's vault options and Region choice, with a link to the deployment-models doc. Ask product marketing for the canonical wording.

### GA and preview status (modeled on Stardog's transparency)

- String de-identification and re-identification: GA.
- File de-identification through signed URLs: uses Skyflow Detect v2, currently in preview and enabled per vault. *[Confirm the status for the publish date.]*

## 10. Conclusion and "Where to start" (about 250 words)

**Conclusion:** two to three sentences.

- Agents are only as trustworthy as the data they move.
- AgentCore Gateway gives you one place where every tool call passes.
- Skyflow turns that place into a privacy control without changing a line of agent code.

**Where to start** (numbered, as in Stardog's):

1. Pick one agent workflow that touches customer data and calls at least one tool outside your account.
2. List the entity types that must never leave, and the tools that may see them.
3. Subscribe to Skyflow in AWS Marketplace and launch the CloudFormation template against that gateway.
4. Start with the default policy (shield the tool), then add "shield the model" for web content and "shield the document" for your document store.
5. Watch the interceptor's CloudWatch metrics for a week before widening the rollout.

**Further reading:**

- AWS Marketplace listing *[link TBD]*
- Skyflow Detect documentation
- Skyflow SDKs
- Skyflow deployment models
- AgentCore Gateway interceptors documentation
- AgentCore Policy documentation

## 11. About the authors

- **Joe McCarron**, Head of Developer Advocacy & Product Lead, Skyflow. *[Two to three line bio + headshot]*
- **[AWS author]**, *[title]*, AWS. *[bio + headshot]*

---

## Open items

1. **Marketplace packaging.** Recommendation: a CloudFormation template, launched from the listing, that deploys only the interceptor and attaches it to the customer's existing gateway. The repo's Strands agent, web console and demo targets stay out of it.
   - **How Marketplace fits:** Marketplace transacts the Skyflow subscription (a SaaS listing). The template deploys the interceptor, with a "Launch stack" link from the listing and the docs.
   - **To confirm with AWS:**
     - whether a template-delivered Lambda product can be listed directly, or must sit beside a SaaS listing
     - whether the AgentCore Gateway CloudFormation resource now supports interceptor configuration natively. If it doesn't, the template needs a custom resource for the attach step.
2. **Banking-flavored demo content.** The repo's sample is an insurance claim note. For the video and screenshots, add a card-dispute case note with fictional data. Recording the video means updating the sample and rerunning the demo.
3. **Customer reference clearance.** Confirm that the anonymized description in section 3 is approved, and whether a quote is possible.
4. **AWS co-authors.** Ask our AWS contact.
5. **Detect v2 status** at the publish date, for the GA/preview paragraph.
6. **Production performance numbers** to replace the sample table in section 6.
7. **Product name.** Confirm what we call the interceptor in the listing, so the post, listing and docs match.
