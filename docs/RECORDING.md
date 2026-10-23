# Recording the blog demo

This is the script for the two-to-three-minute video and the screenshots in the
blog post. It follows the post's card-dispute example: an analyst asks the
agent to look into a disputed transaction, the agent searches the web for the
merchant, then pulls the case note from S3.

Run every command from the repository root. `docs/DEMO.md` explains what each
step proves in more depth.

| Scene | What the viewer sees | Blog figure |
| --- | --- | --- |
| 1. Shield the tool | The search provider receives a token for the customer's name; the analyst still reads the real name | Video part 1 |
| 2. Shield the document | The agent gets a link to a Skyflow-hosted clean copy of the case note | Video part 2, Figure 4 |
| 3. Policy without redeploys | Switching documents to one-way tokens takes effect a minute later | Video part 3 |

Figures 1 to 3 are diagrams rather than screenshots, so they are not produced
here.

## Before the session

Do this the day before. None of it should be on camera.

**1. Set the shell up.** Every later command uses these.

```bash
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
export BUCKET="agentcore-skyflow-files-$(aws sts get-caller-identity --query Account --output text)"
export LOG_GROUP=$(aws cloudformation describe-stacks --stack-name SkyflowInterceptorStack \
  --query "Stacks[0].Outputs[?OutputKey=='InterceptorLogGroupName'].OutputValue" --output text)
PY=app/Flow/.venv/bin/python
```

**2. Deploy the interceptor with upstream logging allowed.** Scene 1 shows the
query the search provider received, which comes from the interceptor's log. The
stack refuses payload logging unless it is deployed to allow it.

```bash
cd gateway/interceptor/cdk
npm ci && npm run build
npx cdk deploy --require-approval never -c allowUpstreamPayloadLogging=true
cd -
```

**3. Deploy the agent and gateway, then check the interceptor is attached.**
This ships the agent and gateway changes on this branch. The gateway knows
nothing about the interceptor, so confirm a deploy has not left it without one.

```bash
agentcore deploy --target dev -y
$PY scripts/attach_interceptor.py --gateway-name agentflow-SkyflowGateway --check
```

If the check prints `FAIL`, re-attach with step 3 of the main README and check
again.

**4. Publish the shipped policy, then switch scene 1's logging on.**

```bash
$PY scripts/demo_policy.py reset
$PY scripts/demo_policy.py show-upstream-search
```

The second command turns on payload logging for `web_search_exa` only. It has no
effect on any other tool.

**5. Upload the case note.**

```bash
python3 scripts/make_samples.py
$PY scripts/create_documents_bucket.py --region $AWS_REGION --upload-samples
```

**6. Run the pre-flight check.** This fetches the case note through the gateway
exactly as the agent will, and fails if anything about the swap is wrong.

```bash
$PY scripts/show_document.py samples/dispute-case-note.txt
$PY scripts/show_document.py samples/dispute-case-note.docx
$PY scripts/show_document.py samples/dispute-case-note.pdf
```

Each should end with `OK`, except the PDF, which is not compared: open the copy
it saves and check the values are tokens. The case note includes a card number,
which no earlier sample did. If only these runs fail, the vault most likely has
no column for card numbers: add `table1.credit_card_entity`, or point a
`credit_card` entry in the policy's `files.destinations` at a column that
exists. The failure message in the interceptor log carries Skyflow's reason.

**7. Choose the region you show.** The clean copy's URL names the bucket and
region of the Skyflow vault's environment. A trial vault answers from
`us-west-2`, which undercuts the post's UK and EU residency story. Record
against an EU vault if you can. Otherwise keep the URL host out of frame and
crop it from screenshots.

## Recording

Open the Flow runtime's test pane in the AgentCore console. `docs/DEMO.md` has
the command that prints its link. Keep a terminal ready beside it, with the
shell set up as in step 1.

### Scene 1: shield the tool

Prompt the agent:

```
Search the web for "Daniel Okonkwo dispute ACME Electronics London" and tell me what you find about the merchant.
```

The console shows the `exa___web_search_exa` tool call with the customer's real
name in its arguments. That is what the agent sent to the gateway. Then show
what the search provider actually received:

```bash
aws logs filter-log-events --log-group-name "$LOG_GROUP" --filter-pattern upstream_request \
  --start-time "$(( $(date +%s) - 300 ))000" --query 'events[-1].message' --output text
```

The query reads `[NAME_…] dispute ACME Electronics London`. The name is a vault
token. London survives because the search rule's entity list leaves out
locations, so the results are still about the right merchant. The agent's
answer uses the real name again, because the response was re-identified on the
way back.

The model writes its own search query, so it may phrase it differently from the
prompt. Whatever it sends, the log shows the name tokenized.

### Scene 2: shield the document

Prompt the agent:

```
Get the case note samples/dispute-case-note.txt and give me the download link.
```

The agent returns a link to a Skyflow-hosted copy rather than to your bucket.
The tool call in the console shows that URL too. Then show the two side by side
in the terminal. This output is Figure 4:

```bash
$PY scripts/show_document.py samples/dispute-case-note.txt
```

Tokens with a long random suffix, such as `[NAME_AJbrIud]`, are vault tokens
that someone with vault permissions can reverse.

### Scene 3: a policy change without a redeploy

Switch documents to one-way tokens, live:

```bash
$PY scripts/demo_policy.py one-way-documents
```

The interceptor rereads its policy within sixty seconds. Wait a minute, then
send scene 2's prompt again and run the comparison again. The tokens now read
`[NAME_1]`: one-way counters that nothing can reverse. Nothing was redeployed.

## Screenshots

- **Figure 4.** The scene 2 terminal output, with a terminal wide enough that
  the two columns do not wrap.
- **The tool call with the clean link.** The console's tool-call view from
  scene 2, with the URL host cropped if step 7 applies.
- **The tokenized query.** The scene 1 log line, for readers who skip the
  video.
- **The alarms.** The post mentions CloudWatch metrics for alarms. The alarms
  are in the CloudWatch console, under names starting with
  `SkyflowInterceptorStack`.

## After the session

Put the shipped policy back, and redeploy without upstream logging:

```bash
$PY scripts/demo_policy.py reset
cd gateway/interceptor/cdk && npx cdk deploy --require-approval never && cd -
$PY scripts/attach_interceptor.py --gateway-name agentflow-SkyflowGateway --check
```

Redeploying the interceptor stack does not detach it, because its function ARN
does not change, but the check costs nothing.

## If something goes wrong

- **The agent's answer says the document was withheld.** The interceptor failed
  closed on purpose. The reason is in the log:

  ```bash
  aws logs filter-log-events --log-group-name "$LOG_GROUP" --filter-pattern fail_closed \
    --start-time "$(( $(date +%s) - 600 ))000" --query 'events[].message' --output text
  ```

- **No `upstream_request` line appears.** Either the stack was not deployed with
  `allowUpstreamPayloadLogging=true`, in which case the log has an
  `upstream_payload_logging_refused` warning, or `show-upstream-search` was not
  published. Run step 4 again.
- **The link points at your own bucket.** The interceptor is not attached. Run
  the `--check` from step 3.
- **The agent refuses to start.** It found no gateway in its environment. Run
  `agentcore deploy` again.
