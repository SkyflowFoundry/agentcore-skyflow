# Console (web UI) for the Flow agent

A small React app that puts a **Cognito login** and a **chat interface** in front
of the `Flow` agent that this repository already deploys to AgentCore Runtime.

It is deliberately thin. The signed-in user gets temporary AWS credentials from
Cognito and calls the Flow runtime **directly from the browser** — there is no
new server to run. The agent, the gateway, and the Skyflow interceptor are
unchanged; the point of the demo is that Flow's tool calls are de-identified by
Skyflow at the gateway while the user just chats normally.

## What's here

- **Auth + hosting: AWS Amplify.** `amplify/` defines a Cognito User Pool and
  Identity Pool (`ampx`), and Amplify Hosting builds and serves the SPA.
- **Chat UI: Cloudscape** chat components, styled to match the AWS console.
- **Agent call: `src/agentClient.js`.** Invokes `Flow` with
  `InvokeAgentRuntimeCommand` and renders its streamed response as it arrives.

The design follows the patterns in AWS's "secure chat UI for Amazon Bedrock"
guidance (Cognito Identity Pool credentials, browser-direct invocation, a
Cloudscape chat surface); the code here is written for this repo, trimmed to the
AgentCore Runtime path only.

## Configuration

The app needs to know which runtime to call. Set these (in `.env` for local dev,
or as Amplify build environment variables when hosted):

| Variable | Meaning |
| --- | --- |
| `VITE_AGENT_REGION` | Region of the Flow runtime, e.g. `us-east-1` |
| `VITE_FLOW_AGENT_RUNTIME_ARN` | Full ARN of the Flow runtime (`agentcore status`) |
| `VITE_FLOW_AGENT_QUALIFIER` | Optional endpoint qualifier (defaults to `DEFAULT`) |

Copy `.env.example` to `.env` and fill it in.

## Run locally

```bash
cd ui
npm install
npx ampx sandbox        # provisions a personal Cognito pool + writes amplify_outputs.json
npm run dev             # http://localhost:5173
```

Create a user to sign in with (self sign-up is off), e.g.:

```bash
aws cognito-idp admin-create-user --user-pool-id <poolId> --username you@example.com
aws cognito-idp admin-set-user-password --user-pool-id <poolId> \
  --username you@example.com --password '<Password1!>' --permanent
```

## Deploy (a live URL to test)

1. In the AWS console, open **Amplify → Create app → connect this GitHub repo**
   and pick this branch.
2. Set the app's **monorepo app root to `ui`** (this file's directory).
3. Add the build environment variables `VITE_FLOW_AGENT_RUNTIME_ARN` and
   `VITE_AGENT_REGION`. Optionally set `FLOW_AGENT_RUNTIME_ARN` (same value) so
   the Cognito role is scoped to exactly that runtime instead of all runtimes in
   the account.
4. Deploy. Amplify runs `amplify.yml`: it provisions Cognito (backend phase) and
   builds the SPA (frontend phase), then serves it over HTTPS at an Amplify URL.

Then create a user in the new Cognito pool (as above) and sign in.

## Not in scope (yet)

No message de-identification at ingress, no Skyflow guardrails, no role-based
re-identification, and no Entra federation. Those can be layered on later; this
console is just auth + chat for the existing Flow agent.
