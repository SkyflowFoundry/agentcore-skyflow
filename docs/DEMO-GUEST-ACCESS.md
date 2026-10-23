# Plan: guest access for the demo UI

## Status

Proposed on 23 October 2026. Nothing in this plan has been built or deployed.

## Problem

The demo UI in `ui/` exists for recorded demos that Claude drives from start to finish. Claude cannot sign in to it.

Claude types a test password only on a local address or on a host whose name marks a test environment. The password must also stay inside that environment. The hosted site sends its sign-in to Cognito at `cognito-idp.us-east-1.amazonaws.com` so it meets neither condition. Ownership of the site does not change this.

A recorded demo must show the real hosted site. A demo recorded on localhost reads as "it works on my machine" and does not show a product a customer can trust.

## Decision

Keep the Cognito sign-in for real users. Add a demo entrance to the sign-in screen that uses the identity pool's guest credentials. Nobody types a password. Claude clicks the button on camera and the chat opens on the hosted site.

## Rejected options

1. **A person signs in for the recording.** The demo's owner has ruled this out.
2. **A local build with a stand-in sign-in.** It would not show the hosted product.
3. **A demo key in a query string.** A key in a URL leaks through browser history and server logs and screenshots. Claude will not put a credential in a URL.
4. **Removing Cognito.** The browser still needs AWS credentials to call the agent. Without Cognito the site would need a new backend proxy that holds its own credentials. That is more work for a weaker result.

## What exists today

These values come from read-only checks on 23 October 2026.

| Item | Value |
| --- | --- |
| Amplify app | `agentcore-skyflow-console` with app id `d3vw9iglke62uz` and branch `main` |
| Site | [main.d3vw9iglke62uz.amplifyapp.com](https://main.d3vw9iglke62uz.amplifyapp.com/) |
| Deploys | Manual because the app has no repository connection. The last deploy finished on 18 September 2026. |
| User pool | `us-east-1_52qyYPCaO` with one user and MFA off |
| Identity pool | `us-east-1:f5500c05-85b1-4d7c-8834-68a36c9c627f` with guest identities allowed |
| Signed-in role | Allows `bedrock-agentcore:InvokeAgentRuntime` on the Flow runtime and its endpoints |
| Guest role | Exists with no policies so guests can do nothing |

The checks also found two gaps.

1. **Self sign-up is open.** The user pool has `AllowAdminCreateUserOnly` set to false. `ui/README.md` says self sign-up is off and the UI hides the button. Anyone who reads the client ID from the site's JavaScript can still register through the Cognito API and then call the agent.
2. **The backend's deploy path is unknown.** `ui/README.md` describes both `npx ampx sandbox` and `ampx pipeline-deploy`. Nobody has confirmed which one produced the live pools.

## Design

### Backend change

In `ui/amplify/backend.ts` set the user pool's `AllowAdminCreateUserOnly` to true. This closes the self sign-up gap. It is the only backend change.

### Demo button

1. In `ui/src/App.jsx` add a "Continue as demo analyst" button to the Authenticator's sign-in screen through its `components.SignIn.Footer` slot.
2. When the button is clicked render the app shell with the label "Demo analyst" instead of a Cognito user.
3. Show the button only when the build sets `VITE_DEMO_GUEST=true`. A customer-facing build leaves it out.
4. `ui/src/agentClient.js` should need no change because `fetchAuthSession()` returns guest credentials when nobody is signed in. Confirm that `amplify_outputs.json` has `unauthenticated_identities_enabled` set to true.

### Switching guest access on and off

Add `scripts/demo_access.py` with three commands.

1. `on --cidr <range>` puts an inline policy named `demo-guest-invoke` on the guest role. The policy allows only `bedrock-agentcore:InvokeAgentRuntime` on the Flow runtime ARN and its `runtime-endpoint/*` children. It carries an `IpAddress` condition on `aws:SourceIp` with the approved ranges. `--cidr` can repeat.
2. `off` deletes that inline policy.
3. `status` prints whether the policy is attached and which ranges it allows.

The script finds the guest role from the identity pool and the runtime ARN from `agentcore/.cli/deployed-state.json`. The policy stays out of the Amplify backend on purpose. Toggling a resource that CloudFormation owns would create drift.

The IP condition works because the browser calls the AgentCore endpoint directly with SigV4. AWS therefore sees the viewer's own public address.

### Risks

1. While access is on anyone at an approved address can run the agent and its tools in this account. Model calls and web searches cost money.
2. The S3 tool can list and fetch documents in the documents bucket. The interceptor swaps each document for a de-identified copy before the agent sees it.
3. An approved range that covers a shared office network gives everyone on that network access.

Keep access off except during recordings. Use the narrowest range possible. Consider an AWS Budgets alert on the account.

## Steps

1. Create a branch from an up-to-date main.
2. Find out how the live backend was deployed. Compare the CloudFormation stack names with the names that `npx ampx sandbox` and `ampx pipeline-deploy` produce.
3. Turn off self sign-up in `ui/amplify/backend.ts` and deploy the backend the same way it was deployed before.
4. Add the demo button behind `VITE_DEMO_GUEST`.
5. Build the site with `VITE_DEMO_GUEST=true` and deploy it to the Amplify app by hand as before.
6. Write `scripts/demo_access.py`.
7. Run the checks under Verification.
8. Update the recording script and re-record the two document scenes.
9. Open a PR.

## Verification

1. With access off the demo button opens the chat but the agent call fails with AccessDenied.
2. With access on from an approved address the agent answers.
3. With access on from any other address the call fails with AccessDenied. To test this set the range to a documentation address such as `192.0.2.1/32`.
4. A self sign-up call through the Cognito API fails.
5. The existing Cognito user can still sign in.

## Recording changes

The recording scripts are not in the repository. A copy lives in `/Users/joe/Code/agentcore/demo-out/scripts/` on the machine that recorded the demo.

1. `ui-flow.mjs` restores a saved Cognito session today. Change it to open the sign-in screen and click "Continue as demo analyst" on camera. Everything after that stays the same.
2. `edit_cut_v2.py` builds the narrated cut. Its second beat shows the sign-in screen and should show the button click instead.
3. `narration.json` holds the narration script. The line "The analyst signs in" still fits.
4. Run `demo_access.py on` before recording and `demo_access.py off` straight after.

## Open questions

1. Which address ranges to approve.
2. Whether the demo button should ever ship in a customer-facing build.
