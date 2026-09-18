import { defineBackend } from '@aws-amplify/backend';
import { Stack } from 'aws-cdk-lib';
import { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { auth } from './auth/resource';

/**
 * The console's backend is just authentication. Cognito issues the signed-in
 * user temporary AWS credentials, and those credentials need exactly one
 * permission: to invoke the Flow AgentCore Runtime agent. Everything else about
 * the agent, the gateway and the Skyflow interceptor is owned by the separate
 * CDK / agentcore deployment and is not touched here.
 */
const backend = defineBackend({
  auth,
});

const authenticatedRole = backend.auth.resources.authenticatedUserIamRole;
const stack = Stack.of(authenticatedRole);

// Prefer the exact runtime ARN (least privilege). Set FLOW_AGENT_RUNTIME_ARN in
// the Amplify build environment. If it is absent we fall back to any runtime in
// this account and region, which is fine for a demo but should be tightened.
const runtimeArn = process.env.FLOW_AGENT_RUNTIME_ARN;
const resources = runtimeArn
  ? [runtimeArn, `${runtimeArn}/runtime-endpoint/*`]
  : [
      `arn:aws:bedrock-agentcore:${stack.region}:${stack.account}:runtime/*`,
      `arn:aws:bedrock-agentcore:${stack.region}:${stack.account}:runtime/*/runtime-endpoint/*`,
    ];

authenticatedRole.addToPrincipalPolicy(
  new PolicyStatement({
    actions: ['bedrock-agentcore:InvokeAgentRuntime'],
    resources,
  }),
);
