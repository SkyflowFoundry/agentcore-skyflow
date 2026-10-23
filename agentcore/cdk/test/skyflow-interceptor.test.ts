import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import type { AgentCoreMcpSpec, AgentCoreProjectSpec } from '@aws/agentcore-cdk';
import { AgentCoreStack, INTERCEPTOR_ARN_EXPORT, SKYFLOW_GATEWAY_NAME } from '../lib/cdk-stack';

// The escape hatch in lib/cdk-stack.ts is the only thing keeping the Skyflow
// interceptor on the gateway across `agentcore deploy`. These pin what it emits.

const RUNTIME_ARN = 'arn:aws:bedrock-agentcore:us-east-1:111111111111:runtime/test';

function gatewaySpec(name: string): AgentCoreMcpSpec {
  return {
    agentCoreGateways: [
      {
        name,
        protocolType: 'MCP',
        authorizerType: 'AWS_IAM',
        enableSemanticSearch: true,
        exceptionLevel: 'NONE',
        targets: [
          {
            name: 'exa',
            targetType: 'mcpServer',
            endpoint: 'https://mcp.exa.ai/mcp',
            outboundAuth: { type: 'NONE' },
          },
        ],
      },
    ],
    mcpRuntimeTools: [],
    unassignedTargets: [],
  } as unknown as AgentCoreMcpSpec;
}

function synth(options: { gatewayName?: string; context?: Record<string, string> } = {}): Template {
  const mcpSpec = gatewaySpec(options.gatewayName ?? SKYFLOW_GATEWAY_NAME);
  const spec = {
    name: 'testproject',
    version: 1,
    managedBy: 'CDK' as const,
    runtimes: [],
    memories: [],
    credentials: [],
    evaluators: [],
    onlineEvalConfigs: [],
    configBundles: [
      {
        name: 'TestConfig',
        type: 'ConfigurationBundle',
        components: { [RUNTIME_ARN]: { configuration: { systemPrompt: 'test' } } },
        branchName: 'mainline',
        commitMessage: 'test',
      },
    ],
    policyEngines: [],
    payments: [],
    agentCoreGateways: mcpSpec.agentCoreGateways,
    mcpRuntimeTools: [],
    unassignedTargets: [],
    datasets: [],
    knowledgeBases: [],
  } as unknown as AgentCoreProjectSpec;

  const app = new cdk.App({ context: options.context });
  return Template.fromStack(new AgentCoreStack(app, 'TestStack', { spec, mcpSpec }));
}

function gatewayResource(template: Template): { Properties: Record<string, unknown>; DependsOn?: string[] } {
  const gateways = Object.values(template.findResources('AWS::BedrockAgentCore::Gateway'));
  expect(gateways).toHaveLength(1);
  return gateways[0] as { Properties: Record<string, unknown>; DependsOn?: string[] };
}

test('the gateway carries the interceptor at both points without request headers', () => {
  const template = synth();

  template.hasResourceProperties('AWS::BedrockAgentCore::Gateway', {
    InterceptorConfigurations: [
      {
        Interceptor: { Lambda: { Arn: { 'Fn::ImportValue': INTERCEPTOR_ARN_EXPORT } } },
        InterceptionPoints: ['REQUEST', 'RESPONSE'],
        InputConfiguration: { PassRequestHeaders: false },
      },
    ],
  });
});

test('an interceptorFunctionArn context value replaces the stack export', () => {
  const arn = 'arn:aws:lambda:us-east-1:111111111111:function:interceptor';
  const template = synth({ context: { interceptorFunctionArn: arn } });

  template.hasResourceProperties('AWS::BedrockAgentCore::Gateway', {
    InterceptorConfigurations: [Match.objectLike({ Interceptor: { Lambda: { Arn: arn } } })],
  });
  expect(JSON.stringify(template.toJSON())).not.toContain('Fn::ImportValue');
});

test('the gateway role may invoke the interceptor before the gateway is created or updated', () => {
  const template = synth();

  const invokePolicies = template.findResources('AWS::IAM::Policy', {
    Properties: {
      PolicyDocument: {
        Statement: [
          {
            Action: 'lambda:InvokeFunction',
            Effect: 'Allow',
            Resource: { 'Fn::ImportValue': INTERCEPTOR_ARN_EXPORT },
          },
        ],
      },
      Roles: [{ Ref: Match.stringLikeRegexp('GatewaySkyflowGatewayRole') }],
    },
  });
  const invokePolicyIds = Object.keys(invokePolicies);
  expect(invokePolicyIds).toHaveLength(1);
  expect(gatewayResource(template).DependsOn).toContain(invokePolicyIds[0]);
});

test('the gateway role may read the project config bundles and the gateway does not wait for it', () => {
  const template = synth();

  const bundleIds = Object.keys(template.findResources('AWS::BedrockAgentCore::ConfigurationBundle'));
  expect(bundleIds).toHaveLength(1);

  const readPolicies = template.findResources('AWS::IAM::Policy', {
    Properties: {
      PolicyDocument: {
        Statement: [
          {
            Action: 'bedrock-agentcore:GetConfigurationBundleVersion',
            Effect: 'Allow',
            Resource: { Ref: bundleIds[0] },
          },
        ],
      },
      Roles: [{ Ref: Match.stringLikeRegexp('GatewaySkyflowGatewayRole') }],
    },
  });
  const readPolicyIds = Object.keys(readPolicies);
  expect(readPolicyIds).toHaveLength(1);
  // A deployed bundle depends on its runtime, which depends on the gateway, so
  // the gateway waiting on this policy would be a circular dependency.
  expect(gatewayResource(template).DependsOn ?? []).not.toContain(readPolicyIds[0]);
});

test('synth fails rather than leave a renamed gateway without the interceptor', () => {
  expect(() => synth({ gatewayName: 'RenamedGateway' })).toThrow(`no gateway named ${SKYFLOW_GATEWAY_NAME}`);
});
