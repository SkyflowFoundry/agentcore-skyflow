import * as cdk from 'aws-cdk-lib';
import * as agentcore from 'aws-cdk-lib/aws-bedrockagentcore';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface InferenceStackProps extends cdk.StackProps {
  /**
   * Identifier of the gateway `agentcore deploy` created, such as
   * skyflowgateway-abc123. The target joins that gateway, so its interceptor
   * shields the model calls the target serves.
   */
  readonly gatewayIdentifier: string;
  /** ARN of that gateway's execution role, which calls Amazon Bedrock. */
  readonly gatewayRoleArn: string;
  /**
   * Target name. Clients may qualify a model with it, as in
   * bedrock/global.anthropic.claude-sonnet-5. Default bedrock.
   */
  readonly targetName?: string;
}

/**
 * A Bedrock inference target on the Skyflow gateway, for shield the model.
 *
 * The project schema can only express inference as a `passthrough` target, so
 * this stack adds the connector target beside what `agentcore deploy` owns.
 * It deploys after `agentcore deploy`, because the gateway has to exist first,
 * and it leaves the gateway itself alone.
 */
export class InferenceStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: InferenceStackProps) {
    super(scope, id, props);

    // The gateway role calls Bedrock for every model call the target serves.
    // Model discovery also lists models, profiles and routers, and the target
    // never reaches READY without those permissions. The list is the set the
    // inference target documentation names, in place of bedrock:List*.
    const role = iam.Role.fromRoleArn(this, 'GatewayRole', props.gatewayRoleArn, { mutable: true });
    const policy = new iam.Policy(this, 'GatewayInferencePolicy', {
      roles: [role],
      statements: [
        new iam.PolicyStatement({
          actions: ['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'],
          // Cross-Region inference profiles route to foundation models in
          // other Regions, so the model ARNs cannot name one Region.
          resources: [
            'arn:aws:bedrock:*::foundation-model/*',
            `arn:aws:bedrock:*:${this.account}:inference-profile/*`,
            `arn:aws:bedrock:*:${this.account}:application-inference-profile/*`,
          ],
        }),
        new iam.PolicyStatement({
          actions: [
            'bedrock:ListFoundationModels',
            'bedrock:ListInferenceProfiles',
            'bedrock:ListProvisionedModelThroughputs',
            'bedrock:ListCustomModelDeployments',
            'bedrock:ListImportedModels',
            'bedrock:ListMarketplaceModelEndpoints',
            'bedrock:ListPromptRouters',
            'bedrock:GetInferenceProfile',
            'bedrock:GetFoundationModel',
          ],
          // List actions take no resource ARN.
          resources: ['*'],
        }),
      ],
    });

    const target = new agentcore.CfnGatewayTarget(this, 'BedrockInference', {
      gatewayIdentifier: props.gatewayIdentifier,
      name: props.targetName ?? 'bedrock',
      description: 'Amazon Bedrock models, shielded by the Skyflow interceptor',
      // CloudFormation models inference targets but this CDK version does not
      // yet, so the configuration goes in as a raw property override.
      targetConfiguration: {},
      credentialProviderConfigurations: [{ credentialProviderType: 'GATEWAY_IAM_ROLE' }],
    });
    target.addPropertyOverride('TargetConfiguration', {
      Inference: { Connector: { Source: { ConnectorId: 'bedrock-runtime' } } },
    });
    target.node.addDependency(policy);

    new cdk.CfnOutput(this, 'InferenceTargetId', {
      value: target.attrTargetId,
      description: 'Gateway target that serves /inference for Bedrock models',
    });

    cdk.Tags.of(this).add('agentcore:component', 'skyflow-inference-target');
  }
}
