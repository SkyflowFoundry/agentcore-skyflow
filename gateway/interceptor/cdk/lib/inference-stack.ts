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
  /**
   * Also add a bedrock-mantle target. It serves the OpenAI Chat Completions
   * and Responses APIs for models the Bedrock runtime target does not, such
   * as gpt-oss on Responses. Default true.
   */
  readonly mantle?: boolean;
  /** Name of the Mantle target. Default mantle. */
  readonly mantleTargetName?: string;
}

/**
 * Bedrock inference targets on the Skyflow gateway, for shield the model.
 *
 * The project schema can only express inference as a `passthrough` target, so
 * this stack adds the connector targets beside what `agentcore deploy` owns.
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
    const mantle = props.mantle ?? true;
    if (mantle) {
      // Mantle authorizes inference on the account's projects rather than on
      // model ARNs. This is the minimum policy its documentation gives for
      // SigV4 callers.
      policy.addStatements(new iam.PolicyStatement({
        actions: ['bedrock-mantle:CreateInference', 'bedrock-mantle:Get*', 'bedrock-mantle:List*'],
        resources: [`arn:aws:bedrock-mantle:${this.region}:${this.account}:project/*`],
      }));
    }

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

    if (mantle) {
      const mantleTarget = new agentcore.CfnGatewayTarget(this, 'MantleInference', {
        gatewayIdentifier: props.gatewayIdentifier,
        name: props.mantleTargetName ?? 'mantle',
        description: 'Amazon Bedrock models on the OpenAI APIs through Mantle, shielded by the Skyflow interceptor',
        targetConfiguration: {},
        credentialProviderConfigurations: [{ credentialProviderType: 'GATEWAY_IAM_ROLE' }],
      });
      mantleTarget.addPropertyOverride('TargetConfiguration', {
        Inference: { Connector: { Source: { ConnectorId: 'bedrock-mantle' } } },
      });
      mantleTarget.node.addDependency(policy);
      // Created after the Bedrock target, one at a time, as every live run did.
      mantleTarget.node.addDependency(target);
      new cdk.CfnOutput(this, 'MantleTargetId', {
        value: mantleTarget.attrTargetId,
        description: 'Gateway target that serves /inference for Bedrock models through Mantle',
      });
    }

    cdk.Tags.of(this).add('agentcore:component', 'skyflow-inference-target');
  }
}
