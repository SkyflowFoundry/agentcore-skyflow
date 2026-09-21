import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

export interface InterceptorStackProps extends cdk.StackProps {
  /** Skyflow vault host, e.g. https://abcd.vault.skyflowapis.com */
  readonly skyflowVaultUrl: string;
  /** Skyflow vault ID. */
  readonly skyflowVaultId: string;
  /**
   * Name of an existing Secrets Manager secret holding the long-lived Skyflow
   * API key. Imported rather than created, so the key survives `cdk destroy`
   * and is never present in a CloudFormation template or synth output.
   */
  readonly skyflowSecretName: string;
  /** Seconds the Lambda caches the policy before re-reading SSM. */
  readonly policyCacheTtlSeconds?: number;
}

/**
 * Skyflow de-identify/re-identify interceptor for an AgentCore Gateway.
 *
 * Deploys the interceptor Lambda plus the SSM parameter holding its redaction
 * policy. Attaching the function to a gateway is a separate step — the
 * AgentCore CLI cannot declare interceptors, so `scripts/attach_interceptor.py`
 * calls `update-gateway` after `agentcore deploy`.
 */
export class InterceptorStack extends cdk.Stack {
  public readonly interceptorFunction: lambda.Function;
  public readonly policyParameter: ssm.StringParameter;

  constructor(scope: Construct, id: string, props: InterceptorStackProps) {
    super(scope, id, props);

    // Resolved from the compiled location: tsc emits to dist/ preserving the
    // source layout, so this file runs as dist/lib/interceptor-stack.js and the
    // interceptor root is three levels up, not two.
    const interceptorRoot = path.resolve(__dirname, '..', '..', '..');

    // The repo file is the source of truth for policy. `cdk deploy` publishes
    // it; scripts/put_policy.py pushes edits without a full deploy, and the
    // Lambda picks them up within its cache TTL.
    const policyPath = path.join(interceptorRoot, 'config', 'policy.json');
    if (!fs.existsSync(policyPath)) {
      throw new Error(`Policy file not found at ${policyPath} (resolved from ${__dirname})`);
    }
    const policyBody = fs.readFileSync(policyPath, 'utf8');
    JSON.parse(policyBody); // fail synth on malformed policy rather than at runtime

    this.policyParameter = new ssm.StringParameter(this, 'RedactionPolicy', {
      parameterName: '/agentcore/interceptor/skyflow-policy',
      stringValue: policyBody,
      description: 'Skyflow interceptor redaction policy (per-server, per-tool)',
      tier: ssm.ParameterTier.STANDARD,
    });

    const skyflowSecret = secretsmanager.Secret.fromSecretNameV2(
      this,
      'SkyflowApiKey',
      props.skyflowSecretName,
    );

    const logGroup = new logs.LogGroup(this, 'InterceptorLogs', {
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    this.interceptorFunction = new lambda.Function(this, 'SkyflowInterceptor', {
      runtime: lambda.Runtime.PYTHON_3_13,
      handler: 'handler.lambda_handler',
      code: lambda.Code.fromAsset(path.join(interceptorRoot, 'src'), {
        exclude: ['__pycache__', '*.pyc', '.pytest_cache'],
      }),
      // A file de-identification is submitted and then polled until it
      // finishes, so the ceiling is set by how long a document takes rather
      // than by a single API call. The handler bounds its own polling by the
      // remaining Lambda time, so this is an upper limit rather than a target.
      //
      // The gateway held a connection open for 298 seconds without giving up,
      // so nothing upstream imposes a shorter ceiling than this one. How long a
      // document actually takes depends on the vault being called: a shared
      // trial vault managed 446 KiB in about 94 seconds where a production
      // vault running on GPUs is far faster.
      timeout: cdk.Duration.seconds(300),
      memorySize: 512,
      logGroup,
      environment: {
        POLICY_PARAMETER_NAME: this.policyParameter.parameterName,
        SKYFLOW_SECRET_ARN: skyflowSecret.secretArn,
        SKYFLOW_VAULT_URL: props.skyflowVaultUrl,
        SKYFLOW_VAULT_ID: props.skyflowVaultId,
        POLICY_CACHE_TTL_SECONDS: String(props.policyCacheTtlSeconds ?? 60),
      },
    });

    this.policyParameter.grantRead(this.interceptorFunction);
    skyflowSecret.grantRead(this.interceptorFunction);

    // The gateway service role invokes this function. That grant is added by
    // scripts/attach_interceptor.py, which knows the gateway's role ARN; it
    // cannot be expressed here because the gateway is created by the AgentCore
    // CLI in a separate stack.
    new cdk.CfnOutput(this, 'InterceptorFunctionArn', {
      value: this.interceptorFunction.functionArn,
      description: 'Pass to scripts/attach_interceptor.py',
      exportName: `${this.stackName}-InterceptorFunctionArn`,
    });

    new cdk.CfnOutput(this, 'PolicyParameterName', {
      value: this.policyParameter.parameterName,
      description: 'SSM parameter holding the redaction policy',
    });

    new cdk.CfnOutput(this, 'InterceptorLogGroupName', {
      value: logGroup.logGroupName,
      description: 'CloudWatch log group to read when a call fails closed',
    });

    cdk.Tags.of(this).add('agentcore:component', 'skyflow-interceptor');
  }
}
