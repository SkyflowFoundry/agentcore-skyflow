import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as sns from 'aws-cdk-lib/aws-sns';
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
  /**
   * Let the policy's `logUpstreamPayloads` take effect. Off by default, in
   * which case the Lambda ignores that flag: the policy changes without a
   * deploy, so this keeps payload logging a deliberate, deployed decision.
   */
  readonly allowUpstreamPayloadLogging?: boolean;
  /**
   * Seconds the last good policy keeps serving while SSM cannot be read or
   * holds a policy that does not parse. After that the interceptor fails
   * closed. Default 3600.
   */
  readonly policyMaxStaleSeconds?: number;
  /** Per-request timeout for Skyflow calls, in seconds. Default 5. */
  readonly skyflowTimeoutSeconds?: number;
  /**
   * SSM parameter holding the policy. Defaults to
   * /agentcore/interceptor/skyflow-policy; set it to run two interceptors in
   * one account and region without them overwriting each other's policy.
   */
  readonly policyParameterName?: string;
  /** `standard` (4 KB, the default) or `advanced` (8 KB, billed). */
  readonly policyParameterTier?: 'standard' | 'advanced';
  /** Days to keep the interceptor's logs. Default 30. */
  readonly logRetentionDays?: number;
  /**
   * CloudWatch namespace for the interceptor's metrics. Default
   * SkyflowInterceptor. Give a second deployment in the same account its own,
   * or its alarms will count the first one's failures too.
   */
  readonly metricNamespace?: string;
  /** SNS topic the alarms notify. Without one they still change state. */
  readonly alarmTopicArn?: string;
}

/**
 * Log terms that become metrics. Each name is the metric, each list the log
 * terms that count towards it. The handler and settings modules emit these
 * terms, and tests in gateway/interceptor/tests pin them.
 */
const METRICS: Array<[string, string[], string | null]> = [
  // [metric, log terms, alarm description or null for no alarm]
  ['FailClosed', ['request_fail_closed', 'response_fail_closed', 'inference_fail_closed'],
    'A tool or model call was blocked because de-identification could not complete.'],
  ['FailOpen', ['request_fail_open', 'response_fail_open', 'inference_fail_open'],
    'A tool or model call went through unprotected because a fail_open rule hit an error.'],
  ['PolicyUnavailable', ['policy_load_failed', 'policy_refresh_failed'],
    'The interceptor could not read its policy from SSM and is serving a stale one or failing closed.'],
  ['HttpPayloadBlocked', ['http_payload_blocked'], null],
  ['HttpPayloadPassthrough', ['http_payload_passthrough'],
    'An HTTP-shaped target was let through uninspected.'],
  ['InferenceBlocked', ['inference_blocked'], null],
];

/**
 * Skyflow de-identify/re-identify interceptor for an AgentCore Gateway.
 *
 * Deploys the interceptor Lambda plus the SSM parameter holding its redaction
 * policy. The AgentCore stack in agentcore/cdk imports the function ARN this
 * stack exports and attaches it to the gateway, so this stack deploys first.
 */
export class InterceptorStack extends cdk.Stack {
  public readonly interceptorFunction: lambda.Function;
  public readonly policyParameter: ssm.StringParameter;
  public readonly inferenceRecords: dynamodb.Table;

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
    // Parsing fails synth on malformed policy rather than at runtime, and the
    // minified form is what is published, so whitespace does not spend the
    // parameter's size limit. scripts/put_policy.py publishes the same form.
    const policyBody = JSON.stringify(JSON.parse(fs.readFileSync(policyPath, 'utf8')));
    const advanced = props.policyParameterTier === 'advanced';
    const limit = advanced ? 8192 : 4096;
    if (Buffer.byteLength(policyBody, 'utf8') > limit) {
      throw new Error(
        `Policy is ${Buffer.byteLength(policyBody, 'utf8')} bytes minified; the ` +
          `${advanced ? 'Advanced' : 'Standard'} SSM tier allows ${limit}.` +
          (advanced ? '' : ' Deploy with -c policyParameterTier=advanced to raise the limit to 8 KB.'),
      );
    }

    this.policyParameter = new ssm.StringParameter(this, 'RedactionPolicy', {
      parameterName: props.policyParameterName ?? '/agentcore/interceptor/skyflow-policy',
      stringValue: policyBody,
      description: 'Skyflow interceptor redaction policy (per-server, per-tool)',
      tier: advanced ? ssm.ParameterTier.ADVANCED : ssm.ParameterTier.STANDARD,
    });

    const skyflowSecret = secretsmanager.Secret.fromSecretNameV2(
      this,
      'SkyflowApiKey',
      props.skyflowSecretName,
    );

    const retentionDays = props.logRetentionDays ?? 30;
    if (!(Object.values(logs.RetentionDays) as number[]).includes(retentionDays)) {
      throw new Error(`logRetentionDays ${retentionDays} is not a retention CloudWatch Logs accepts`);
    }
    const logGroup = new logs.LogGroup(this, 'InterceptorLogs', {
      retention: retentionDays as logs.RetentionDays,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Shield the model writes one short-lived record per model call under the
    // gateway's REQUEST_ID, because the response event carries no request.
    // Records hold the rule's response settings and the tokens the request
    // minted, never user data, and expire through the TTL attribute.
    this.inferenceRecords = new dynamodb.Table(this, 'InferenceRecords', {
      partitionKey: { name: 'requestId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expiresAt',
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
      // Active tracing records each interceptor invocation, with its Skyflow
      // calls as time spent, in X-Ray and CloudWatch Application Signals.
      tracing: lambda.Tracing.ACTIVE,
      environment: {
        POLICY_PARAMETER_NAME: this.policyParameter.parameterName,
        SKYFLOW_SECRET_ARN: skyflowSecret.secretArn,
        SKYFLOW_VAULT_URL: props.skyflowVaultUrl,
        SKYFLOW_VAULT_ID: props.skyflowVaultId,
        POLICY_CACHE_TTL_SECONDS: String(props.policyCacheTtlSeconds ?? 60),
        ALLOW_UPSTREAM_PAYLOAD_LOGGING: String(props.allowUpstreamPayloadLogging ?? false),
        POLICY_MAX_STALE_SECONDS: String(props.policyMaxStaleSeconds ?? 3600),
        SKYFLOW_TIMEOUT_SECONDS: String(props.skyflowTimeoutSeconds ?? 5),
        INFERENCE_RECORD_TABLE: this.inferenceRecords.tableName,
      },
    });

    // One data point per decision worth watching, so a blocked call, an
    // unprotected one or a missing policy shows up as a metric that can be
    // alarmed on rather than only as a log line.
    const namespace = props.metricNamespace ?? 'SkyflowInterceptor';
    const alarmTopic = props.alarmTopicArn
      ? sns.Topic.fromTopicArn(this, 'AlarmTopic', props.alarmTopicArn)
      : undefined;
    for (const [name, terms, alarmDescription] of METRICS) {
      const filter = new logs.MetricFilter(this, `${name}Metric`, {
        logGroup,
        metricNamespace: namespace,
        metricName: name,
        filterPattern: logs.FilterPattern.anyTerm(...terms),
        metricValue: '1',
      });
      if (!alarmDescription) {
        continue;
      }
      const alarm = new cloudwatch.Alarm(this, `${name}Alarm`, {
        alarmDescription,
        metric: filter.metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) }),
        threshold: 1,
        evaluationPeriods: 1,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        // No log line means nothing went wrong, not that data is missing.
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      });
      if (alarmTopic) {
        alarm.addAlarmAction(new cwActions.SnsAction(alarmTopic));
      }
    }

    this.policyParameter.grantRead(this.interceptorFunction);
    skyflowSecret.grantRead(this.interceptorFunction);
    this.inferenceRecords.grant(this.interceptorFunction, 'dynamodb:PutItem', 'dynamodb:GetItem');

    // The AgentCore stack imports this export by name, attaches the function to
    // its gateway and grants the gateway role permission to invoke it. Renaming
    // the export breaks `agentcore deploy`, and CloudFormation refuses to change
    // or delete it while that stack imports it.
    new cdk.CfnOutput(this, 'InterceptorFunctionArn', {
      value: this.interceptorFunction.functionArn,
      description: 'Imported by the AgentCore stack, which attaches it to the gateway',
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
