#!/usr/bin/env node
import * as fs from 'fs';
import * as path from 'path';
import * as cdk from 'aws-cdk-lib';
import { InterceptorStack } from '../lib/interceptor-stack';

const app = new cdk.App();

// dist/bin/interceptor.js -> repo root
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..', '..');
const TARGETS_FILE = path.join(REPO_ROOT, 'agentcore', 'aws-targets.json');

interface AwsTarget {
  name: string;
  account: string;
  region: string;
}

/**
 * Resolve account and region from agentcore/aws-targets.json.
 *
 * The interceptor Lambda must live in the same region as the gateway that
 * invokes it. The gateway is deployed by `agentcore deploy` from
 * aws-targets.json, so this stack reads the same file rather than inheriting
 * the ambient AWS CLI default region — those are easy to have disagree, and the
 * failure mode (gateway and interceptor in different regions) is not obvious.
 */
function resolveEnv(): { account: string; region: string } {
  const override = {
    account: app.node.tryGetContext('account'),
    region: app.node.tryGetContext('region'),
  };
  if (override.account && override.region) {
    return { account: override.account, region: override.region };
  }

  if (!fs.existsSync(TARGETS_FILE)) {
    throw new Error(
      `Cannot resolve deployment target: ${TARGETS_FILE} not found. ` +
        'Pass -c account=<id> -c region=<region> instead.',
    );
  }

  const targets: AwsTarget[] = JSON.parse(fs.readFileSync(TARGETS_FILE, 'utf8'));
  if (targets.length === 0) {
    throw new Error(
      `${TARGETS_FILE} is empty. Add a deployment target, or pass -c account=<id> -c region=<region>.`,
    );
  }

  const wanted = app.node.tryGetContext('target');
  const target = wanted ? targets.find((t) => t.name === wanted) : targets[0];
  if (!target) {
    throw new Error(
      `No target named '${wanted}' in ${TARGETS_FILE}. Available: ${targets.map((t) => t.name).join(', ')}`,
    );
  }

  return {
    account: override.account ?? target.account,
    region: override.region ?? target.region,
  };
}

/**
 * Required context (pass with -c):
 *   skyflowVaultUrl   https://<cluster>.vault.skyflowapis.com
 *   skyflowVaultId    vault ID
 * Optional:
 *   skyflowSecretName Secrets Manager secret name (default skyflow/detect-api-key)
 *   target            aws-targets.json entry to deploy into (default: first)
 *   account / region  override aws-targets.json entirely
 */
function required(name: string): string {
  const value = app.node.tryGetContext(name);
  if (!value) {
    throw new Error(`Missing required context '${name}'. Pass it with: cdk deploy -c ${name}=<value>`);
  }
  return value;
}

const env = resolveEnv();

new InterceptorStack(app, 'SkyflowInterceptorStack', {
  env,
  skyflowVaultUrl: required('skyflowVaultUrl'),
  skyflowVaultId: required('skyflowVaultId'),
  skyflowSecretName: app.node.tryGetContext('skyflowSecretName') ?? 'skyflow/detect-api-key',
  policyCacheTtlSeconds: Number(app.node.tryGetContext('policyCacheTtlSeconds') ?? 60),
});
