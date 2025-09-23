#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { MCPProxyStack } from '../lib/mcp-proxy';
import { MCPProxyPersistentStack } from '../lib/mcp-proxy-persistent';
import { loadConfig, getEnvWithConfig } from '../lib/types/config';

const repoName = require('child_process')
    .execSync('git config --get remote.origin.url')
    .toString().trim();

const app = new cdk.App({});

// Load configuration from CDK context
const envConfig = loadConfig(app);
const env = getEnvWithConfig(envConfig);

const synthesizer = new cdk.CliCredentialsStackSynthesizer({
  bucketPrefix: envConfig.assets.bucketPrefix,
  fileAssetsBucketName: envConfig.assets.bucketName
});

const persistentStack = new MCPProxyPersistentStack(app, `${envConfig.serviceName}-persistent`, {
  synthesizer: synthesizer,
  stackName: `${envConfig.serviceName}-persistent`,
  description: 'MCP Proxy Persistent Resources',
  vpcId: envConfig.vpc.vpcId,
  // DNS configuration is optional - only pass if both hostedZoneId and zoneName are provided
  ...(envConfig.dns?.hostedZoneId && envConfig.dns?.zoneName && {
    hostedZoneId: envConfig.dns.hostedZoneId,
    zoneName: envConfig.dns.zoneName
  }),
  enableExternalLoadBalancer: envConfig.enableExternalLoadBalancer,
  internalNetworks: envConfig.internalNetworks,
  ...(envConfig.loadBalancerPorts && { loadBalancerPorts: envConfig.loadBalancerPorts }),
  ...(envConfig.servicePort && { servicePort: envConfig.servicePort }),
  ...(envConfig.existingResources && { existingResources: envConfig.existingResources }),
  env: env
});

new MCPProxyStack(app, envConfig.serviceName, {
  synthesizer: synthesizer,
  stackName: envConfig.serviceName,
  description: 'MCP Proxy',
  vpcId: envConfig.vpc.vpcId,
  certificateArn: envConfig.certificates.certificateArn,
  cluster: persistentStack.cluster,
  loadBalancers: persistentStack.loadBalancers,
  // Persistent task role is "needed" for google wif.
  taskRole: persistentStack.proxyTaskRole,
  imageTag: process.env.IMAGE_TAG || envConfig.ecr.imageTag || (app.node.tryGetContext("gitRev") ? `sha-${app.node.tryGetContext("gitRev")}` : "latest"),
  kmsKeyArn: envConfig.kms?.keyArn,
  googleWifSecretArn: envConfig.secrets.googleWifSecretArn,
  googleOAuthSecretArn: envConfig.secrets.googleOauthSecretArn,
  // Optional secrets - only passed if provided
  ...(envConfig.secrets.grafanaSecretArn && { grafanaSecretArn: envConfig.secrets.grafanaSecretArn }),
  ...(envConfig.secrets.openmetadataSecretArn && { openmetadataSecretArn: envConfig.secrets.openmetadataSecretArn }),
  ...(envConfig.secrets.posthogSecretArn && { posthogSecretArn: envConfig.secrets.posthogSecretArn }),
  saEmail: envConfig.saEmail,
  // Required Google Workspace configuration
  googleWorkspaceDomain: process.env.GOOGLE_WORKSPACE_DOMAIN || envConfig.googleWorkspaceDomain,
  googleAdminEmail: process.env.GOOGLE_ADMIN_EMAIL || envConfig.googleAdminEmail,
  googleCustomerId: process.env.GOOGLE_CUSTOMER_ID || envConfig.googleCustomerId,
  googleOrgUnitPath: process.env.GOOGLE_ORG_UNIT_PATH || envConfig.googleOrgUnitPath,
  // Optional configuration
  forceHttpsDomains: process.env.FORCE_HTTPS_DOMAINS || envConfig.forceHttpsDomains,
  ...(envConfig.grafanaUrl && { grafanaUrl: envConfig.grafanaUrl }),
  desiredCount: envConfig.desiredCount,
  ...(envConfig.loadBalancerPorts && { loadBalancerPorts: envConfig.loadBalancerPorts }),
  ...(envConfig.servicePort && { servicePort: envConfig.servicePort }),
  ecrRepositoryArns: {
    mcpProxyRepositoryArn: envConfig.ecr.mcpProxyRepositoryArn,
    mcpOauthRepositoryArn: envConfig.ecr.mcpOauthRepositoryArn,
  },
  env: env
});

// Apply tags from configuration
if (envConfig.tags) {
  Object.entries(envConfig.tags).forEach(([key, value]) => {
    if (value) {
      cdk.Tags.of(app).add(key, value);
    }
  });
}

// Add repository tag
cdk.Tags.of(app).add('Repo', repoName);
