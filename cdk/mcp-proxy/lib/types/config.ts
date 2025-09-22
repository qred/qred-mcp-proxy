import { App } from 'aws-cdk-lib';

// Configuration interfaces for environment-specific values
export interface EnvironmentConfig {
  serviceName: string; // Service name used for stack names and resource naming
  account: string;
  region: string;
  desiredCount: number;
  tags?: {
    team?: string;
    costCenter?: string;
    environment?: string;
    [key: string]: string | undefined;
  };
  assets: {
    bucketName: string;
    bucketPrefix: string;
  };
  vpc: {
    vpcId: string;
  };
  dns?: {
    hostedZoneId: string;
    zoneName: string;
  };
  certificates: {
    certificateArn: string;
  };
  ecr: {
    mcpProxyRepositoryArn: string;
    mcpOauthRepositoryArn: string;
    imageTag?: string; // Optional image tag to use if IMAGE_TAG env var is not set
  };
  kms?: {
    keyArn: string;  // ARN of existing KMS key to use for encryption
  };
  secrets: {
    googleWifSecretArn: string;
    googleOauthSecretArn: string;
    grafanaSecretArn?: string;        // Optional - if provided, enables Grafana MCP server
    posthogSecretArn?: string;        // Optional - if provided, enables PostHog MCP server
    openmetadataSecretArn?: string;   // Optional - if provided, enables OpenMetadata MCP server
  };
  saEmail: string;                    // Service Account email for Google authentication
  googleWorkspaceDomain?: string;     // Google Workspace domain for OAuth (e.g., "company.com")
  googleAdminEmail?: string;          // Google Workspace admin email for WIF service
  forceHttpsDomains?: string;         // Comma-separated domains that should force HTTPS behind load balancer
  grafanaUrl?: string;                // Grafana instance URL for MCP server (required if grafanaSecretArn is provided)
  enableExternalLoadBalancer?: boolean; // Enable external load balancer for AI providers (default: false)
  loadBalancerPorts?: number[];       // Ports to configure on load balancer listeners (for shared infrastructure)
  servicePort?: number;               // Port for this specific service instance (default: 443)
  internalNetworks: string[];         // CIDR blocks allowed to access internal load balancer (required for security)
  // Existing resources configuration (for shared environments)
  existingResources?: {
    clusterName?: string;                 // Use existing ECS cluster instead of creating new one
    internalLoadBalancerArn?: string;     // Use existing internal load balancer instead of creating new one  
    externalLoadBalancerArn?: string;     // Use existing external load balancer instead of creating new one
    internalLoadBalancerSecurityGroupId?: string; // Security group ID of the existing internal load balancer
    externalLoadBalancerSecurityGroupId?: string; // Security group ID of the existing external load balancer
    // Note: When using existing load balancers, the parent stack that owns them 
    // should handle any additional ports, security groups, or listeners needed
  };
}

// Helper function to validate required configuration values
export function validateConfig(envConfig: EnvironmentConfig, environmentName: string): EnvironmentConfig {
  const errors: string[] = [];

  // Validate basic required fields
  if (!envConfig.serviceName || envConfig.serviceName === '') {
    errors.push(`${environmentName}.serviceName is required (used for stack names and resource naming)`);
  } else if (!/^[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9]$/.test(envConfig.serviceName) || envConfig.serviceName.length > 50) {
    errors.push(`${environmentName}.serviceName must be a valid identifier (alphanumeric and hyphens, max 50 chars, start with letter, end with alphanumeric)`);
  }

  // Validate account and region
  if (!envConfig.account || envConfig.account === '') {
    errors.push(`${environmentName}.account is required (your AWS account ID)`);
  } else if (!/^\d{12}$/.test(envConfig.account)) {
    errors.push(`${environmentName}.account must be a 12-digit AWS account ID`);
  }
  
  if (!envConfig.region || envConfig.region === '') {
    errors.push(`${environmentName}.region is required (e.g., "eu-west-1")`);
  }

  if (typeof envConfig.desiredCount !== 'number' || envConfig.desiredCount < 1) {
    errors.push(`${environmentName}.desiredCount must be a positive number`);
  }

  // Validate assets section
  if (!envConfig.assets) {
    errors.push(`Missing ${environmentName}.assets section`);
  } else {
    if (!envConfig.assets.bucketName || envConfig.assets.bucketName === '') {
      errors.push(`${environmentName}.assets.bucketName is required`);
    }
    if (!envConfig.assets.bucketPrefix || envConfig.assets.bucketPrefix === '') {
      errors.push(`${environmentName}.assets.bucketPrefix is required`);
    }
  }

  // Validate VPC section
  if (!envConfig.vpc?.vpcId || envConfig.vpc.vpcId === '') {
    errors.push(`${environmentName}.vpc.vpcId is required (your VPC ID, e.g., "vpc-123456789abcdef0")`);
  } else if (!/^vpc-[a-f0-9]+$/.test(envConfig.vpc.vpcId)) {
    errors.push(`${environmentName}.vpc.vpcId must be a valid VPC ID format (vpc-xxxxx)`);
  }

  // Validate DNS section (optional - only validate if provided)
  if (envConfig.dns) {
    if (!envConfig.dns.hostedZoneId || envConfig.dns.hostedZoneId === '') {
      errors.push(`${environmentName}.dns.hostedZoneId is required when dns section is provided (Route53 hosted zone ID)`);
    } else if (!/^Z[A-Z0-9]+$/.test(envConfig.dns.hostedZoneId)) {
      errors.push(`${environmentName}.dns.hostedZoneId must be a valid Route53 hosted zone ID (starts with Z)`);
    }
    if (!envConfig.dns.zoneName || envConfig.dns.zoneName === '') {
      errors.push(`${environmentName}.dns.zoneName is required when dns section is provided (domain name for your hosted zone)`);
    }
  }

  // Validate certificates section
  if (!envConfig.certificates?.certificateArn || envConfig.certificates.certificateArn === '') {
    errors.push(`${environmentName}.certificates.certificateArn is required (ACM certificate ARN)`);
  } else if (!/^arn:aws:acm:.+:certificate\/.+$/.test(envConfig.certificates.certificateArn)) {
    errors.push(`${environmentName}.certificates.certificateArn must be a valid ACM certificate ARN`);
  }

  // Validate ECR section
  if (!envConfig.ecr) {
    errors.push(`Missing ${environmentName}.ecr section`);
  } else {
    const requiredRepos = [
      'mcpProxyRepositoryArn',
      'mcpOauthRepositoryArn'
    ];
    
    requiredRepos.forEach(repoKey => {
      const repoArn = (envConfig.ecr as any)[repoKey];
      if (!repoArn || repoArn === '') {
        errors.push(`${environmentName}.ecr.${repoKey} is required (ECR repository ARN)`);
      } else if (!/^arn:aws:ecr:.+:repository\/.+$/.test(repoArn)) {
        errors.push(`${environmentName}.ecr.${repoKey} must be a valid ECR repository ARN`);
      }
    });
  }

  // Validate KMS section (optional - only validate if provided)
  if (envConfig.kms) {
    if (!envConfig.kms.keyArn || envConfig.kms.keyArn === '') {
      errors.push(`${environmentName}.kms.keyArn is required when kms section is provided (KMS key ARN)`);
    } else if (!/^arn:aws:kms:.+:key\/.+$/.test(envConfig.kms.keyArn)) {
      errors.push(`${environmentName}.kms.keyArn must be a valid KMS key ARN`);
    }
  }

  // Validate secrets section
  if (!envConfig.secrets) {
    errors.push(`Missing ${environmentName}.secrets section`);
  } else {
    // Only Google secrets are required - others are optional
    const requiredSecrets = [
      'googleWifSecretArn',
      'googleOauthSecretArn'
    ];
    
    requiredSecrets.forEach(secretKey => {
      const secretArn = (envConfig.secrets as any)[secretKey];
      if (!secretArn || secretArn === '') {
        errors.push(`${environmentName}.secrets.${secretKey} is required (AWS Secrets Manager ARN)`);
      } else if (!/^arn:aws:secretsmanager:.+:secret:.+$/.test(secretArn)) {
        errors.push(`${environmentName}.secrets.${secretKey} must be a valid Secrets Manager ARN`);
      }
    });

    // Validate optional secrets if they are provided
    const optionalSecrets = [
      'grafanaSecretArn',
      'posthogSecretArn',
      'openmetadataSecretArn'
    ];
    
    optionalSecrets.forEach(secretKey => {
      const secretArn = (envConfig.secrets as any)[secretKey];
      if (secretArn && secretArn !== '' && !/^arn:aws:secretsmanager:.+:secret:.+$/.test(secretArn)) {
        errors.push(`${environmentName}.secrets.${secretKey} must be a valid Secrets Manager ARN if provided`);
      }
    });
  }

  // Validate required configuration fields
  if (!envConfig.saEmail || envConfig.saEmail === '') {
    errors.push(`${environmentName}.saEmail is required (Google Service Account email)`);
  } else if (!/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com$/.test(envConfig.saEmail)) {
    errors.push(`${environmentName}.saEmail must be a valid Google Service Account email (ending in .iam.gserviceaccount.com)`);
  }

  // Validate grafanaUrl only if grafanaSecretArn is provided
  if (envConfig.secrets?.grafanaSecretArn) {
    if (!envConfig.grafanaUrl || envConfig.grafanaUrl === '') {
      errors.push(`${environmentName}.grafanaUrl is required when grafanaSecretArn is provided (Grafana instance URL)`);
    } else if (!/^https?:\/\/.+$/.test(envConfig.grafanaUrl)) {
      errors.push(`${environmentName}.grafanaUrl must be a valid URL starting with http:// or https://`);
    }
  }

  // Validate internalNetworks - must be explicitly configured for security
  if (!envConfig.internalNetworks || envConfig.internalNetworks.length === 0) {
    errors.push(`${environmentName}.internalNetworks is required (array of CIDR blocks that should have access to internal load balancer). Example: ["10.0.0.0/16"] for VPC-only access or ["192.168.1.0/24"] for specific network.`);
  } else {
    // Validate each CIDR block format
    envConfig.internalNetworks.forEach((cidr, index) => {
      if (!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(cidr)) {
        errors.push(`${environmentName}.internalNetworks[${index}] "${cidr}" is not a valid CIDR block (e.g., "10.0.0.0/16")`);
      }
    });
  }

  if (errors.length > 0) {
    throw new Error(
      `Configuration validation failed:\n${errors.map(e => `  - ${e}`).join('\n')}\n\n` +
      'Please check your cdk.json file and ensure all required fields are properly configured.\n' +
      'See cdk.example.jsonc for reference.'
    );
  }

  return envConfig;
}

// Helper function to load configuration from CDK context
export function loadConfig(app: App, environmentName?: string): EnvironmentConfig {
  // Default to 'default' if no environment specified
  const env = environmentName || process.env.CONFIG_ENV || 'default';
  
  // Get current CDK environment
  const currentAccount = process.env.CDK_DEFAULT_ACCOUNT;
  const currentRegion = process.env.CDK_DEFAULT_REGION || 'eu-west-1';
  
  if (!currentAccount) {
    throw new Error(
      `No AWS credentials detected. CDK_DEFAULT_ACCOUNT is not set.\n` +
      'Please ensure you have valid AWS credentials configured (via AWS CLI, environment variables, or IAM roles).\n' +
      'Run "aws sts get-caller-identity" to verify your credentials.'
    );
  }
  
  // Try to get environment-specific configuration first
  const environments = app.node.tryGetContext('environments') as Record<string, EnvironmentConfig>;
  
  // If no environments config exists, try to use the account-based context (like parent project)
  if (!environments) {
    const accountConfig = app.node.tryGetContext(currentAccount);
    if (!accountConfig) {
      throw new Error(
        `No configuration found for current AWS account '${currentAccount}'.\n` +
        'Please add environment configuration to your cdk.json file.\n' +
        'You can either:\n' +
        '1. Add an "environments" section with environment-specific config, or\n' +
        '2. Add account-specific configuration under "${currentAccount}" key\n' +
        'See cdk.example.jsonc for reference.'
      );
    }
    
    // Use account-based configuration (fallback to parent project style)
    const regionConfig = accountConfig[currentRegion];
    if (!regionConfig) {
      throw new Error(
        `No configuration found for region '${currentRegion}' in account '${currentAccount}'.\n` +
        'Please add region-specific configuration to your cdk.json file.'
      );
    }
    
    // Create a minimal environment config from account/region context
    const envConfig: EnvironmentConfig = {
      serviceName: 'mcp-proxy', // Default service name
      account: currentAccount,
      region: currentRegion,
      desiredCount: 1,
      assets: {
        bucketName: `mcp-proxy-${currentAccount}-${currentRegion}-assets`,
        bucketPrefix: 'mcp-proxy/'
      },
      vpc: {
        vpcId: regionConfig.vpc00?.vpcId || regionConfig.vpcId
      },
      // DNS is optional - only include if both zoneId and zoneName are provided
      ...(regionConfig.zoneId && regionConfig.zoneName && {
        dns: {
          hostedZoneId: regionConfig.zoneId,
          zoneName: regionConfig.zoneName
        }
      }),
      certificates: {
        certificateArn: regionConfig.certificateArn || `arn:aws:acm:${currentRegion}:${currentAccount}:certificate/placeholder`
      },
      ecr: {
        mcpProxyRepositoryArn: `arn:aws:ecr:${currentRegion}:${currentAccount}:repository/mcp-proxy`,
        mcpOauthRepositoryArn: `arn:aws:ecr:${currentRegion}:${currentAccount}:repository/mcp-oauth`
      },
      kms: regionConfig.kmsKeyArns?.['mcp-proxy'] ? {
        keyArn: regionConfig.kmsKeyArns['mcp-proxy']
      } : undefined,
      secrets: {
        googleWifSecretArn: regionConfig.secretArns?.['mcp-proxy']?.googleWif || `arn:aws:secretsmanager:${currentRegion}:${currentAccount}:secret:mcp-proxy/googleWIF-xxxxxx`,
        googleOauthSecretArn: regionConfig.secretArns?.['mcp-proxy']?.googleOAuth || `arn:aws:secretsmanager:${currentRegion}:${currentAccount}:secret:mcp-proxy/googleOAuth-xxxxxx`,
        grafanaSecretArn: regionConfig.secretArns?.['mcp-proxy']?.grafana,        // Optional
        posthogSecretArn: regionConfig.secretArns?.['mcp-proxy']?.posthog,        // Optional
        openmetadataSecretArn: regionConfig.secretArns?.['mcp-proxy']?.openmetadata  // Optional
      },
      saEmail: regionConfig.saEmail || 'your-sa@your-gcp-project.iam.gserviceaccount.com',
      grafanaUrl: regionConfig.grafanaUrl,  // Optional - only needed if Grafana secret is provided
      enableExternalLoadBalancer: regionConfig.enableExternalLoadBalancer || false,
      internalNetworks: regionConfig.internalNetworks  // Must be explicitly configured - no unsafe defaults
    };
    
    return validateConfig(envConfig, env);
  }

  // Use environment-based configuration
  const envConfig = environments[env];
  if (!envConfig) {
    const availableEnvs = Object.keys(environments);
    throw new Error(
      `Environment '${env}' not found in CDK context.\n` +
      `Available environments: ${availableEnvs.join(', ')}\n` +
      'Please add this environment to your cdk.json file or set CONFIG_ENV to an existing environment.\n' +
      'See cdk.example.jsonc for reference.'
    );
  }

  // Validate that the configured account matches the current AWS credentials
  if (envConfig.account !== currentAccount) {
    throw new Error(
      `Account mismatch detected!\n` +
      `Current AWS credentials are for account: ${currentAccount}\n` +
      `But environment '${env}' is configured for account: ${envConfig.account}\n\n` +
      'This deployment would fail. Please either:\n' +
      `1. Switch to AWS credentials for account ${envConfig.account}, or\n` +
      `2. Use a different environment that matches account ${currentAccount}, or\n` +
      `3. Update the configuration for environment '${env}' to use account ${currentAccount}\n\n` +
      'Run "aws sts get-caller-identity" to verify your current AWS account.'
    );
  }

  // Use current region as default if not specified in config, but prefer config value
  const finalConfig = {
    ...envConfig,
    region: envConfig.region || currentRegion
  };

  // Validate the configuration
  const validatedConfig = validateConfig(finalConfig, env);
  
  return validatedConfig;
}

// Helper function to get environment variables with config fallback
export function getEnvWithConfig(envConfig: EnvironmentConfig) {
  // Since we've already validated that envConfig.account matches CDK_DEFAULT_ACCOUNT in loadConfig,
  // we can safely use the CDK environment values directly
  return {
    account: process.env.CDK_DEFAULT_ACCOUNT || envConfig.account,
    region: process.env.CDK_DEFAULT_REGION || envConfig.region,
  };
}