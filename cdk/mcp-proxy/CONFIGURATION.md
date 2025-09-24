# MCP Proxy CDK Configuration

This document explains how to configure the MCP Proxy CDK deployment for your AWS environment using CDK context configuration.

## Overview

The MCP Proxy CDK configuration supports multiple environments (development, staging, production, etc.) within the `cdk.json` file. Each environment can have its own specific settings for VPC, certificates, ECR repositories, optional DNS management, optional KMS encryption, and secrets.

## Key Configuration Features

- **Optional DNS Management**: Automatic Route53 record creation when DNS configuration is provided
- **External KMS Support**: Bring-your-own KMS keys (stack does not create keys)
- **Flexible Infrastructure**: Support for existing resources and shared infrastructure
- **Multi-Environment**: Environment-specific configuration within a single file

## Quick Start

1. **Copy the example configuration:**
   ```bash
   cp cdk.example.jsonc cdk.json
   ```

2. **Edit the configuration file:**
   Edit the `cdk.json` file and fill in your AWS-specific values in the `environments` section.

3. **Deploy to specific environment:**
   ```bash
   CONFIG_ENV=development npm run cdk deploy
   # or for default environment:
   npm run cdk deploy
   ```

## Configuration Structure

The configuration is organized into environments within the CDK context:

```json
{
  "context": {
    "environments": {
      "default": {
        "serviceName": "mcp-proxy",
        "account": "123456789012",
        "region": "eu-west-1",
        // ... more configuration
      },
      "production": {
        "serviceName": "mcp-proxy",
        "account": "987654321098",
        "region": "eu-west-1",
        // ... production-specific configuration
      }
    }
  }
}
```

## Environment Configuration

Each environment section supports the following configuration options:

### Basic Settings
- `serviceName`: Used for stack naming and resource prefixes
- `account`: AWS account ID (12 digits)
- `region`: AWS region (e.g., "eu-west-1")
- `desiredCount`: Number of ECS tasks to run
- `saEmail`: Google Service Account email for authentication (required)
- `grafanaUrl`: Grafana instance URL for MCP server (required only if `grafanaSecretArn` is provided)
- `enableExternalLoadBalancer`: Enable internet-facing load balancer for AI providers (optional, default: false)
- `loadBalancerPorts`: Array of ports for load balancer listeners (optional, default: [443])
- `servicePort`: Port for this specific service instance (optional, default: 443)
- `internalNetworks`: Array of CIDR blocks allowed to access internal load balancer (REQUIRED for security)

### Tags
```json
"tags": {
  "team": "platform",
  "costCenter": "platform",
  "environment": "production"
}
```

### CDK Assets
```json
"assets": {
  "bucketName": "mcp-proxy-123456789012-eu-west-1-assets",
  "bucketPrefix": "mcp-proxy/"
}
```

### VPC Configuration
```json
"vpc": {
  "vpcId": "vpc-xxxxxxxxx"
}
```

### DNS Configuration (Optional)
**DNS Management Behavior:**
- **Both values required**: Provide both `hostedZoneId` AND `zoneName` to enable automatic Route53 record creation
- **Omit section**: Skip DNS configuration entirely to manage records externally
- **Existing resources**: When using existing load balancers, DNS records are NOT created regardless of this configuration

```json
"dns": {
  "hostedZoneId": "Z03108621XXXXXXXXXX",  // Required if using automatic DNS
  "zoneName": "example.com"               // Required if using automatic DNS
}
```

**DNS Records Created (when enabled):**
- `<serviceName>.<zoneName>` → Internal Load Balancer
- `<serviceName>-ext.<zoneName>` → External Load Balancer (if enabled)

**For External DNS Management:**
- Omit the entire `dns` section from your configuration
- Use load balancer DNS names from stack outputs to create your own records

### Certificates
```json
"certificates": {
  "certificateArn": "arn:aws:acm:eu-west-1:123456789012:certificate/xxx"
}
```

### Container Registry
```json
"ecr": {
  "mcpProxyRepositoryArn": "arn:aws:ecr:eu-west-1:123456789012:repository/mcp-proxy",
  "mcpOauthRepositoryArn": "arn:aws:ecr:eu-west-1:123456789012:repository/mcp-oauth",
  "imageTag": "latest"
}
```

### KMS Encryption (Optional)
**IMPORTANT**: This stack does NOT create KMS keys. You must create them externally.

Only include this section if you have an existing KMS key to use:

```json
"kms": {
  "keyArn": "arn:aws:kms:eu-west-1:123456789012:key/xxx"
}
```

**KMS Key Requirements:**
- Key must be created outside this stack (manually, via separate stack, or existing key)
- Deploying IAM role must have necessary KMS permissions (Encrypt, Decrypt, GenerateDataKey)
- Key should be in the same region as the deployment

**If omitted**: AWS managed keys will be used where encryption is required.

### Secrets Manager
```json
"secrets": {
  "googleWifSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleWIF-xxx",
  "googleOauthSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleOAuth-xxx",
  "grafanaSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/grafana-xxx",
  "posthogSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/posthog-xxx",
  "openmetadataSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/openmetadata-xxx"
}
```

## Secret Configuration Details

The MCP Proxy uses AWS Secrets Manager for storing sensitive configuration. Secrets are categorized as required or optional:

### Required Secrets
These must always be provided:
- `googleWifSecretArn`: Google Workload Identity Federation configuration
- `googleOauthSecretArn`: Google OAuth application credentials

### Optional Secrets
These enable additional MCP servers when provided:
- `grafanaSecretArn`: Enables Grafana observability tools (requires `grafanaUrl` to be set)
- `posthogSecretArn`: Enables PostHog product analytics
- `openmetadataSecretArn`: Enables OpenMetadata data catalog

### Configuration Examples

#### Minimal Configuration (Required Only)
```json
"secrets": {
  "googleWifSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleWIF-xxx",
  "googleOauthSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleOAuth-xxx"
},
"saEmail": "your-sa@your-gcp-project.iam.gserviceaccount.com",
"internalNetworks": ["10.0.0.0/16"]
```

#### Partial Configuration (Some Optional Servers)
```json
"secrets": {
  "googleWifSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleWIF-xxx",
  "googleOauthSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleOAuth-xxx",
  "grafanaSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/grafana-xxx"
},
"saEmail": "your-sa@your-gcp-project.iam.gserviceaccount.com",
"grafanaUrl": "https://your-grafana.url"
```

#### Full Configuration (All Optional Servers)
```json
"secrets": {
  "googleWifSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleWIF-xxx",
  "googleOauthSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleOAuth-xxx",
  "grafanaSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/grafana-xxx",
  "posthogSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/posthog-xxx",
  "openmetadataSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/openmetadata-xxx"
},
"saEmail": "your-sa@your-gcp-project.iam.gserviceaccount.com",
"grafanaUrl": "https://your-grafana.url",
"enableExternalLoadBalancer": true
```

## Existing Resources Configuration

The MCP Proxy supports using existing AWS resources for shared infrastructure deployments. This is useful for cost optimization and multi-environment setups where resources are shared across multiple deployments.

### Existing Resources Options

Configure existing resources in the `existingResources` section:

```json
"existingResources": {
  "clusterName": "shared-cluster",                           // Use existing ECS cluster
  "internalLoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/shared-internal-alb/1234567890123456",
  "internalLoadBalancerSecurityGroupId": "sg-0123456789abcdef0",  // Security group ID of existing internal ALB
  "externalLoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/shared-external-alb/9876543210987654",    // Optional: existing external ALB
  "externalLoadBalancerSecurityGroupId": "sg-0987654321fedcba0"   // Optional: security group ID of existing external ALB
}
```

### Shared Infrastructure Configuration Options

- **`clusterName`**: Name of existing ECS cluster to use instead of creating a new one
- **`internalLoadBalancerArn`**: ARN of existing internal Application Load Balancer
- **`internalLoadBalancerSecurityGroupId`**: Security group ID of the existing internal load balancer
- **`externalLoadBalancerArn`**: (Optional) ARN of existing external Application Load Balancer
- **`externalLoadBalancerSecurityGroupId`**: (Optional) Security group ID of the existing external load balancer

### Important Notes for Shared Infrastructure

#### Resource Ownership and Management
- **Parent Stack Responsibility**: The stack that creates the load balancer must configure all needed ports, listeners, and security groups
- **Child Stack Behavior**: Stacks using existing resources will NOT modify them - they only reference them
- **DNS Management**: When using existing load balancers, this stack will NOT create Route53 records
- **Port Planning**: Ensure all `loadBalancerPorts` are configured on the existing load balancer before deploying dependent stacks

#### Security Group Management
- When using existing load balancers, provide the security group IDs to ensure proper network access
- The stack will import and reference these security groups without modifying them
- Ensure the existing security groups allow traffic on the ports used by your service

#### Cost Benefits
- **Shared Load Balancers**: Save costs by sharing expensive ALB resources across multiple environments
- **Shared ECS Clusters**: Optimize compute resource utilization
- **Reduced Infrastructure**: Fewer resources to manage and monitor

### Shared Infrastructure Example

```json
{
  "environments": {
    // Parent environment that creates shared infrastructure
    "shared-parent": {
      "serviceName": "mcp-proxy-shared",
      "account": "123456789012",
      "region": "eu-west-1",
      "loadBalancerPorts": [443, 8443, 9443],  // Configure all ports for child services
      "servicePort": 443,                      // Parent uses port 443
      "internalNetworks": ["10.0.0.0/16"],
      // Full configuration for creating all resources
      "vpc": {"vpcId": "vpc-xxxxxxxxx"},
      "dns": {"hostedZoneId": "Z03108621XXXXXXXXXX", "zoneName": "example.com"}
    },

    // Child environment using existing infrastructure
    "dev1": {
      "serviceName": "mcp-proxy-dev1",
      "account": "123456789012",
      "region": "eu-west-1",
      "servicePort": 8443,             // Use different port from parent
      "existingResources": {
        "clusterName": "mcp-proxy-shared-cluster",
        "internalLoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/mcp-proxy-shared-internal/1234567890123456",
        "internalLoadBalancerSecurityGroupId": "sg-0123456789abcdef0"
      },
      // DNS will be managed by parent stack - access via parent's domain:8443
      "assets": {"bucketName": "shared-assets", "bucketPrefix": "dev1/"}
    },

    // Another child environment
    "dev2": {
      "serviceName": "mcp-proxy-dev2",
      "account": "123456789012",
      "region": "eu-west-1",
      "servicePort": 9443,             // Use third port
      "existingResources": {
        "clusterName": "mcp-proxy-shared-cluster",
        "internalLoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/mcp-proxy-shared-internal/1234567890123456",
        "internalLoadBalancerSecurityGroupId": "sg-0123456789abcdef0"
      }
    }
  }
}
```

## External Load Balancer Configuration

The MCP Proxy can optionally create an internet-facing load balancer for external AI providers:

### When to Enable External Load Balancer
- **Enable (`true`)**: When using AI providers like Claude that need internet access to your MCP proxy
- **Disable (`false`, default)**: For VS Code, internal agents, or when only VPN/internal access is needed

### Security Considerations
- **Default**: External load balancer is **disabled** for security
- **IP Restrictions**: When enabled, access is restricted to known AI provider IP addresses
- **Minimal Exposure**: Only enable if you specifically need external AI provider access

### Load Balancer Types Created
- **Internal Load Balancer**: Always created for VPN and internal network access
- **External Load Balancer**: Conditionally created based on `enableExternalLoadBalancer` setting

### Internal Network Configuration (REQUIRED)
The `internalNetworks` setting controls which CIDR blocks can access the internal load balancer:
- **REQUIRED**: You must explicitly specify which networks should have access for security reasons
- **No defaults**: For security, no default networks are allowed - you must explicitly configure access
- **Examples**:
  - VPN network: `["10.8.0.0/24"]`
  - Corporate network: `["192.168.1.0/24", "10.0.10.0/24"]`
  - AWS VPC only: `["10.0.0.0/16"]`
  - Multiple offices: `["10.1.0.0/16", "10.2.0.0/16", "192.168.0.0/16"]`

⚠️ **Security Note**: You must explicitly configure which networks can access your MCP proxy. This prevents unintended network access and requires conscious security decisions.

**Important**: Only include CIDR blocks that should have access to your MCP proxy. This controls the security perimeter for internal access.

> **Note**: Only the MCP servers with corresponding secrets will be deployed. This allows you to start with a minimal setup and add more servers as needed.

## Environment Variables

### CONFIG_ENV
Set which environment configuration to use:
```bash
export CONFIG_ENV=production
# or
CONFIG_ENV=development npm run cdk deploy
```

If not set, defaults to "default" environment.

### IMAGE_TAG
Override the Docker image tag:
```bash
export IMAGE_TAG=v1.2.3
```

> **Note**: The `ENABLE_KMS` environment variable has been removed. KMS support is now controlled entirely through the optional `kms` section in your configuration.

Takes precedence over `ecr.imageTag` in configuration.

## Deployment Commands

### Deploy to Default Environment
```bash
npm run cdk deploy
```

### Deploy to Specific Environment
```bash
CONFIG_ENV=development npm run cdk deploy
CONFIG_ENV=production npm run cdk deploy
```

### Deploy with Custom Image Tag
```bash
IMAGE_TAG=v1.2.3 npm run cdk deploy
```

### Combined Deployment Examples
```bash
# Deploy production environment with specific image
CONFIG_ENV=production IMAGE_TAG=v1.2.3 npm run cdk deploy

# Deploy development environment with latest dev build
CONFIG_ENV=development IMAGE_TAG=dev-latest npm run cdk deploy
```

> **Note**: All configuration is now controlled through the JSON configuration file. Environment variables are only used for runtime deployment options like `CONFIG_ENV` and `IMAGE_TAG`.

## Example Complete Configuration

Here's a complete example showing multiple environments:

```json
{
  "app": "npx ts-node --prefer-ts-exts bin/mcp-proxy.ts",
  "requireApproval": "never",
  "context": {
    "environments": {
      "default": {
        "serviceName": "mcp-proxy",
        "account": "123456789012",
        "region": "eu-west-1",
        "desiredCount": 1,
        "tags": {
          "team": "platform",
          "costCenter": "platform"
        },
        "assets": {
          "bucketName": "mcp-proxy-123456789012-eu-west-1-assets",
          "bucketPrefix": "mcp-proxy/"
        },
        "vpc": {
          "vpcId": "vpc-xxxxxxxxx"
        },
        "dns": {
          "hostedZoneId": "Z03108621XXXXXXXXXX",
          "zoneName": "dev.example.com"
        },
        "certificates": {
          "certificateArn": "arn:aws:acm:eu-west-1:123456789012:certificate/xxx",
          "cloudfrontCertArn": "arn:aws:acm:us-east-1:123456789012:certificate/xxx"
        },
        "ecr": {
          "mcpProxyRepositoryArn": "arn:aws:ecr:eu-west-1:123456789012:repository/mcp-proxy",
          "mcpOauthRepositoryArn": "arn:aws:ecr:eu-west-1:123456789012:repository/mcp-oauth",
          "imageTag": "latest"
        },
        "secrets": {
          "googleWifSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleWIF-xxx",
          "googleOauthSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleOAuth-xxx",
          "grafanaSecretArn": "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/grafana-xxx"
        }
      },
      "production": {
        "serviceName": "mcp-proxy",
        "account": "987654321098",
        "region": "eu-west-1",
        "desiredCount": 3,
        "tags": {
          "team": "platform",
          "costCenter": "platform",
          "environment": "production"
        },
        "assets": {
          "bucketName": "mcp-proxy-prod-987654321098-eu-west-1-assets",
          "bucketPrefix": "mcp-proxy/prod/"
        },
        "vpc": {
          "vpcId": "vpc-yyyyyyyyy"
        },
        "dns": {
          "hostedZoneId": "Z03108621YYYYYYYYYY",
          "zoneName": "mcp.example.com"
        },
        "certificates": {
          "certificateArn": "arn:aws:acm:eu-west-1:987654321098:certificate/yyy",
          "cloudfrontCertArn": "arn:aws:acm:us-east-1:987654321098:certificate/yyy"
        },
        "ecr": {
          "mcpProxyRepositoryArn": "arn:aws:ecr:eu-west-1:987654321098:repository/mcp-proxy",
          "mcpOauthRepositoryArn": "arn:aws:ecr:eu-west-1:987654321098:repository/mcp-oauth",
          "imageTag": "v1.2.3"
        },
        "kms": {
          "keyArn": "arn:aws:kms:eu-west-1:987654321098:key/yyy",
          "adminRoles": [
            "arn:aws:iam::987654321098:role/AWSAdministratorAccess"
          ]
        },
        "secrets": {
          "googleWifSecretArn": "arn:aws:secretsmanager:eu-west-1:987654321098:secret:mcp-proxy/googleWIF-yyy",
          "googleOauthSecretArn": "arn:aws:secretsmanager:eu-west-1:987654321098:secret:mcp-proxy/googleOAuth-yyy",
          "grafanaSecretArn": "arn:aws:secretsmanager:eu-west-1:987654321098:secret:mcp-proxy/grafana-yyy"
        }
      }
    }
  }
}
```

### Load Balancer Port Configuration

The port configuration system supports both standalone and shared infrastructure deployments:

#### Port Configuration Options

- **`loadBalancerPorts`**: Array of ports to configure on load balancer listeners
  - Used for shared infrastructure where multiple services use the same load balancer
  - Default: `[443]` for standalone deployments
  - Example: `[443, 8443, 9443]` for shared infrastructure supporting multiple services

- **`servicePort`**: Port for this specific service instance
  - Must be one of the ports listed in `loadBalancerPorts`
  - Default: `443`
  - Each service in a shared environment should use a different port

#### Standalone Environment (Default)
```json
{
  "serviceName": "mcp-proxy",
  "account": "123456789012",
  "region": "eu-west-1",
  // Standalone configuration - single service on port 443
  "loadBalancerPorts": [443],    // Load balancer listens on port 443
  "servicePort": 443,            // Service uses port 443
  "internalNetworks": ["10.0.0.0/16"]
}
```

#### Shared Infrastructure Environment
```json
{
  "serviceName": "mcp-proxy-dev1",
  "account": "123456789012",
  "region": "eu-west-1",
  // Shared configuration - multiple services sharing infrastructure
  "loadBalancerPorts": [443, 8443, 9443],  // Load balancer configured for multiple ports
  "servicePort": 8443,                     // This service uses port 8443
  "internalNetworks": ["10.0.0.0/16"],
  "existingResources": {
    "clusterName": "shared-cluster",
    "internalLoadBalancerArn": "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/shared-internal-alb/1234567890123456"
  }
}
```

#### Port Configuration Strategy for Shared Infrastructure

When deploying multiple environments that share infrastructure:

1. **Parent Stack**: Creates load balancer with all needed ports in `loadBalancerPorts`
   ```json
   "loadBalancerPorts": [443, 8443, 9443]  // Configure all ports needed by child services
   ```

2. **Child Stacks**: Use existing load balancer with specific `servicePort`
   ```json
   "servicePort": 8443,  // Each child service uses a different port
   "existingResources": {
     "internalLoadBalancerArn": "arn:aws:elasticloadbalancing:..."
   }
   ```

**Use cases:**
- **Production**: Use default port 443 for standard HTTPS
- **Development**: Use port 8443 to avoid conflicts with other services
- **Shared Infrastructure**: Multiple environments (dev1: 8443, dev2: 9443, staging: 443)
- **Cost Optimization**: Share expensive resources like load balancers across multiple environments

## Validation

The configuration is automatically validated when you run CDK commands. Common validation errors include:

- Missing required fields
- Invalid AWS resource ARN formats
- Invalid VPC ID format
- Invalid Route53 hosted zone ID format
- Invalid service name format

## Tips

1. **Use meaningful service names** - The `serviceName` field is used for all AWS resource naming
2. **Keep environment-specific values separate** - Use different configurations for dev/staging/prod
3. **Use descriptive tags** - Tags help with cost allocation and resource management
4. **Validate ARNs** - Ensure all ARN formats are correct before deployment
5. **Test with default environment first** - Deploy to default environment before production

## Feature Flags

The configuration system supports optional features that can be enabled via environment variables:

### KMS Encryption (Optional)

By default, the system uses AWS managed keys for encryption. To use custom KMS keys:

```bash
export ENABLE_KMS=true
cdk deploy
```

**When KMS is enabled:**
- Requires KMS configuration in your `cdk.json` context
- Creates a dedicated KMS stack for encryption
- Adds KMS decrypt permissions to the task execution role

**When KMS is disabled (default):**
- Uses AWS managed keys (e.g., `/aws/secretsmanager`)
- No additional KMS permissions needed
- Simpler setup and reduced costs

## Environment Variables

The configuration system respects these environment variables:

- `CDK_DEFAULT_ACCOUNT`: Overrides account ID from cdk.json context
- `CDK_DEFAULT_REGION`: Overrides region from cdk.json context
- `IMAGE_TAG`: Docker image tag to deploy (highest priority)
- `ENABLE_KMS`: Enable custom KMS encryption (true/false)

### Image Tag Priority

The system determines which Docker image tag to use with the following priority:

1. **Environment Variable**: `IMAGE_TAG` (highest priority)
2. **Configuration File**: `imageTag` context value in cdk.json
3. **Git Context**: `sha-{gitRev}` if available from CDK context
4. **Default**: `"latest"` (lowest priority)

Example:
```bash
# Deploy with specific image tag
IMAGE_TAG=v1.2.3 npm run cdk deploy

# Or set in cdk.json context
{
  "context": {
    "imageTag": "v1.2.3"
  }
}
```

## Validation

The configuration is automatically validated when you run CDK commands. Common validation errors:

- **Invalid AWS account ID**: Must be exactly 12 digits
- **Invalid VPC ID**: Must start with `vpc-` followed by hexadecimal characters
- **Invalid ARNs**: Must follow proper AWS ARN format for each service
- **Missing required fields**: All required context values must be present

## Security Best Practices

1. **Never commit `cdk.json`** to version control (use `cdk.example.jsonc` as template)
2. **Use least-privilege IAM roles** for KMS admin access
3. **Rotate secrets regularly** in AWS Secrets Manager
4. **Use different configurations** for different environments (dev, staging, production)

## Troubleshooting

### "Configuration file not found"
```bash
cp cdk.example.jsonc cdk.json
# Edit cdk.json with your values
```

### "Configuration validation failed"
Check the error message for specific validation failures and fix the corresponding fields in `cdk.json`.

### "Need to perform AWS calls but no credentials configured"
Ensure your AWS credentials are configured:
```bash
aws configure
# or
aws sso login --profile your-profile
```

### CDK deployment fails
1. Verify all ARNs exist in your AWS account
2. Check IAM permissions for CDK deployment
3. Ensure the VPC and subnets are properly configured

## Example Deployment Workflow

```bash
# 1. Set up configuration
cp cdk.example.jsonc cdk.json
# Edit cdk.json with your values

# 2. Install dependencies
npm install

# 3. Build the project
npm run build

# 4. Bootstrap CDK (first time only)
npm run cdk bootstrap

# 5. Preview changes
npm run cdk diff

# 6. Deploy
npm run cdk deploy
```

## Configuration Examples

For detailed configuration examples and all available options, see the comprehensive examples in `cdk.example.jsonc`.
