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
- `dbUser`: Database username
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
        "dbUser": "mcp_proxy",
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
        "dbUser": "mcp_proxy",
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

2. **Edit the configuration file:**

The configuration system supports optional features that can be enabled via environment variables:   Fill in your AWS-specific values in `config.toml`



### KMS Encryption (Optional)3. **Deploy to specific environment:**

   ```bash

By default, the system uses AWS managed keys for encryption. To use custom KMS keys:   CONFIG_ENV=development npm run cdk deploy

   # or for default environment (default):

```bash   npm run cdk deploy

export ENABLE_KMS=true   ```

cdk deploy

```## Feature Flags



**When KMS is enabled:**The configuration system supports optional features that can be enabled via environment variables:

- Requires `[environment.kms]` section in config.toml

- Creates a dedicated KMS stack for encryption### KMS Encryption (Optional)

- Adds KMS decrypt permissions to the task execution role

By default, the system uses AWS managed keys for encryption. To use custom KMS keys:

**When KMS is disabled (default):**

- Uses AWS managed keys (e.g., `/aws/secretsmanager`)```bash

- No additional KMS permissions neededexport ENABLE_KMS=true

- Simpler setup and reduced costscdk deploy

```

## Setting the Environment

**When KMS is enabled:**

You can specify which environment configuration to use:- Requires `[environment.kms]` section in config.toml

- Creates a dedicated KMS stack for encryption

1. **Environment Variable** (recommended):- Adds KMS decrypt permissions to the task execution role

   ```bash

   export CONFIG_ENV=development**When KMS is disabled (default):**

   cdk deploy- Uses AWS managed keys (e.g., `/aws/secretsmanager`)

   ```- No additional KMS permissions needed

- Simpler setup and reduced costs

2. **Default**: If no `CONFIG_ENV` is set, it defaults to `default`

## Setting the Environment

## Configuration File Structure

You can specify which environment configuration to use:

The configuration is stored in `config.toml` using the TOML format. Here's what each section contains:

1. **Environment Variable** (recommended):

### [general]   ```bash

Global settings that apply to all environments (team and cost center tags).   export CONFIG_ENV=development

   cdk deploy

```toml   ```

[general]

team = "platform"                      # Team tag for resources2. **Default**: If no `CONFIG_ENV` is set, it defaults to `default`

cost_center = "platform"               # Cost center tag for resources

```## Configuration File Structure



### [environment] sections (e.g., [default], [development], [production])The configuration is stored in `config.toml` using the TOML format. Here's what each section contains:

Environment-specific deployment settings. Each environment must be defined in its own section.

### [general]

```tomlGlobal settings that apply to all environments (team and cost center tags).

[default]

name = "default"                       # Environment name - used when no CONFIG_ENV is set```toml

account = "123456789012"               # AWS account ID for this environment[general]

region = "eu-west-1"                   # AWS region for this environmentteam = "platform"                      # Team tag for resources

bucket_name = "mcp-proxy-123456789012-eu-west-1-assets" # S3 assets bucket (literal name)cost_center = "platform"               # Cost center tag for resources

bucket_prefix = "mcp-proxy/"           # S3 bucket prefix for CDK assets```

desired_count = 1                      # Number of ECS tasks to run

### [environment] sections (e.g., [default], [development], [production])

[development]Environment-specific deployment settings. Each environment must be defined in its own section.

name = "development"                   # Environment name

account = "123456789012"               # AWS account ID for this environment```toml

region = "eu-west-1"                   # AWS region for this environment[default]

bucket_name = "mcp-proxy-123456789012-eu-west-1-assets" # S3 assets bucket (literal name)name = "default"                       # Environment name - used when no CONFIG_ENV is set

bucket_prefix = "mcp-proxy/"           # S3 bucket prefix for CDK assetsaccount = "123456789012"               # AWS account ID for this environment

desired_count = 1                      # Number of ECS tasks to runregion = "eu-west-1"                   # AWS region for this environment

bucket_name = "mcp-proxy-123456789012-eu-west-1-assets" # S3 assets bucket (literal name)

[production]bucket_prefix = "mcp-proxy/"           # S3 bucket prefix for CDK assets

name = "production"                    # Environment namedesired_count = 1                      # Number of ECS tasks to run

account = "987654321098"               # AWS account ID for productiondb_user = "mcp_proxy"         # Database username

region = "us-east-1"                   # AWS region for production

bucket_name = "mcp-proxy-987654321098-us-east-1-assets" # S3 assets bucket (literal name)[production]

bucket_prefix = "mcp-proxy/"           # S3 bucket prefix for CDK assetsname = "production"           # Environment name (dev/staging/production)

desired_count = 3                      # Number of ECS tasks to rundesired_count = 2             # Number of ECS tasks to run

```db_user = "mcp_proxy"         # Database username



### [environment.vpc][development]

Virtual Private Cloud configuration for each environment.name = "development"          # Environment name

desired_count = 1            # Number of ECS tasks to run  

```tomldb_user = "mcp_proxy_dev"    # Database username

[default.vpc]```

vpc_id = "vpc-123456789abcdef0"        # VPC ID where resources will be deployed

### [environment.vpc]

[production.vpc]Virtual Private Cloud configuration for each environment.

vpc_id = "vpc-prod123456789abcdef0"    # VPC ID for production

```toml

[development.vpc][default.vpc]

vpc_id = "vpc-dev123456789abcdef0"     # VPC ID for developmentvpc_id = "vpc-123456789abcdef0"  # VPC ID where resources will be deployed

```

[production.vpc]

**How to find your VPC ID:**vpc_id = "vpc-prod123456789abcdef0"   # VPC ID for production

- AWS Console: VPC → Your VPCs

- AWS CLI: `aws ec2 describe-vpcs --query 'Vpcs[*].{VpcId:VpcId,Name:Tags[?Key==\`Name\`]|[0].Value}'`[development.vpc]

vpc_id = "vpc-dev123456789abcdef0"   # VPC ID for development

### [environment.dns]```

Route53 DNS configuration for each environment.

**How to find your VPC ID:**

```toml- AWS Console: VPC → Your VPCs

[default.dns]- AWS CLI: `aws ec2 describe-vpcs --query 'Vpcs[*].{VpcId:VpcId,Name:Tags[?Key==\`Name\`]|[0].Value}'`

hosted_zone_id = "Z03108621DEXAMPLE"   # Route53 hosted zone ID

zone_name = "example.com"              # Domain name### [environment.dns]

Route53 DNS configuration for each environment.

[production.dns]

hosted_zone_id = "Z03108621PRODEXAMPLE" # Production hosted zone ID```toml

zone_name = "prod.example.com"          # Production domain name[default.dns]

hosted_zone_id = "Z03108621DEXAMPLE"  # Route53 hosted zone ID

[development.dns]  zone_name = "example.com"             # Domain name

hosted_zone_id = "Z03108621DEVEXAMPLE" # Development hosted zone ID

zone_name = "dev.example.com"          # Development domain name[production.dns]

```hosted_zone_id = "Z03108621PRODEXAMPLE"  # Production hosted zone ID

zone_name = "prod.example.com"           # Production domain name

**How to find your hosted zone:**

- AWS Console: Route 53 → Hosted zones[development.dns]  

- AWS CLI: `aws route53 list-hosted-zones --query 'HostedZones[*].{Id:Id,Name:Name}'`hosted_zone_id = "Z03108621DEVEXAMPLE" # Development hosted zone ID

zone_name = "dev.example.com"          # Development domain name

### [environment.certificates]```

SSL/TLS certificate configuration for each environment.

**How to find your hosted zone:**

```toml- AWS Console: Route 53 → Hosted zones

[production.certificates]- AWS CLI: `aws route53 list-hosted-zones --query 'HostedZones[*].{Id:Id,Name:Name}'`

certificate_arn = "arn:aws:acm:eu-west-1:123456789012:certificate/example-cert-id"

cloudfront_cert_arn = "arn:aws:acm:us-east-1:123456789012:certificate/example-cloudfront-cert-id"  # Optional### [environment.certificates]

SSL/TLS certificate configuration for each environment.

[development.certificates]

certificate_arn = "arn:aws:acm:eu-west-1:123456789012:certificate/dev-cert-id"  ```toml

cloudfront_cert_arn = "arn:aws:acm:us-east-1:123456789012:certificate/dev-cloudfront-cert-id"  # Optional[production.certificates]

```certificate_arn = "arn:aws:acm:eu-west-1:123456789012:certificate/example-cert-id"

cloudfront_cert_arn = "arn:aws:acm:us-east-1:123456789012:certificate/example-cloudfront-cert-id"  # Optional

**Note:** CloudFront certificates must be in us-east-1 region.

[development.certificates]

**How to find certificates:**certificate_arn = "arn:aws:acm:eu-west-1:123456789012:certificate/dev-cert-id"  

- AWS Console: Certificate Managercloudfront_cert_arn = "arn:aws:acm:us-east-1:123456789012:certificate/dev-cloudfront-cert-id"  # Optional

- AWS CLI: `aws acm list-certificates --region eu-west-1````



### [environment.ecr]**Note:** CloudFront certificates must be in us-east-1 region.

Amazon Elastic Container Registry configuration for each environment.

**How to find certificates:**

```toml- AWS Console: Certificate Manager

[production.ecr]- AWS CLI: `aws acm list-certificates --region eu-west-1`

mcp_proxy_repository_arn = "arn:aws:ecr:eu-west-1:123456789012:repository/mcp-proxy"

mcp_postgres_repository_arn = "arn:aws:ecr:eu-west-1:123456789012:repository/mcp-postgres"### [environment.ecr]

mcp_oauth_repository_arn = "arn:aws:ecr:eu-west-1:123456789012:repository/mcp-oauth"Amazon Elastic Container Registry configuration for each environment.

# Optional: Image tag to use if IMAGE_TAG environment variable is not set

image_tag = "v1.2.3"```toml

```[production.ecr]

mcp_proxy_repository_arn = "arn:aws:ecr:eu-west-1:123456789012:repository/mcp-proxy"

**Required fields:**mcp_postgres_repository_arn = "arn:aws:ecr:eu-west-1:123456789012:repository/mcp-postgres"

- `mcp_proxy_repository_arn`: ECR repository ARN for the main MCP proxy containermcp_oauth_repository_arn = "arn:aws:ecr:eu-west-1:123456789012:repository/mcp-oauth"

- `mcp_postgres_repository_arn`: ECR repository ARN for the PostgreSQL MCP server container# Optional: Image tag to use if IMAGE_TAG environment variable is not set

- `mcp_oauth_repository_arn`: ECR repository ARN for the OAuth authentication containerimage_tag = "v1.2.3"

```

**Optional fields:**

- `image_tag`: Docker image tag to use (see [Image Tag Priority](#image-tag-priority) section)**Required fields:**

- `mcp_proxy_repository_arn`: ECR repository ARN for the main MCP proxy container

**How to find ECR repository ARNs:**- `mcp_postgres_repository_arn`: ECR repository ARN for the PostgreSQL MCP server container

- AWS Console: Elastic Container Registry → Repositories- `mcp_oauth_repository_arn`: ECR repository ARN for the OAuth authentication container

- AWS CLI: `aws ecr describe-repositories --region eu-west-1`

**Optional fields:**

### [environment.kms] (Optional)- `image_tag`: Docker image tag to use (see [Image Tag Priority](#image-tag-priority) section)

Key Management Service configuration for each environment. **Only required if `ENABLE_KMS=true`**.

**How to find ECR repository ARNs:**

```toml- AWS Console: Elastic Container Registry → Repositories

# Only include this section if you want to use custom KMS keys- AWS CLI: `aws ecr describe-repositories --region eu-west-1`

# Otherwise, AWS managed keys will be used automatically

### [environment.kms] (Optional)

[default.kms]Key Management Service configuration for each environment. **Only required if `ENABLE_KMS=true`**.

key_arn = "arn:aws:kms:eu-west-1:123456789012:key/example-key-id"

admin_roles = [```toml

    "arn:aws:iam::123456789012:role/example-admin-role"# Only include this section if you want to use custom KMS keys

]# Otherwise, AWS managed keys will be used automatically

admin_users = []  # Optional

[default.kms]

[production.kms]key_arn = "arn:aws:kms:eu-west-1:123456789012:key/example-key-id"

key_arn = "arn:aws:kms:eu-west-1:123456789012:key/prod-key-id"admin_roles = [

admin_roles = [    "arn:aws:iam::123456789012:role/example-admin-role"

    "arn:aws:iam::123456789012:role/example-admin-role"]

]admin_users = []  # Optional

admin_users = []  # Optional

[production.kms]

[development.kms]key_arn = "arn:aws:kms:eu-west-1:123456789012:key/prod-key-id"

key_arn = "arn:aws:kms:eu-west-1:123456789012:key/dev-key-id"admin_roles = [

admin_roles = [    "arn:aws:iam::123456789012:role/example-admin-role"

    "arn:aws:iam::123456789012:role/example-admin-role"]

]admin_users = []  # Optional

admin_users = []  # Optional

```[development.kms]

key_arn = "arn:aws:kms:eu-west-1:123456789012:key/dev-key-id"

**Usage:**admin_roles = [

- Set `ENABLE_KMS=true` to enable custom KMS encryption    "arn:aws:iam::123456789012:role/example-admin-role"

- If not set, AWS managed keys are used (simpler setup)]

admin_users = []  # Optional

**How to create/find KMS keys:**```

- AWS Console: Key Management Service → Customer managed keys

- AWS CLI: `aws kms list-keys --query 'Keys[*].KeyId'`**Usage:**

- Set `ENABLE_KMS=true` to enable custom KMS encryption

### [environment.secrets]- If not set, AWS managed keys are used (simpler setup)

AWS Secrets Manager configuration for sensitive data in each environment.

**How to create/find KMS keys:**

```toml- AWS Console: Key Management Service → Customer managed keys

[production.secrets]- AWS CLI: `aws kms list-keys --query 'Keys[*].KeyId'`

google_wif_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleWIF-example"

google_oauth_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleOAuth-example"### [environment.secrets]

grafana_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/grafana-example"AWS Secrets Manager configuration for sensitive data in each environment.

openmetadata_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/openmetadata-example"

```toml

[development.secrets][production.secrets]

google_wif_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/dev/googleWIF-example"google_wif_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleWIF-example"

google_oauth_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/dev/googleOAuth-example"  google_oauth_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/googleOAuth-example"

grafana_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/dev/grafana-example"grafana_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/grafana-example"

openmetadata_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/dev/openmetadata-example"openmetadata_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/openmetadata-example"

```

[development.secrets]

**How to create secrets:**google_wif_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/dev/googleWIF-example"

```bashgoogle_oauth_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/dev/googleOAuth-example"  

# Example: Create Google OAuth secretgrafana_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/dev/grafana-example"

aws secretsmanager create-secret \openmetadata_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/dev/openmetadata-example"

    --name "mcp-proxy/googleOAuth" \```

    --description "Google OAuth credentials for MCP Proxy" \

    --secret-string '{"client_id":"your-client-id","client_secret":"your-client-secret"}'## Migration from Old Format

```

If you have an existing `config.toml` file in the old format, you need to restructure it:

## Environment Variables

### Old Format (deprecated):

The configuration system also respects these environment variables:```toml

[general]

- `CDK_DEFAULT_ACCOUNT`: Overrides `[environment].account`# ... general settings

- `CDK_DEFAULT_REGION`: Overrides `[environment].region`

- `IMAGE_TAG`: Docker image tag to deploy (highest priority)[environment]

name = "production"

### Image Tag Priority# ... environment settings



The system determines which Docker image tag to use with the following priority:[vpc]

vpc_id = "vpc-123"

1. **Environment Variable**: `IMAGE_TAG` (highest priority)

2. **Configuration File**: `[environment].ecr.image_tag` [dns]

3. **Git Context**: `sha-{gitRev}` if available from CDK context# ... dns settings

4. **Default**: `"latest"` (lowest priority)```



Example configuration:### New Format:

```toml```toml

[production.ecr][general]

mcp_proxy_repository_arn = "arn:aws:ecr:region:account:repository/mcp-proxy"# ... same general settings

mcp_postgres_repository_arn = "arn:aws:ecr:region:account:repository/mcp-postgres"

mcp_oauth_repository_arn = "arn:aws:ecr:region:account:repository/mcp-oauth"[production]

image_tag = "v1.2.3"  # Used if IMAGE_TAG env var is not setname = "production"

```# ... environment settings



## Migration from Old Format[production.vpc]

vpc_id = "vpc-123"

If you have an existing `config.toml` file in the old format, you need to restructure it:

[production.dns]

### Old Format (deprecated):# ... dns settings

```toml```

[general]

# ... general settings### Migration Steps:

1. Keep the `[general]` section unchanged

[environment]2. Rename `[environment]` to `[default]` (or your desired environment name)

name = "production"3. Move all other sections under your environment (e.g., `[vpc]` → `[default.vpc]`)

# ... environment settings4. Optionally, add additional environments like `[development]`, `[staging]`, `[production]`, etc.



[vpc]## Environment Usage Examples

vpc_id = "vpc-123"

```bash

[dns]# Deploy to default environment (default)

# ... dns settingsnpm run cdk deploy

```

# Deploy to development

### New Format:CONFIG_ENV=development npm run cdk deploy

```toml

[general]# Deploy to production

# ... same general settingsCONFIG_ENV=production npm run cdk deploy



[production]# Deploy to staging

name = "production"CONFIG_ENV=staging npm run cdk deploy

# ... environment settings```

openmetadata_secret_arn = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:mcp-proxy/openmetadata-example"  # Optional

[production.vpc]```

vpc_id = "vpc-123"

**How to create secrets:**

[production.dns]```bash

# ... dns settings# Example: Create Google OAuth secret

```aws secretsmanager create-secret \

    --name "mcp-proxy/googleOAuth" \

### Migration Steps:    --description "Google OAuth credentials for MCP Proxy" \

1. Keep the `[general]` section unchanged    --secret-string '{"client_id":"your-client-id","client_secret":"your-client-secret"}'

2. Rename `[environment]` to `[default]` (or your desired environment name)```

3. Move all other sections under your environment (e.g., `[vpc]` → `[default.vpc]`)

4. Optionally, add additional environments like `[development]`, `[staging]`, `[production]`, etc.## Environment Variables



## ValidationThe configuration system also respects these environment variables:



The configuration is automatically validated when you run CDK commands. Common validation errors:- `CDK_DEFAULT_ACCOUNT`: Overrides `[environment].account`

- `CDK_DEFAULT_REGION`: Overrides `[environment].region`

- **Invalid AWS account ID**: Must be exactly 12 digits- `IMAGE_TAG`: Docker image tag to deploy (highest priority)

- **Invalid VPC ID**: Must start with `vpc-` followed by hexadecimal characters

- **Invalid ARNs**: Must follow proper AWS ARN format for each service### Image Tag Priority

- **Missing required fields**: All required sections and fields must be present

The system determines which Docker image tag to use with the following priority:

## Security Best Practices

1. **Environment Variable**: `IMAGE_TAG` (highest priority)

1. **Never commit `config.toml`** to version control (it's already in `.gitignore`)2. **Configuration File**: `[environment].ecr.image_tag` 

2. **Use least-privilege IAM roles** for KMS admin access3. **Git Context**: `sha-{gitRev}` if available from CDK context

3. **Rotate secrets regularly** in AWS Secrets Manager4. **Default**: `"latest"` (lowest priority)

4. **Use different configurations** for different environments (dev, staging, production)

Example configuration:

## Troubleshooting```toml

[production.ecr]

### "Configuration file not found"mcp_proxy_repository_arn = "arn:aws:ecr:region:account:repository/mcp-proxy"

```mcp_postgres_repository_arn = "arn:aws:ecr:region:account:repository/mcp-postgres"

cp config.example.toml config.tomlmcp_oauth_repository_arn = "arn:aws:ecr:region:account:repository/mcp-oauth"

```image_tag = "v1.2.3"  # Used if IMAGE_TAG env var is not set

```

### "Configuration validation failed"

Check the error message for specific validation failures and fix the corresponding fields in `config.toml`.## Validation



### "Need to perform AWS calls but no credentials configured"The configuration is automatically validated when you run CDK commands. Common validation errors:

Ensure your AWS credentials are configured:

```bash- **Invalid AWS account ID**: Must be exactly 12 digits

aws configure- **Invalid VPC ID**: Must start with `vpc-` followed by hexadecimal characters

# or- **Invalid ARNs**: Must follow proper AWS ARN format for each service

aws sso login --profile your-profile- **Missing required fields**: All required sections and fields must be present

```

## Security Best Practices

### CDK deployment fails

1. Verify all ARNs exist in your AWS account1. **Never commit `config.toml`** to version control (it's already in `.gitignore`)

2. Check IAM permissions for CDK deployment2. **Use least-privilege IAM roles** for KMS admin access

3. Ensure the VPC and subnets are properly configured3. **Rotate secrets regularly** in AWS Secrets Manager

4. **Use different configurations** for different environments (dev, staging, production)

## Environment Usage Examples

## Troubleshooting

```bash

# Deploy to default environment (default)### "Configuration file not found"

cp config.example.toml config.toml

npm run cdk deploy```

# Deploy to development```

CONFIG_ENV=development npm run cdk deploy

### "Configuration validation failed"

# Deploy to productionCheck the error message for specific validation failures and fix the corresponding fields in `config.toml`.

CONFIG_ENV=production npm run cdk deploy

### "Need to perform AWS calls but no credentials configured"

# Deploy to stagingEnsure your AWS credentials are configured:

CONFIG_ENV=staging npm run cdk deploy```bash

```aws configure

# or

## Example Deployment Workflowaws sso login --profile your-profile

```

```bash

# 1. Set up configuration### CDK deployment fails

cp config.example.toml config.toml1. Verify all ARNs exist in your AWS account

# Edit config.toml with your values2. Check IAM permissions for CDK deployment

3. Ensure the VPC and subnets are properly configured

# 2. Install dependencies

npm install## Example Deployment Workflow



# 3. Build the project```bash

npm run build# 1. Set up configuration

cp config.example.toml config.toml

# 4. Bootstrap CDK (first time only)# Edit config.toml with your values

npm run cdk bootstrap

# 2. Install dependencies

# 5. Preview changesnpm install

npm run cdk diff

# 3. Build the project

# 6. Deploynpm run build

npm run cdk deploy

```# 4. Bootstrap CDK (first time only)

npm run cdk bootstrap

## Multiple Environments

# 5. Preview changes

For multiple environments, you can use the CONFIG_ENV environment variable to switch between configurations within the same `config.toml` file:npm run cdk diff



```bash# 6. Deploy

# Development deploymentnpm run cdk deploy

CONFIG_ENV=development npm run cdk deploy```



# Production deployment  ## Multiple Environments

CONFIG_ENV=production npm run cdk deploy

For multiple environments, create separate configuration files:

# Or set it persistently in your shell

export CONFIG_ENV=development```bash

npm run cdk deploy# Development

```cp config.example.toml config.dev.toml

# Edit config.dev.toml

All environment configurations are defined in the same `config.toml` file using the environment-specific section format outlined above.
# Production  
cp config.example.toml config.prod.toml
# Edit config.prod.toml

# Deploy with specific config
ln -sf config.dev.toml config.toml && npm run cdk deploy
```