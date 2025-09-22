# MCP Proxy CDK Infrastructure

This directory contains the AWS CDK (TypeScript) infrastructure stack for deploying the MCP proxy system, including all necessary AWS resources for a production-ready deployment.

## Quick Start

**Prerequisites:** Ensure you have valid AWS credentials configured (via AWS CLI, environment variables, or IAM roles).

1. **Configure your environment:**
   ```bash
   cp cdk.example.jsonc cdk.json
   # Edit cdk.json with your AWS-specific values
   # Important: The account ID in your config must match your current AWS credentials
   ```

2. **Verify your AWS credentials:**
   ```bash
   aws sts get-caller-identity
   # Note the Account ID - this must match your cdk.json configuration
   ```

3. **Install dependencies and deploy:**
   ```bash
   npm install
   npm run build
   npm run cdk deploy
   ```

4. **Deploy to specific environment:**
   ```bash
   CONFIG_ENV=development npm run cdk deploy
   CONFIG_ENV=production npm run cdk deploy
   ```

> **Account Validation:** The system automatically validates that your configured AWS account matches your current AWS credentials before deployment. This prevents deployment failures and ensures security.

For detailed configuration instructions, see [CONFIGURATION.md](./CONFIGURATION.md).

## Architecture Overview

The CDK stack deploys a complete containerized MCP proxy system with:

### Core Infrastructure
- **ECS Fargate Cluster**: Scalable container hosting
- **Application Load Balancer**: Traffic distribution and SSL termination
- **VPC Integration**: Uses your existing VPC and security groups
- **Route53 DNS**: Optional automatic domain name management (configurable)

### Services Deployed
- **MCP Proxy Service**: Main aggregated proxy server
- **OAuth 2.1 Sidecar**: Authentication and client routing service  
- **PostgreSQL Backend**: Database integration service

### Security & Monitoring
- **SSL/TLS**: Automatic certificate management
- **IAM Roles**: Least-privilege access controls
- **CloudWatch Logs**: Centralized logging and monitoring
- **Secrets Manager**: Secure credential storage

### Optional Features
- **DNS Management**: Automatic Route53 record creation (configurable)
- **KMS Encryption**: Bring-your-own encryption keys (external key required)
- **Cross-Account Access**: RDS access across AWS accounts

## Environment Configuration

The stack supports multiple environments with environment-specific configuration:

```bash
# Default environment
npm run cdk deploy

# Development environment  
CONFIG_ENV=development npm run cdk deploy

# Production environment
CONFIG_ENV=production npm run cdk deploy
```

Each environment can have its own:
- AWS account and region
- VPC and networking configuration
- Domain names and certificates
- Service scaling parameters
- Security and encryption settings

## Configuration File Structure

## Configuration File Structure

The stack uses `cdk.json` for environment-specific configuration:

```json
{
  "context": {
    "environments": {
      "default": {
        "serviceName": "mcp-proxy",
        "account": "123456789012",
        "region": "us-east-1",
        "tags": {
          "team": "your-team",
          "costCenter": "your-cost-center"
        }
        // ... other default settings
      },
      "production": {
        "serviceName": "mcp-proxy",
        "account": "987654321098", 
        "region": "us-east-1",
        "desiredCount": 3,
        "tags": {
          "team": "your-team",
          "costCenter": "your-cost-center",
          "environment": "production"
        }
        // ... production-specific settings
      },
      "development": {
        "serviceName": "mcp-proxy-dev",
        "account": "123456789012",
        "region": "us-west-2"
        // ... development-specific settings
      }
    }
  }
}
desired_count = 1
# ... development-specific settings
```

## Stack Resources

### Primary Stacks
1. **`{service_name}`**: Main application stack with ECS services, load balancer, and application resources
2. **`{service_name}-persistent`**: Persistent resources like ECS cluster and shared infrastructure

### Optional Configuration
- **DNS Records**: Automatically created when both `hostedZoneId` and `zoneName` are provided
- **KMS Encryption**: Uses external KMS key when `kms.keyArn` is provided in configuration
- **Existing Resources**: Supports shared infrastructure via `existingResources` configuration

### Resource Naming
All resources are named using the configurable `service_name` from your environment configuration, allowing multiple deployments in the same account.

## Common CDK Commands

```bash
npm run build           # Compile TypeScript to JavaScript
npm run watch          # Watch for changes and compile automatically
npm run test           # Run Jest unit tests
npm run cdk deploy     # Deploy the stack
npm run cdk diff       # Compare deployed stack with current state
npm run cdk synth      # Generate CloudFormation template
npm run cdk destroy    # Remove the stack and all resources
```

## MCP Server Configuration

The MCP Proxy supports multiple optional MCP servers that can be enabled by providing the corresponding AWS Secrets Manager ARNs in your configuration:

### Required Components
- **Google OAuth & WIF**: Always required for authentication
- **MCP Proxy**: Core proxy functionality

### Optional MCP Servers
- **Grafana**: Enable by providing `grafanaSecretArn` - adds Grafana observability tools
- **PostHog**: Enable by providing `posthogSecretArn` - adds product analytics tools  
- **OpenMetadata**: Enable by providing `openmetadataSecretArn` - adds data catalog tools

### Load Balancer Configuration
- **Internal Load Balancer**: Always created for internal/VPN access
  - Configure `internalNetworks` to specify which CIDR blocks can access it
  - Defaults to RFC 1918 private ranges if not specified
- **External Load Balancer**: Optional internet-facing load balancer for AI providers
  - Set `enableExternalLoadBalancer: true` to enable external access
  - Only needed if you plan to use AI providers like Claude that need internet access
  - **Security Note**: Disabled by default to minimize security exposure

### Port Configuration
- **`loadBalancerPorts`**: Array of ports to configure on load balancer listeners (default: [443])
  - Use multiple ports for shared infrastructure: `[443, 8443, 9443]`
- **`servicePort`**: Port for this specific service instance (default: 443)
  - Must be one of the ports listed in `loadBalancerPorts`

### Shared Infrastructure Support
The stack supports cost-efficient shared infrastructure deployments:
- **Existing Resources**: Use existing ECS clusters and load balancers
- **Multi-Environment**: Deploy multiple services sharing the same infrastructure
- **Cost Optimization**: Share expensive resources like ALBs across environments
- **DNS Management**: Conditional Route53 record creation respects resource ownership

## DNS Configuration Options

The stack provides flexible DNS management to accommodate different deployment scenarios:

### 1. **Automatic DNS Management (Recommended)**
Provide both `hostedZoneId` and `zoneName` in your configuration:
- Creates A records: `<serviceName>.<zoneName>` → internal load balancer
- Creates A records: `<serviceName>-ext.<zoneName>` → external load balancer (if enabled)
- Automatically manages record updates during deployments

### 2. **External DNS Management**
Omit the `dns` section from your configuration:
- No Route53 records are created by this stack
- You manage DNS records externally (manual, Terraform, etc.)
- Use load balancer DNS names from stack outputs to create your own records

### 3. **Shared Infrastructure DNS**
When using `existingResources` with existing load balancers:
- No DNS records are created regardless of DNS configuration
- DNS should be managed by the parent stack that owns the load balancers
- Allows multiple services to share the same domain with different paths/ports

**Example DNS Outputs:**
After deployment, the stack outputs load balancer DNS names that you can use:
- Internal LB: `mcp-proxy-internal-alb-123456789.eu-west-1.elb.amazonaws.com`
- External LB: `mcp-proxy-external-alb-987654321.eu-west-1.elb.amazonaws.com`

### Minimal Configuration
For a basic setup (VS Code, internal agents only):

```json
{
  "dns": {
    "hostedZoneId": "Z03108621XXXXXXXXXX",
    "zoneName": "example.com"
  },
  "secrets": {
    "googleWifSecretArn": "arn:aws:secretsmanager:...",
    "googleOauthSecretArn": "arn:aws:secretsmanager:..."
  },
  "saEmail": "your-sa@your-gcp-project.iam.gserviceaccount.com",
  "enableExternalLoadBalancer": false,
  "internalNetworks": ["10.0.0.0/16", "192.168.1.0/24"]
}
```

### Configuration without DNS (External DNS Management)
To deploy without automatic DNS record creation:

```json
{
  // Omit the "dns" section entirely
  "secrets": {
    "googleWifSecretArn": "arn:aws:secretsmanager:...",
    "googleOauthSecretArn": "arn:aws:secretsmanager:..."
  },
  "saEmail": "your-sa@your-gcp-project.iam.gserviceaccount.com",
  "enableExternalLoadBalancer": false,
  "internalNetworks": ["10.0.0.0/16", "192.168.1.0/24"]
}
```
> **Note**: When DNS is omitted, you'll need to create your own DNS records pointing to the load balancer endpoints.

### Configuration for AI Providers
To enable access for external AI providers like Claude:

```json
"secrets": {
  "googleWifSecretArn": "arn:aws:secretsmanager:...",
  "googleOauthSecretArn": "arn:aws:secretsmanager:..."
},
"saEmail": "your-sa@your-gcp-project.iam.gserviceaccount.com",
"enableExternalLoadBalancer": true,
"internalNetworks": ["10.0.0.0/16", "192.168.1.0/24"]
```

### Shared Infrastructure Configuration
For cost-efficient multi-environment deployments:

```json
// Parent environment (creates shared infrastructure)
"shared-parent": {
  "serviceName": "mcp-proxy-shared",
  "loadBalancerPorts": [443, 8443, 9443],  // Configure all ports for child services
  "servicePort": 443,                      // Parent uses port 443
  "internalNetworks": ["10.0.0.0/16"]
},

// Child environment (uses existing infrastructure) 
"dev1": {
  "serviceName": "mcp-proxy-dev1",
  "servicePort": 8443,                     // Child uses port 8443
  "existingResources": {
    "clusterName": "mcp-proxy-shared-cluster",
    "internalLoadBalancerArn": "arn:aws:elasticloadbalancing:..."
  }
}
```

### Full Configuration
To enable all optional MCP servers with external access:

```json
"secrets": {
  "googleWifSecretArn": "arn:aws:secretsmanager:...",
  "googleOauthSecretArn": "arn:aws:secretsmanager:...",
  "grafanaSecretArn": "arn:aws:secretsmanager:...",
  "posthogSecretArn": "arn:aws:secretsmanager:...",
  "openmetadataSecretArn": "arn:aws:secretsmanager:..."
},
"saEmail": "your-sa@your-gcp-project.iam.gserviceaccount.com",
"grafanaUrl": "https://your-grafana.url",
"enableExternalLoadBalancer": true
```

> **Security Note**: The external load balancer is disabled by default to minimize security exposure. Only enable it if you need external AI provider access.

## MCP Server Configuration Files

The system uses two configuration approaches:

- **`config/mcp-servers.json`**: Minimal configuration with only the fetch server for basic functionality
- **`config/mcp-servers.example.jsonc`**: Complete example showing all available MCP servers with detailed comments

To add optional MCP servers, copy the relevant sections from the example file to your `mcp-servers.json` and configure according to your setup.

## Prerequisites

### AWS Setup
- AWS CLI configured with appropriate credentials
- CDK bootstrapped in your target region: `npx cdk bootstrap`
- VPC with public (if using external loadbalancer) and private subnets
- Route53 hosted zone for your domain (optional - only if using automatic DNS)
- ACM certificate for HTTPS
- KMS key for encryption (optional - only if using custom encryption)

### Required Permissions
Your AWS credentials need permissions for:
- ECS, EC2, and VPC management
- IAM role creation and management
- Route53 DNS record management
- Secrets Manager access
- ECR repository access
- CloudWatch logs management

## Security Configuration

### Secrets Management
Store sensitive configuration in AWS Secrets Manager:

```bash
# Google OAuth credentials
aws secretsmanager create-secret \
    --name "mcp-proxy/googleOAuth" \
    --secret-string '{"client_id":"your-id","client_secret":"your-secret"}'

# Google Workload Identity Federation
aws secretsmanager create-secret \
    --name "mcp-proxy/googleWIF" \
    --secret-string '{"type":"service_account",...}'
```

### Network Security
- ECS tasks run in private subnets
- Load balancer in public subnets with security groups
- HTTPS-only with automatic HTTP redirect
- VPC endpoints for AWS services (optional)

## Monitoring and Logging

### CloudWatch Integration
- Application logs automatically sent to CloudWatch
- Log groups created per service
- Structured logging for easy querying

### Health Checks
- Application Load Balancer health checks
- ECS service health monitoring
- Auto-scaling based on CPU/memory utilization

## Troubleshooting

### Common Issues

**"Configuration file not found"**
```bash
cp cdk.example.jsonc cdk.json
# Edit cdk.json with your values
```

**"CDK not bootstrapped"**
```bash
npx cdk bootstrap aws://ACCOUNT-NUMBER/REGION
```

**"Stack deployment failed"**
1. Check that all ARNs in cdk.json exist in your AWS account
2. Verify IAM permissions for CDK deployment
3. Ensure VPC and subnets are properly configured
4. Check that domain and certificates are valid

### Validation
The configuration is automatically validated when you run CDK commands. Common validation errors and solutions are documented in [CONFIGURATION.md](./CONFIGURATION.md).

## Advanced Configuration

### Custom Image Tags
Control which Docker images to deploy:

```bash
# Deploy specific image tag
IMAGE_TAG=v1.2.3 npm run cdk deploy

# Deploy latest development build
IMAGE_TAG=dev-latest npm run cdk deploy
```

### KMS Encryption
To use custom KMS encryption, you must first create a KMS key externally:

```bash
# Create KMS key (outside of this stack)
aws kms create-key --description "MCP Proxy encryption key"

# Note the key ARN for configuration
aws kms describe-key --key-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Then add to your configuration:

```json
{
  "kms": {
    "keyArn": "arn:aws:kms:eu-west-1:123456789012:key/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  }
}
```

> **Important**: This stack does NOT create KMS keys. You must create and manage KMS keys externally for security best practices.

### Multiple Environments
Deploy to different environments with isolated resources:

```bash
# Deploy development environment
CONFIG_ENV=development npm run cdk deploy

# Deploy production environment  
CONFIG_ENV=production npm run cdk deploy
```

## Next Steps

After successful deployment:

1. **Configure OAuth**: Set up Google Workspace integration
2. **Test Connectivity**: Verify MCP clients can connect
3. **Monitor Logs**: Check CloudWatch for application health
4. **Set Up Clients**: Configure VS Code, Claude, or other MCP clients

For detailed setup instructions, see the main project [README.md](../../README.md) and [CONFIGURATION.md](./CONFIGURATION.md).
