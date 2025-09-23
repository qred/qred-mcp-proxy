import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as path from 'path';
import * as fs from 'fs';
import { generateLogicId, getSecurityGroup } from './helpers';
import { McpProxyProps, McpContainerOptions } from '../types/interfaces';
import { Construct } from 'constructs';

export interface TargetGroupAttachment {
  targetGroup: elbv2.ApplicationTargetGroup;
  containerName: string;
  containerPort: number;
}

export function getTaskDefinition(
  scope: Construct,
  id: string,
  logsRetentionDays: logs.RetentionDays,
  stackProps: McpProxyProps,
): ecs.FargateTaskDefinition {
  // Read the servers.json template override file
  const serversJsonPath = path.join(__dirname, '../../config', 'mcp-servers.json');
  const serversJsonTemplate = fs.readFileSync(serversJsonPath, 'utf8');

  const mcpProxyRepository = ecr.Repository.fromRepositoryArn(scope, 'MCPProxyEcrRepo', stackProps.ecrRepositoryArns.mcpProxyRepositoryArn);
  const mcpProxyImage = ecs.ContainerImage.fromEcrRepository(mcpProxyRepository, stackProps.imageTag);

  const mcpOauthRepository = ecr.Repository.fromRepositoryArn(scope, 'MCPOauthEcrRepo', stackProps.ecrRepositoryArns.mcpOauthRepositoryArn);
  const mcpOauthImage = ecs.ContainerImage.fromEcrRepository(mcpOauthRepository, stackProps.imageTag);

  // Build container options dynamically based on provided secrets
  const mcpContainerOptions: McpContainerOptions = [
    {
      id: 'config-sync',
      essential: false,
      image: ecs.ContainerImage.fromRegistry('public.ecr.aws/amazonlinux/amazonlinux:2023'),
      cpu: 256,
      memoryLimitMiB: 512,
      command: [
        'sh', '-c', `
          set -e
          echo "Install jq & curl"
          dnf update -y && dnf -y install jq
          echo "Creating servers.json configuration file..."
          cat > /shared/servers.json << 'EOF'
${serversJsonTemplate}
EOF
          echo "Configuration file created successfully... Generated servers.json:"
          jq . /shared/servers.json
          echo "Config sync completed successfully"
          `
      ]
    }
  ];

  // Build proxy container secrets dynamically
  const proxySecrets: { [key: string]: ecs.Secret } = {};

  if (stackProps.posthogSecretArn) {
    proxySecrets.POSTHOG_API_KEY = ecs.Secret.fromSecretsManager(
      secretsmanager.Secret.fromSecretCompleteArn(scope, 'PosthogApiKey', stackProps.posthogSecretArn),
      'api_key'
    );
  }

  if (stackProps.openmetadataSecretArn) {
    proxySecrets.OPENMETADATA_JWT_TOKEN = ecs.Secret.fromSecretsManager(
      secretsmanager.Secret.fromSecretCompleteArn(scope, 'OpenmetadataJWTToken', stackProps.openmetadataSecretArn),
      'token'
    );
  }

  // Add proxy container
  mcpContainerOptions.push({
    id: 'proxy',
    image: mcpProxyImage,
    essential: true,
    containerPort: 8096,
    ...(Object.keys(proxySecrets).length > 0 && { secrets: proxySecrets }),
    environment: {
      OAUTH_SERVICE_URL: 'http://127.0.0.1:8001',
      FORCE_HTTPS_DOMAINS: stackProps.forceHttpsDomains || '',
    } satisfies ecs.ContainerDefinitionOptions['environment'],
    command: ["--pass-environment", "--port", "8096", "--host", "0.0.0.0", "--named-server-config", "/app/config-sync/servers.json", "--google-auth-required"]
  });

  // Only add Grafana container if grafana secret is provided
  if (stackProps.grafanaSecretArn) {
    if (!stackProps.grafanaUrl) {
      throw new Error('grafanaUrl is required when grafanaSecretArn is provided');
    }

    mcpContainerOptions.push({
      id: 'grafana',
      image: ecs.ContainerImage.fromRegistry('mcp/grafana'),
      essential: true,
      containerPort: 8000,
      secrets: {
        GRAFANA_SERVICE_ACCOUNT_TOKEN: ecs.Secret.fromSecretsManager(
          secretsmanager.Secret.fromSecretCompleteArn(scope, 'GrafanaSAToken', stackProps.grafanaSecretArn),
          'token'
        )
      },
      environment: {
        GRAFANA_URL: stackProps.grafanaUrl
      } satisfies ecs.ContainerDefinitionOptions['environment'],
      command: ["-t", "streamable-http"]
    });
  }

  // Add auth container (always required)
  mcpContainerOptions.push({
    id: 'auth',
    essential: true,
    image: mcpOauthImage,
    containerPort: 8001,
    secrets: {
      GCP_SECRET_ARN: ecs.Secret.fromSecretsManager(secretsmanager.Secret.fromSecretCompleteArn(scope, 'GoogleWifConfig', stackProps.googleWifSecretArn)),
      GOOGLE_OAUTH: ecs.Secret.fromSecretsManager(secretsmanager.Secret.fromSecretCompleteArn(scope, 'GoogleOAuth', stackProps.googleOAuthSecretArn)),
    },
    environment: {
      SA_EMAIL: stackProps.saEmail,
      GOOGLE_WORKSPACE_DOMAIN: stackProps.googleWorkspaceDomain,
      GOOGLE_ADMIN_EMAIL: stackProps.googleAdminEmail,
      GOOGLE_CUSTOMER_ID: stackProps.googleCustomerId,
      GOOGLE_ORG_UNIT_PATH: stackProps.googleOrgUnitPath,
      FORCE_HTTPS_DOMAINS: stackProps.forceHttpsDomains || '',
    } satisfies ecs.ContainerDefinitionOptions['environment'],
    command: ["--host", "0.0.0.0", "--port", "8001"],
    healthcheck: {
      command: ['CMD-SHELL', 'curl -f http://localhost:8001/health || exit 1'],
      interval: cdk.Duration.seconds(30),
      timeout: cdk.Duration.seconds(10),
      retries: 3,
      startPeriod: cdk.Duration.seconds(60)
    }
  });

  const logGroup = new logs.LogGroup(scope, 'LogGroup', {
    logGroupName: `/aws/ecs/${id}`,
    retention: logsRetentionDays,
    removalPolicy: cdk.RemovalPolicy.DESTROY
  });
  const taskDefinition = new ecs.FargateTaskDefinition(scope, `TaskDefinition`, {
    family: `${id}`,
    cpu: 1024,
    taskRole: stackProps.taskRole,
    memoryLimitMiB: 2048,
    runtimePlatform: {
      cpuArchitecture: ecs.CpuArchitecture.ARM64
    }
  });
  mcpContainerOptions.forEach(container => {
    const containerOpts: ecs.ContainerDefinitionOptions = {
      containerName: container.id,
      image: container.image,
      essential: container.essential,
      logging: ecs.LogDriver.awsLogs({
        streamPrefix: 'ecs',
        logGroup: logGroup
      }),
      ...(container.cpu ? { cpu: container.cpu } : {}),
      ...(container.memoryLimitMiB ? { memoryLimitMiB: container.memoryLimitMiB } : {}),
      ...(container.containerPort ? {
        portMappings: [{
          containerPort: container.containerPort,
          ...(container.hostPort ? { hostPort: container.hostPort } : {})
        }]
      } : {}),
      ...(container.user ? { user: container.user } : {}),
      ...(container.entryPoint ? { entryPoint: container.entryPoint } : {}),
      ...(container.command ? { command: container.command } : {}),
      ...(container.environment ? { environment: container.environment } : {}),
      ...(container.secrets ? { secrets: container.secrets } : {}),
      ...(container.healthcheck ? { healthCheck: container.healthcheck } : {})
    }
    taskDefinition.addContainer(`Container${generateLogicId(container.id)}`, containerOpts);

  });

  // Allow KMS decrypt to execution role (only if KMS is enabled)
  if (stackProps.kmsKeyArn) {
    taskDefinition.addToExecutionRolePolicy(new iam.PolicyStatement({
      actions: [
        "kms:Decrypt",
      ],
      resources: [stackProps.kmsKeyArn],
      effect: iam.Effect.ALLOW
    }));
  }

  return taskDefinition;
}

export function getSimpleFargateService(
  scope: Construct,
  id: string,
  vpc: ec2.IVpc,
  cluster: ecs.ICluster,
  taskDefinition: ecs.FargateTaskDefinition,
  desiredCount: number,
  targetGroupAttachments: TargetGroupAttachment[]
): ecs.FargateService {

  // Create a regular Fargate service
  const service = new ecs.FargateService(scope, `FargateService`, {
    serviceName: id,
    cluster: cluster,
    taskDefinition: taskDefinition,
    healthCheckGracePeriod: cdk.Duration.seconds(60),
    assignPublicIp: false,
    enableExecuteCommand: false,
    desiredCount: desiredCount,
    securityGroups: [getSecurityGroup(scope, vpc, id, 'ecs-sg')],
    vpcSubnets: {
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS
    }
  });

  // Attach service to each target group
  targetGroupAttachments.forEach((attachment) => {
    attachment.targetGroup.addTarget(service.loadBalancerTarget({
      containerName: attachment.containerName,
      containerPort: attachment.containerPort,
      protocol: ecs.Protocol.TCP
    }));
  });

  // Configure deployment circuit breaker to stop failed deployments
  const cfnService = service.node.defaultChild as ecs.CfnService;
  cfnService.deploymentConfiguration = {
    maximumPercent: 200,
    minimumHealthyPercent: 50,
    deploymentCircuitBreaker: {
      enable: true,
      rollback: true
    }
  };

  return service;
}
