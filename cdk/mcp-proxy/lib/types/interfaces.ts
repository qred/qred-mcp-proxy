import * as cdk from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';

export interface McpProxyProps extends cdk.StackProps {
  vpcId: string;
  certificateArn: string;
  imageTag: string;
  kmsKeyArn?: string; // Optional - only used if ENABLE_KMS=true
  cluster: ecs.ICluster;
  loadBalancers: {
    internalLoadBalancer: elbv2.IApplicationLoadBalancer; // Changed to interface to support both new and existing LBs
    externalLoadBalancer?: elbv2.IApplicationLoadBalancer; // Optional - only present if enabled
    securityGroupInternalLb: ec2.ISecurityGroup; // Changed to interface to support both new and existing SGs
    securityGroupExternalLb?: ec2.ISecurityGroup; // Optional - only present if external LB is enabled
  };
  taskRole: iam.Role;
  googleWifSecretArn: string;
  googleOAuthSecretArn: string;
  grafanaSecretArn?: string;        // Optional - if provided, enables Grafana MCP server
  openmetadataSecretArn?: string;   // Optional - if provided, enables OpenMetadata MCP server
  posthogSecretArn?: string;        // Optional - if provided, enables PostHog MCP server
  saEmail: string;                  // Service Account email for Google authentication
  googleWorkspaceDomain: string;    // Google Workspace domain for OAuth (e.g., "company.com")
  googleAdminEmail: string;         // Google Workspace admin email for WIF service
  googleCustomerId: string;         // Google Workspace customer ID for Directory API (e.g., "CXXXXXXXXX")
  googleOrgUnitPath: string;        // Google Workspace organizational unit path for user search (e.g., "/")
  forceHttpsDomains?: string;       // Comma-separated domains that should force HTTPS behind load balancer
  grafanaUrl?: string;              // Grafana instance URL for MCP server (required if grafanaSecretArn is provided)
  desiredCount: number;
  loadBalancerPorts?: number[];     // Ports to configure on load balancer listeners (for shared infrastructure)
  servicePort?: number;             // Port for this specific service instance (default: 443)
  ecrRepositoryArns: {
    mcpProxyRepositoryArn: string;
    mcpOauthRepositoryArn: string;
  };
}

export interface McpContainerOption {
  id: string;
  image: ecs.ContainerImage;
  essential: boolean;
  cpu?: number;
  memoryLimitMiB?: number;
  user?: string;
  containerPort?: number;
  hostPort?: number;
  secrets?: ecs.ContainerDefinitionOptions['secrets'];
  environment?: ecs.ContainerDefinitionOptions['environment'];
  entryPoint?: string[];
  command?: string[];
  healthcheck?: ecs.HealthCheck;
}

export type McpContainerOptions = McpContainerOption[];
