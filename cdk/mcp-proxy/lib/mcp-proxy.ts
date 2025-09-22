import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import { getTaskDefinition, getSimpleFargateService, TargetGroupAttachment } from './constructs/service';
import { setupVolumes } from './constructs/volumes';
import { getListener, getTargetGroup } from './constructs/helpers';
import { McpProxyProps } from './types/interfaces';
import { Construct } from 'constructs';

export class MCPProxyStack extends cdk.Stack {
  private readonly vpc: ec2.IVpc;

  constructor(scope: Construct, id: string, props: McpProxyProps) {
    super(scope, id, props);

    // lookups
    this.vpc = ec2.Vpc.fromLookup(this, 'VPC', {
      vpcId: props.vpcId
    });

    // vpc doesn't exist eg wrong account
    if (this.vpc.vpcId === 'vpc-12345') {
      return
    }

    const cert = acm.Certificate.fromCertificateArn(this, 'Certificate', props.certificateArn);

    const serviceName = this.stackName;
    const servicePort = props.servicePort || 443;  // Default to 443 if not specified

    // task definition
    const logRetention = logs.RetentionDays.THREE_MONTHS;
    const taskDefinition = getTaskDefinition(this, serviceName, logRetention, props );
    setupVolumes(taskDefinition);
    
    // Create listeners for simplified single-port service
    const internalListener = getListener(this, 'int', cert, props.loadBalancers.internalLoadBalancer, servicePort );
    
    // Create target groups for both MCP proxy and OAuth services
    const mcpProxyTargetGroup = getTargetGroup(this, 'proxy', serviceName, this.vpc, 8096, '/status', 8096);
    const oauthTargetGroup = getTargetGroup(this, 'auth', serviceName, this.vpc, 8001, '/health', 8001);

    let targetGroupAttachments: TargetGroupAttachment[] = []

    // Add target groups to internal listener with routing rules
    internalListener.addTargetGroups('McpProxyRule', {
      targetGroups: [mcpProxyTargetGroup],
      conditions: [
        elbv2.ListenerCondition.pathPatterns(['/messages*', '/mcp*'])
      ],
      priority: 10
    });
    
    internalListener.addTargetGroups('OAuthRule', {
      targetGroups: [oauthTargetGroup],
      conditions: [
        elbv2.ListenerCondition.pathPatterns(['/auth*', '/oauth*', '/.well-known*', '/callback*'])
      ],
      priority: 20
    });

    targetGroupAttachments.push(
      { targetGroup: mcpProxyTargetGroup, containerName: 'proxy', containerPort: 8096 },
      { targetGroup: oauthTargetGroup, containerName: 'auth', containerPort: 8001 }
    );

    // Conditionally add external listener and target groups if external load balancer is enabled
    if (props.loadBalancers.externalLoadBalancer) {
      const externalListener = getListener(this, 'ext', cert, props.loadBalancers.externalLoadBalancer, servicePort );
      const mcpProxyExtTargetGroup = getTargetGroup(this, 'proxy-ext', serviceName, this.vpc, 8096, '/status', 8096);
      const oauthExtTargetGroup = getTargetGroup(this, 'oauth-ext', serviceName, this.vpc, 8001, '/health', 8001);
      
      externalListener.addTargetGroups('ExternalProxyRule', {
        targetGroups: [mcpProxyExtTargetGroup],
        conditions: [
          elbv2.ListenerCondition.pathPatterns(['/messages*', '/mcp*'])
        ],
        priority: 10
      });
      
      externalListener.addTargetGroups('ExternalOAuthRule', {
        targetGroups: [oauthExtTargetGroup],
        conditions: [
          elbv2.ListenerCondition.pathPatterns(['/auth*', '/oauth*', '/.well-known*', '/callback*'])
        ],
        priority: 20
      });

      targetGroupAttachments.push(
        { targetGroup: mcpProxyExtTargetGroup, containerName: 'proxy', containerPort: 8096 },
        { targetGroup: oauthExtTargetGroup, containerName: 'auth', containerPort: 8001 }
      );
    }

    // Create the service with pre-created target groups
    const service = getSimpleFargateService(
      this, 
      `${serviceName}`, 
      this.vpc, 
      props.cluster, 
      taskDefinition, 
      props.desiredCount,
      targetGroupAttachments
    );
    
    // Allow traffic to both MCP proxy and OAuth services
    service.connections.allowFrom(props.loadBalancers.securityGroupInternalLb, ec2.Port.tcp(8096), 'Internal LB to MCP Proxy');
    service.connections.allowFrom(props.loadBalancers.securityGroupInternalLb, ec2.Port.tcp(8001), 'Internal LB to OAuth Service');
    
    // Conditionally allow external traffic if external load balancer is enabled
    if (props.loadBalancers.securityGroupExternalLb) {
      service.connections.allowFrom(props.loadBalancers.securityGroupExternalLb, ec2.Port.tcp(8096), 'External LB to MCP Proxy');
      service.connections.allowFrom(props.loadBalancers.securityGroupExternalLb, ec2.Port.tcp(8001), 'External LB to OAuth Service');
    }
  }
}
