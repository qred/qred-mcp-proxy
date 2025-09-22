import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53_targets from 'aws-cdk-lib/aws-route53-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import { generateLogicId, getSecurityGroup } from './constructs/helpers';
import { Construct } from 'constructs';

export interface Props extends cdk.StackProps {
  vpcId: string;
  hostedZoneId?: string;                // Optional - only needed if DNS records should be created
  zoneName?: string;                    // Optional - only needed if DNS records should be created
  enableExternalLoadBalancer?: boolean; // Enable external load balancer for AI providers (default: false)
  internalNetworks?: string[];          // CIDR blocks allowed to access internal load balancer
  loadBalancerPorts?: number[];         // Ports to configure on load balancer listeners (for shared infrastructure)
  servicePort?: number;                 // Port for this specific service instance (default: 443)
  // Existing resources configuration (for shared environments in the same account)
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

export class MCPProxyPersistentStack extends cdk.Stack {
  private readonly serviceName: string;
  private readonly vpc: ec2.IVpc;
  public readonly cluster: ecs.ICluster;
  public proxyTaskRole: iam.Role;
  public readonly loadBalancers: {
    internalLoadBalancer: elbv2.IApplicationLoadBalancer; // Changed to interface to support both new and existing LBs
    externalLoadBalancer?: elbv2.IApplicationLoadBalancer; // Optional - only created if enabled
    securityGroupInternalLb: ec2.ISecurityGroup; // Changed to interface to support both new and existing SGs
    securityGroupExternalLb?: ec2.ISecurityGroup; // Optional - only created if external LB is enabled
  };

  constructor(scope: Construct, id: string, props: Props) {
    super(scope, id, props);

    // lookups
    this.vpc = ec2.Vpc.fromLookup(this, 'VPC', {
      vpcId: props.vpcId
    });

    // vpc doesn't exist eg wrong account
    if (this.vpc.vpcId === 'vpc-12345') {
      return
    }

    this.serviceName = this.stackName;
    
    // DNS configuration is optional - only create zone lookup and records if DNS config is provided
    const zone = props.hostedZoneId && props.zoneName ? 
      route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
        hostedZoneId: props.hostedZoneId,
        zoneName: props.zoneName
      }) : undefined;

    // persistent
    this.cluster = this.getCluster(this.serviceName, props.existingResources?.clusterName);
    this.loadBalancers = this.getLoadBalancers(
      this.serviceName, 
      props.enableExternalLoadBalancer, 
      props.internalNetworks, 
      props.loadBalancerPorts,
      props.servicePort,
      props.existingResources
    );
    this.proxyTaskRole = new iam.Role(this, `ProxyTaskRole`, {
      roleName: `${this.serviceName}-task-role`,
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
    });

    if (props.hostedZoneId && props.zoneName) {
      const zone = route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
        hostedZoneId: props.hostedZoneId,
        zoneName: props.zoneName
      });
      // DNS Records - only create if we have DNS configuration and created new load balancers (not for existing ones)
      // When using existing load balancers, DNS should be managed by the parent stack
      if (!props.existingResources?.internalLoadBalancerArn) {
        // DNS Records for internal domain (only if we created the internal LB and have DNS config)
        this.getRoute53ARecord(`internal-lb`, `${this.serviceName}.${zone.zoneName}`, zone, this.loadBalancers.internalLoadBalancer);
      }
      
      // DNS Records for external domain (only if we created the external LB, it's enabled, and we have DNS config)
      if (this.loadBalancers.externalLoadBalancer && !props.existingResources?.externalLoadBalancerArn) {
        this.getRoute53ARecord(`external-lb`, `${this.serviceName}-ext.${zone.zoneName}`, zone, this.loadBalancers.externalLoadBalancer);
      }
    }
  }

  private getCluster(name: string, existingClusterName?: string): ecs.ICluster {
    if (existingClusterName) {
      // Use existing cluster
      return ecs.Cluster.fromClusterAttributes(this, 'ExistingCluster', {
        clusterName: existingClusterName,
        vpc: this.vpc,
      });
    }
    
    // Create new cluster
    return new ecs.Cluster(this, 'Cluster', {
      clusterName: name,
      vpc: this.vpc,
      containerInsightsV2: ecs.ContainerInsights.ENABLED,
    });
  }
  
  private getLoadBalancers(
    id: string, 
    enableExternalLoadBalancer?: boolean, 
    internalNetworks?: string[], 
    loadBalancerPorts?: number[],
    servicePort?: number,
    existingResources?: {
      clusterName?: string;
      internalLoadBalancerArn?: string;
      externalLoadBalancerArn?: string;
      internalLoadBalancerSecurityGroupId?: string;
      externalLoadBalancerSecurityGroupId?: string;
    }
  ) {
    const port = servicePort || 443; // Default to 443 if not specified
    const allPorts = loadBalancerPorts || [port]; // Use loadBalancerPorts if specified, otherwise just the service port
    
    // Require explicit configuration of internal networks for security (only for new load balancers)
    if (!existingResources?.internalLoadBalancerArn && (!internalNetworks || internalNetworks.length === 0)) {
      throw new Error('internalNetworks must be explicitly configured in cdk.json for security when creating new load balancers. Example: ["10.0.0.0/16"] for VPC-only access.');
    }
    
    // Handle Internal Load Balancer
    let internalLoadBalancer: elbv2.IApplicationLoadBalancer;
    let securityGroupInternalLb: ec2.ISecurityGroup;
    
    if (existingResources?.internalLoadBalancerArn) {
      // Use existing internal load balancer AS-IS - do not modify it
      internalLoadBalancer = elbv2.ApplicationLoadBalancer.fromApplicationLoadBalancerAttributes(this, 'ExistingInternalLoadBalancer', {
        loadBalancerArn: existingResources.internalLoadBalancerArn,
        securityGroupId: existingResources.internalLoadBalancerSecurityGroupId || '', // Import existing security group if provided
      });
      
      // Import the existing security group instead of creating a dummy one
      if (existingResources.internalLoadBalancerSecurityGroupId) {
        securityGroupInternalLb = ec2.SecurityGroup.fromSecurityGroupId(this, 'ExistingInternalSecurityGroup', existingResources.internalLoadBalancerSecurityGroupId);
      } else {
        // Fallback: create a minimal security group if the existing one is not specified
        securityGroupInternalLb = getSecurityGroup(this, this.vpc, this.serviceName, 'internal-lb-sg-fallback');
      }
    } else {
      // Create new internal load balancer with proper security configuration
      securityGroupInternalLb = getSecurityGroup(this, this.vpc, this.serviceName, 'internal-lb-sg');
      
      // Add rules for each configured internal network and all specified load balancer ports
      internalNetworks!.forEach((cidr, index) => {
        allPorts.forEach((portNum) => {
          securityGroupInternalLb.connections.allowFrom(
            ec2.Peer.ipv4(cidr), 
            ec2.Port.tcp(portNum), 
            `Internal network ${index + 1} - Port ${portNum}`
          );
        });
      });

      internalLoadBalancer = new elbv2.ApplicationLoadBalancer(this, 'InternalLoadBalancer', {
        vpc: this.vpc,
        loadBalancerName: `${id}-internal-alb`,
        internetFacing: false,
        securityGroup: securityGroupInternalLb
      });
    }

    // Handle External Load Balancer
    let externalLoadBalancer: elbv2.IApplicationLoadBalancer | undefined;
    let securityGroupExternalLb: ec2.ISecurityGroup | undefined;

    if (enableExternalLoadBalancer) {
      if (existingResources?.externalLoadBalancerArn) {
        // Use existing external load balancer AS-IS - do not modify it
        externalLoadBalancer = elbv2.ApplicationLoadBalancer.fromApplicationLoadBalancerAttributes(this, 'ExistingExternalLoadBalancer', {
          loadBalancerArn: existingResources.externalLoadBalancerArn,
          securityGroupId: existingResources.externalLoadBalancerSecurityGroupId || '', // Import existing security group if provided
        });
        
        // Import the existing security group instead of creating a dummy one
        if (existingResources.externalLoadBalancerSecurityGroupId) {
          securityGroupExternalLb = ec2.SecurityGroup.fromSecurityGroupId(this, 'ExistingExternalSecurityGroup', existingResources.externalLoadBalancerSecurityGroupId);
        } else {
          // Fallback: create a minimal security group if the existing one is not specified
          securityGroupExternalLb = getSecurityGroup(this, this.vpc, this.serviceName, 'external-lb-sg-fallback');
        }
      } else {
        // Create new external load balancer with proper security configuration
        securityGroupExternalLb = getSecurityGroup(this, this.vpc, this.serviceName, 'external-lb-sg');
        
        // Anthropic Claude outbound IP addresses
        const anthropicIPs = [
          '34.162.46.92/32',
          '34.162.102.82/32', 
          '34.162.136.91/32',
          '34.162.142.92/32',
          '34.162.183.95/32'
        ];
        
        anthropicIPs.forEach((ip, index) => {
          allPorts.forEach((portNum) => {
            securityGroupExternalLb!.connections.allowFrom(
              ec2.Peer.ipv4(ip), 
              ec2.Port.tcp(portNum), 
              `Anthropic outbound IP ${index + 1} - Port ${portNum}`
            );
          });
        });

        externalLoadBalancer = new elbv2.ApplicationLoadBalancer(this, 'ExternalLoadBalancer', {
          vpc: this.vpc,
          loadBalancerName: `${id}-external-alb`,
          internetFacing: true,
          securityGroup: securityGroupExternalLb
        });
      }
    }

    return {internalLoadBalancer, externalLoadBalancer, securityGroupInternalLb, securityGroupExternalLb}
  }
  
  private getRoute53ARecord(id: string, domainName: string, zone: route53.IHostedZone, loadBalancer: elbv2.IApplicationLoadBalancer) {
    return new route53.ARecord(this, `AliasRecord${generateLogicId(id)}`, {
      target: route53.RecordTarget.fromAlias(new route53_targets.LoadBalancerTarget(loadBalancer)),
      zone: zone,
      recordName: domainName
    });
  }
}