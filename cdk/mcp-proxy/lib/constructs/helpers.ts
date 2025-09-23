import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as route53_targets from 'aws-cdk-lib/aws-route53-targets';
import { Construct } from 'constructs';

export function generateLogicId(id: string): string {
  return id.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join('');
}

export function getRoute53ARecord(
  scope: Construct,
  id: string,
  domainName: string,
  zone: route53.IHostedZone,
  loadBalancer: elbv2.IApplicationLoadBalancer
): route53.ARecord {
  return new route53.ARecord(scope, `AliasRecord${generateLogicId(id)}`, {
    target: route53.RecordTarget.fromAlias(new route53_targets.LoadBalancerTarget(loadBalancer)),
    zone: zone,
    recordName: domainName
  });
}

export function getSecurityGroup(
  scope: Construct,
  vpc: ec2.IVpc,
  serviceName: string,
  suffix: string = 'sg'
): ec2.SecurityGroup {
  const securityGroup = new ec2.SecurityGroup(scope, `SecurityGroup${generateLogicId(suffix)}`, {
    vpc: vpc,
    securityGroupName: `${serviceName}-${suffix}`,
    disableInlineRules: true
  });
  cdk.Tags.of(securityGroup).add('Name', `${serviceName}-${suffix}`);
  return securityGroup;
}

export function getListener(
  scope: Construct,
  id: string,
  cert: acm.ICertificate,
  loadbalancer: elbv2.IApplicationLoadBalancer, // Changed to interface to support both new and existing LBs
  port: number = 443,
): elbv2.ApplicationListener {
  return new elbv2.ApplicationListener(scope, `${generateLogicId(id)}Listener`, {
      port: port,
      loadBalancer: loadbalancer,
      certificates: [cert],
      open: false,
      protocol: elbv2.ApplicationProtocol.HTTPS,
      defaultAction: elbv2.ListenerAction.fixedResponse(404),
      sslPolicy: elbv2.SslPolicy.RECOMMENDED_TLS
    });
}

export function getTargetGroup(
  scope: Construct,
  id: string,
  serviceName: string,
  vpc: ec2.IVpc,
  port: number,
  healthCheckPath: string = '/status',
  healthCheckPort?: number
): elbv2.ApplicationTargetGroup {
  const targetGroup = new elbv2.ApplicationTargetGroup(scope, `TargetGroup${generateLogicId(id)}`, {
    targetGroupName: `${serviceName}-${id}`,
    // ALB communication uses standard HTTP port
    protocol: elbv2.ApplicationProtocol.HTTP,
    port: 80,
    vpc: vpc,
    targetType: elbv2.TargetType.IP,
    deregistrationDelay: cdk.Duration.seconds(5),
    healthCheck: {
      enabled: true,
      interval: cdk.Duration.seconds(30),
      timeout: cdk.Duration.seconds(5),
      healthyThresholdCount: 2,
      unhealthyThresholdCount: 3,
      path: healthCheckPath,
      port: healthCheckPort ? healthCheckPort.toString() : port.toString(),
      protocol: elbv2.Protocol.HTTP
    }
  });

  return targetGroup;
}
