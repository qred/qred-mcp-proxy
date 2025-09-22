# Disclaimer

**This project is provided as-is and intended as an example implementation. While we will make reasonable efforts to address security issues, adopters are responsible for performing their own security reviews, checks, and ongoing maintenance. Use this project as a reference and adapt it to your own security requirements.**

# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

### How to Report

To report a vulnerability, please use one of the following methods:

1. **GitHub Security Advisories** (preferred): Go to the [Security tab](https://github.com/qred/qred-mcp-proxy/security/advisories) and click "Report a vulnerability"
2. **Email**: Send details to [security@qred.com](mailto:security@qred.com) with subject line "MCP Proxy Security Issue"

### What to Include

Please include as much of the following information as possible:

- **Description**: A clear description of the vulnerability
- **Impact**: Potential impact and attack scenarios
- **Reproduction**: Step-by-step instructions to reproduce the issue
- **Affected Versions**: Which versions are affected
- **Environment**: Deployment environment details (AWS region, configuration, etc.)
- **Mitigation**: Any temporary workarounds or mitigation steps

### Response Timeline

- **Initial Response**: We will acknowledge receipt within 3 business days
- **Investigation**: We will investigate and provide an initial assessment within 5 business days of the initial response
- **Resolution**: We aim to resolve critical vulnerabilities within 30 days
- **Disclosure**: We will coordinate responsible disclosure timing with the reporter

### Security Considerations

This project handles enterprise authentication and sensitive data. Key security areas include:

#### Authentication & Authorization
- **OAuth 2.1 Implementation**: Follows RFC 6749, RFC 6750, and security best practices
- **Google Workspace Integration**: Domain-restricted authentication with proper token validation
- **Workload Identity Federation**: Eliminates long-lived service account keys
- **Session Management**: Secure token caching with appropriate expiration

#### Infrastructure Security
- **Network Security**: VPC isolation, security groups, and load balancer configuration
- **Encryption**: TLS in transit, KMS encryption at rest (optional)
- **Secrets Management**: AWS Secrets Manager integration for sensitive data
- **IAM**: Least-privilege access controls for all AWS resources

#### Container Security
- **Base Images**: Regularly updated base images with security patches
- **Dependency Scanning**: Automated vulnerability scanning of dependencies
- **Runtime Security**: Non-root container execution with minimal attack surface

#### Monitoring & Auditing
- **Access Logging**: Comprehensive authentication and activity logging
- **CloudWatch Integration**: Centralized log monitoring and alerting
- **Audit Trail**: All user actions and administrative changes logged

### Common Security Configurations

#### Production Deployment Checklist
- [ ] Configure external KMS encryption key (add `kms.keyArn` to configuration)
- [ ] Configure restrictive `internalNetworks` CIDR blocks
- [ ] Use ACM certificates for TLS termination
- [ ] Enable CloudWatch logging and monitoring
- [ ] Implement network access controls (VPC security groups)
- [ ] Regularly rotate OAuth client secrets
- [ ] Monitor AWS CloudTrail for administrative actions

#### Security Group Configuration
- **Internal Load Balancer**: Only allow access from trusted networks
- **External Load Balancer**: Only enable if required for AI providers and be specific in intended audience
- **ECS Tasks**: Allow only necessary ports (443, 8443 or similar) from load balancers

#### Secrets Management
- **AWS Secrets Manager**: All sensitive data stored securely
- **Cross-Account Access**: Use IAM roles, not direct access keys
- **Environment Variables**: Never store secrets in persistent environment variables

### Dependencies and Supply Chain

We maintain security through:

- **Dependabot**: Automated dependency updates for security patches
- **SBOM Generation**: Software Bill of Materials for transparency
- **Vulnerability Scanning**: Regular scanning of container images and dependencies
- **License Compliance**: All dependencies use compatible open source licenses

### Known Security Considerations

#### OAuth Implementation
- **Client Secret Storage**: OAuth client secrets must be securely stored in AWS Secrets Manager
- **Redirect URI Validation**: Strict validation of OAuth redirect URIs
- **State Parameter**: CSRF protection using state parameter validation
- **Token Scope**: Minimal scope requests following principle of least privilege

#### AWS Infrastructure
- **VPC Configuration**: Requires existing VPC with proper subnet configuration
- **IAM Permissions**: Deployment requires extensive AWS permissions
- **Cross-Account Access**: RDS access patterns need careful IAM configuration
- **Load Balancer Exposure**: External load balancer creates internet exposure

#### Container Runtime
- **Privileged Access**: Containers run as non-root users
- **Network Policies**: Container networking restricted to required ports
- **Resource Limits**: CPU and memory limits prevent resource exhaustion
- **Image Scanning**: Regular vulnerability scanning of container images

### Security Updates

Security updates are prioritized and released according to severity:

- **Critical**: Immediate release (within 24-48 hours)
- **High**: Release within 1 week
- **Medium**: Release with next minor version
- **Low**: Release with next minor version or as backport if needed

### Acknowledgments

We appreciate the security research community and will acknowledge security researchers who responsibly disclose vulnerabilities (unless they prefer to remain anonymous).

### Contact

For security-related questions or concerns, contact:
- Security Email: [security@qred.com](mailto:security@qred.com)
- Project Maintainers: See [CODEOWNERS](.github/CODEOWNERS)

---

**Note**: This security policy is specifically for the MCP Proxy project. For security issues related to the Model Context Protocol specification itself, please refer to the [official MCP documentation](https://modelcontextprotocol.io/).