# Contributing to MCP Proxy

Thank you for your interest in contributing to the MCP Proxy project! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Process](#contributing-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)
- [Community](#community)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [conduct@qred.com](mailto:conduct@qred.com).

## Getting Started

### Ways to Contribute

- **Bug Reports**: Found a bug? Please create an issue with detailed reproduction steps
- **Feature Requests**: Have an idea? Open an issue to discuss it first
- **Documentation**: Help improve our documentation
- **Code**: Submit bug fixes, implement features, or improve performance
- **Testing**: Help expand test coverage or improve existing tests
- **Security**: Report security vulnerabilities following our [Security Policy](SECURITY.md)

### Before You Start

1. **Check existing issues**: Look for existing issues or discussions about your topic
2. **Start small**: Consider starting with issues labeled `good first issue` or `help wanted`
3. **Discuss first**: For significant changes, open an issue to discuss your approach
4. **Read the docs**: Familiarize yourself with the project structure and documentation

## Development Setup

### Quick Start (Recommended)

The fastest way to get started with development:

```bash
# Clone and install dependencies
git clone https://github.com/qred/qred-mcp-proxy.git
cd qred-mcp-proxy
uv sync

# 🎯 RECOMMENDED: Install automated quality hooks
uv run pre-commit install

# Verify everything works
uv run pre-commit run --all-files
```

This setup provides:
- ✅ All Python dependencies installed
- ✅ Automated code quality checks on every commit
- ✅ Consistent formatting and linting
- ✅ Security scanning
- ✅ Type checking

### Prerequisites

- **Python** 3.11+ with uv package manager
- **Node.js** 18+ and npm (for CDK deployment)
- **Docker** and Docker Compose (for container development)
- **AWS CLI** configured (for infrastructure testing)
- **Google Cloud SDK** (for authentication testing)

### Detailed Development Environment

If you need more control or are working on specific components:

1. **Clone the repository**:
   ```bash
   git clone https://github.com/qred/qred-mcp-proxy.git
   cd qred-mcp-proxy
   ```

2. **Set up Python environment**:
   ```bash
   # Install uv if not already installed
   curl -LsSf https://astral.sh/uv/install.sh | sh

   # Create virtual environment and install dependencies
   uv sync
   ```

3. **Set up pre-commit hooks (Highly Recommended)**:
   ```bash
   uv run pre-commit install
   ```

4. **Set up CDK environment** (for infrastructure changes):
   ```bash
   cd cdk/mcp-proxy
   npm install
   npm run build
   ```

5. **Set up Docker development** (for container changes):
   ```bash
   # Build development images
   cd docker/mcp_proxy
   docker build -t mcp-proxy:dev .

   cd ../mcp_oauth
   docker build -t mcp-oauth:dev .
   ```

6. **Configure environment**:
   ```bash
   # Copy example configuration
   cp cdk/mcp-proxy/cdk.example.jsonc cdk/mcp-proxy/cdk.json
   # Edit configuration with your development values
   ```

### Development Workflow

1. **Make your changes**
2. **Automated quality checks** (if pre-commit is installed):
   ```bash
   # Pre-commit hooks run automatically on commit
   git add .
   git commit -m "your changes"  # Quality checks run automatically
   ```

3. **Manual quality checks** (if needed):
   ```bash
   # Run all checks manually
   uv run pre-commit run --all-files

   # Or run individual tools
   uv run ruff check .
   uv run ruff format .
   uv run mypy .
   uv run bandit -r .
   ```

4. **Run tests**:
   ```bash
   # Python tests
   uv run pytest

   # TypeScript tests (if working on CDK)
   cd cdk/mcp-proxy && npm test
   ```

5. **Local development servers** (for testing):
   ```bash
   # Run MCP proxy locally
   cd docker/mcp_proxy
   uv run python -m mcp_proxy_qred

   # Run OAuth sidecar locally
   cd docker/mcp_oauth
   uv run python -m mcp_oauth
   ```

## Contributing Process

### 1. Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally
3. Add the upstream repository as a remote:
   ```bash
   git remote add upstream https://github.com/qred/qred-mcp-proxy.git
   ```

### 2. Create a Branch

Create a feature branch from `main`:
```bash
git checkout main
git pull upstream main
git checkout -b feature/your-feature-name
```

**Branch naming conventions**:
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `test/description` - Test improvements

### 3. Make Changes

- Follow our [coding standards](#coding-standards)
- Write tests for new functionality
- Update documentation as needed
- Keep commits focused and atomic

### 4. Commit Changes

Write clear, descriptive commit messages:
```bash
git commit -m "feat: add support for custom OAuth scopes

- Adds configurable OAuth scope support
- Updates documentation with scope examples
- Includes tests for scope validation

Fixes #123"
```

**Commit message format**:
- Use conventional commit format: `type(scope): description`
- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`
- Include issue references when applicable

### 5. Test Your Changes

Before submitting:
```bash
# Run all tests
uv run pytest
cd cdk/mcp-proxy && npm test

# Test type checking
uv run mypy .

# Test linting
uv run ruff check .
npm run lint

# Test building
npm run build
```

## Coding Standards

### Python Code

- **PEP 8** compliance with line length of 100 characters
- **Type hints** for all function signatures
- **Docstrings** for public functions and classes
- **Error handling** with appropriate exception types
- **Logging** using structured logging with appropriate levels

Example:
```python
from typing import Optional
import logging

logger = logging.getLogger(__name__)

def process_oauth_token(token: str, scope: Optional[str] = None) -> dict[str, str]:
    """Process OAuth token and return user information.

    Args:
        token: The OAuth access token
        scope: Optional scope restriction

    Returns:
        Dictionary containing user information

    Raises:
        ValueError: If token is invalid
        AuthenticationError: If token verification fails
    """
    if not token:
        raise ValueError("Token cannot be empty")

    logger.info("Processing OAuth token", extra={"scope": scope})
    # Implementation here
```

### TypeScript Code

- **TypeScript** with strict mode enabled
- **ESLint** and **Prettier** configuration
- **Type safety** with explicit types, avoid `any`
- **AWS CDK** best practices for infrastructure code
- **Documentation** with TSDoc comments

Example:
```typescript
import { Construct } from 'constructs';
import { StackProps } from 'aws-cdk-lib';

/**
 * Configuration for MCP Proxy load balancer
 */
export interface LoadBalancerConfig {
  /** Ports to configure on load balancer listeners */
  readonly loadBalancerPorts: number[];
  /** Port for this specific service instance */
  readonly servicePort: number;
  /** CIDR blocks allowed to access internal load balancer */
  readonly internalNetworks: string[];
}

/**
 * Creates and configures Application Load Balancer for MCP Proxy
 */
export class McpProxyLoadBalancer extends Construct {
  constructor(scope: Construct, id: string, config: LoadBalancerConfig) {
    super(scope, id);

    // Implementation here
  }
}
```

### Documentation

- **Markdown** for all documentation files
- **Clear structure** with table of contents for longer documents
- **Code examples** that are tested and work
- **Links** to related documentation and external resources
- **Screenshots** when helpful for setup or UI guidance

## Testing

### Test Requirements

- **Unit tests** for all business logic
- **Integration tests** for API endpoints and authentication flows
- **Infrastructure tests** for CDK constructs
- **Security tests** for authentication and authorization
- **Documentation tests** to ensure examples work

### Running Tests

```bash
# Python unit tests
uv run pytest tests/

# Python with coverage
uv run pytest --cov=mcp_proxy_qred tests/

# TypeScript tests
cd cdk/mcp-proxy && npm test

# Infrastructure tests
cd cdk/mcp-proxy && npm run test:integ

# Security tests
uv run bandit -r .
```

### Test Guidelines

- **Test naming**: Use descriptive test names that explain the scenario
- **Arrange-Act-Assert**: Structure tests clearly
- **Mock external dependencies**: Use pytest fixtures and mocks
- **Test edge cases**: Include error conditions and boundary cases
- **Performance tests**: For critical paths and authentication flows

## Documentation

### Documentation Standards

- **Keep it current**: Update docs with code changes
- **Be comprehensive**: Cover setup, configuration, and troubleshooting
- **Include examples**: Provide working code examples
- **Link appropriately**: Reference related sections and external docs
- **Consider the audience**: Write for both new users and experienced developers

### Documentation Types

- **README**: Project overview and quick start
- **API Documentation**: Generated from code comments
- **Setup Guides**: Step-by-step instructions
- **Configuration Reference**: All available options
- **Troubleshooting**: Common issues and solutions
- **Security**: Security considerations and best practices

## Submitting Changes

### Pull Request Process

1. **Update documentation** for any user-facing changes
2. **Add or update tests** for the changes
3. **Run the full test suite** and ensure it passes
4. **Update the changelog** if applicable
5. **Submit the pull request** with a clear description

### Pull Request Template

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] New tests added for changes
- [ ] Manual testing performed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new security vulnerabilities introduced

## Related Issues
Fixes #(issue number)
```

### Review Process

1. **Automated checks**: CI/CD pipeline runs tests and security scans
2. **Code review**: Maintainers review code quality, security, and design
3. **Documentation review**: Ensure documentation is clear and complete
4. **Security review**: For changes affecting authentication or infrastructure
5. **Approval and merge**: After successful review and approval

### Merge Requirements

- [ ] All CI checks pass
- [ ] At least one maintainer approval
- [ ] No unresolved review comments
- [ ] Documentation updated
- [ ] Security review completed (if applicable)

## Community

### Communication Channels

- **GitHub Issues**: Bug reports, feature requests, and discussions
- **GitHub Discussions**: General questions and community discussions
- **Security Email**: [security@qred.com](mailto:security@qred.com) for security issues
- **Maintainer Email**: [maintainers@qred.com](mailto:maintainers@qred.com) for project governance

### Getting Help

- **Documentation**: Check existing documentation first
- **Issues**: Search existing issues for similar problems
- **Discussions**: Ask questions in GitHub Discussions
- **Code examples**: Look at existing code for patterns

### Recognition

We appreciate all contributions and recognize contributors in:
- Release notes for significant contributions
- Contributors section in README
- GitHub contributor statistics
- Special recognition for security discoveries

## License

By contributing to this project, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

---

Thank you for contributing to MCP Proxy! Your help makes this project better for everyone.
