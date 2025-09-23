# MCP Proxy Test Suite

This directory contains comprehensive tests for the MCP Proxy project, including OAuth server endpoints, configuration loading, and CDK infrastructure synthesis.

## Test Structure

```
tests/
├── conftest.py              # Shared test fixtures and configuration
├── oauth/                   # OAuth server tests
│   ├── test_oauth_endpoints.py    # FastAPI endpoint tests
│   └── test_token_validation.py   # Token validation tests
├── config/                  # Configuration and lifecycle tests
│   ├── test_config_loading.py     # Config file parsing tests
│   └── test_lifecycle.py          # Application startup/shutdown tests
└── cdk/                     # CDK infrastructure tests
    └── test_cdk_synthesis.py      # CDK stack synthesis tests
```

## Running Tests

### Prerequisites

Install test dependencies:

```bash
# Using uv (recommended)
uv sync --group test

# Or using pip
pip install -e ".[test]"
```

### Running All Tests

```bash
# Using the test runner script
python run_tests.py

# Or directly with pytest
pytest tests/ -v
```

### Running Specific Test Categories

```bash
# OAuth server tests only
python run_tests.py --oauth

# Configuration tests only
python run_tests.py --config

# CDK synthesis tests only
python run_tests.py --cdk

# Fast mode (fail on first error)
python run_tests.py --fast
```

### Running Individual Tests

```bash
# Run specific test file
pytest tests/oauth/test_oauth_endpoints.py -v

# Run specific test function
pytest tests/oauth/test_oauth_endpoints.py::TestOAuthEndpoints::test_health_endpoint -v

# Run tests matching a pattern
pytest -k "test_health" -v
```

## Test Categories

### OAuth Server Tests (`tests/oauth/`)

Tests for the FastAPI OAuth service including:

- **Endpoint Testing**: All OAuth endpoints (`/health`, `/oauth/register`, `/oauth/auth`, `/oauth/token`, `/validate`)
- **Error Handling**: Invalid parameters, missing credentials, malformed requests
- **Token Exchange**: Authorization code and refresh token flows
- **Dynamic Client Registration**: Valid and invalid registration requests
- **Callback Forwarding**: Session management and localhost callback handling

### Configuration Tests (`tests/config/`)

Tests for configuration loading and application lifecycle:

- **Config File Parsing**: Valid/invalid JSON, missing files, environment variables
- **OAuth Config Loading**: Google OAuth configuration validation
- **MCP Server Config**: Server configuration parsing and group extraction
- **Application Lifecycle**: Startup, shutdown, and refresh system management
- **Environment Variables**: Custom refresh intervals and config paths

### CDK Infrastructure Tests (`tests/cdk/`)

Tests for AWS CDK stack synthesis:

- **Basic Synthesis**: Verifies CDK app can generate CloudFormation templates
- **Stack Variants**: Tests with different feature flags (KMS, persistent stack)
- **Configuration Validation**: Tests with valid and invalid configurations
- **Resource Validation**: Ensures expected AWS resources are included

## Test Configuration

### Environment Variables

Tests use the following environment variables:

- `GOOGLE_OAUTH`: Mock OAuth configuration (automatically set by tests)
- `MCP_SERVERS_CONFIG_PATH`: Path to MCP servers config file (automatically set)
- `MCP_OAUTH_REFRESH_GROUPS_INTERVAL`: Groups refresh interval in minutes
- `MCP_OAUTH_REFRESH_USERS_INTERVAL`: Users refresh interval in minutes

### Mocking Strategy

Tests extensively mock external dependencies:

- **Google OAuth API**: Mocked to avoid real authentication calls
- **Google Workspace Integration**: Mocked WIF configuration and group validation
- **File System**: Temporary files for configuration testing
- **Network Requests**: httpx client mocked for token exchange tests

### Fixtures

Common test fixtures in `conftest.py`:

- `mock_oauth_config`: Sample OAuth configuration
- `mock_mcp_servers_config`: Sample MCP servers configuration
- `mock_env_vars`: Environment variables for testing
- `mock_google_wif`: Mocked Google Workspace integration

## Coverage

Tests aim for high coverage of critical paths:

- OAuth flow error handling and edge cases
- Configuration parsing and validation
- Application startup and shutdown scenarios
- CDK synthesis with various configurations

Run with coverage reporting:

```bash
pytest --cov=mcp_oauth --cov-report=html tests/
```

## CI/CD Integration

Tests are designed to run in CI environments:

- No external network dependencies (everything mocked)
- Configurable timeouts for CDK synthesis tests
- Skip CDK tests if Node.js dependencies not installed
- Clear error messages for debugging failures

## Contributing

When adding new tests:

1. Use descriptive test names that explain the scenario
2. Mock external dependencies to ensure test isolation
3. Include both success and failure scenarios
4. Add docstrings explaining complex test logic
5. Use appropriate fixtures to reduce code duplication

## Troubleshooting

### Common Issues

**CDK Tests Skipped**: Install Node.js dependencies in `cdk/mcp-proxy/`:
```bash
cd cdk/mcp-proxy && npm install
```

**Import Errors**: Ensure test dependencies are installed:
```bash
uv sync --group test
```

**Environment Issues**: Use the test runner script which sets up the environment:
```bash
python run_tests.py
```

### Debug Mode

Run tests with extra debugging:

```bash
pytest tests/ -v -s --tb=long --log-cli-level=DEBUG
```
