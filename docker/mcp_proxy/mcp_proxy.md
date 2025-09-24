# MCP Proxy Container: Aggregated MCP Server with OAuth 2.1 Discovery

The `mcp_proxy` container provides an aggregated proxy server for the Model Context Protocol (MCP) with OAuth 2.1 discovery and Google Workspace authentication. It combines multiple backend MCP servers into a single unified interface, providing comprehensive activity logging and secure access control.

## Features

- **Aggregated MCP Server**: Combines multiple backend MCP servers into a single unified interface
- **OAuth 2.1 Discovery Support**: RFC 9728 and RFC 8414 compliant discovery endpoints for automatic client configuration
- **OAuth Bearer Token Authentication**: OAuth2 tokens validated against Google Workspace via userinfo endpoint
- **Structured Logging**: Dedicated authentication logs (`auth.log`) and application logs with user context
- **Clean URL Structure**: Supports both `/mcp` and `/mcp/` endpoints via middleware
- **Cached Token Validation**: 5-minute TTL cache to reduce authentication overhead
- **Tool Namespacing**: Backend tools are namespaced by their server name for isolation
- **User Parameter Injection**: Automatically injects authenticated user context to backend services
- **Cross-Account Authentication**: Support for AWS cross-account role assumption for backend services

## OAuth 2.1 Discovery Support

The MCP proxy implements **OAuth 2.1 discovery** following RFC 9728 (Protected Resource Metadata) and RFC 8414 (Authorization Server Metadata) standards. This enables MCP clients to automatically discover and configure OAuth authentication without manual setup.

### Discovery Endpoints

#### 1. Protected Resource Metadata (RFC 9728)
**Endpoint:** `/.well-known/oauth-protected-resource`

```json
{
  "resource": "https://your-mcp-proxy-domain.com/mcp",
  "authorization_servers": ["https://accounts.google.com"],
  "scopes_supported": ["openid", "email", "profile"],
  "bearer_methods_supported": ["header"]
}
```

#### 2. Authorization Server Metadata (RFC 8414)
**Endpoint:** `/.well-known/oauth-authorization-server`

**Dynamic Response:** Fetches and caches Google's live OpenID configuration from `https://accounts.google.com/.well-known/openid-configuration` (1-hour cache).

#### 3. Client Configuration Help
**Endpoint:** `/oauth/client-config`

Provides comprehensive setup guidance for OAuth discovery-enabled MCP clients without exposing any secrets.

### Client Configuration

#### Discovery-Enabled Configuration (Recommended)
```json
{
  "mcp-proxy": {
    "url": "https://your-mcp-proxy-domain.com/mcp",
    "type": "http"
  }
}
```

**What Happens:**
1. Client discovers OAuth endpoints automatically from well-known URLs
2. Client redirects user to Google's authentication page for login
3. Client performs standard OAuth 2.0/OpenID Connect flow
4. Client uses Bearer token for all MCP requests

### OAuth Error Handling

The server provides RFC 6750 compliant error responses:

#### Missing Bearer Token
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="MCP Server"
Content-Type: application/json

{
  "error": "unauthorized",
  "error_description": "OAuth Bearer token required for MCP access",
  "oauth_discovery": {
    "protected_resource_metadata": "https://your-mcp-proxy-domain.com/.well-known/oauth-protected-resource",
    "authorization_server_metadata": "https://your-mcp-proxy-domain.com/.well-known/oauth-authorization-server"
  }
}
```

#### Invalid/Expired Token
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="MCP Server", error="invalid_token", error_description="Token validation failed"
Content-Type: application/json

{
  "error": "unauthorized",
  "error_description": "OAuth Bearer token is invalid or user not in Google Workspace"
}
```

## MCP Server Architecture
The proxy server aggregates tools, resources, and prompts from configured backend servers:
- **Tool Calls**: Routed to appropriate backends with comprehensive logging
- **Resource Access**: Namespaced URIs for backend resource isolation
- **Prompt Management**: Unified prompt interface across backends
- **Authentication**: OAuth2 Bearer token validation with Google Workspace membership verification
- **Discovery**: RFC-compliant OAuth 2.1 discovery endpoints for automatic client configuration

## Configuration

### Backend Servers
Backend MCP servers are configured in `servers.json`. Example:
```json
{
  "fetch": {
    "command": "uvx",
    "args": ["mcp-server-fetch"]
  },
  "example-server": {
    "command": "npx",
    "args": ["-y", "your-mcp-server"]
  }
}
```

### Tool Filtering
The proxy supports filtering/excluding tools from being exposed to agents. This is useful for:
- **Security**: Hide sensitive operations like delete, update, or administrative functions
- **Licensing/Usability**: Reduce clutter by hiding tools that aren't relevant for certain use cases
- **Access Control**: Different deployment configurations can expose different tool sets

Add an `excluded_tools` array to any server configuration:
```json
{
  "your-server": {
    "command": "npx",
    "args": ["-y", "your-mcp-server"],
    "transportType": "stdio",
    "excluded_tools": [
      "sensitive_operation",
      "admin_function",
      "*delete*",
      "update_*"
    ]
  }
}
```

**Pattern Matching:**
- **Exact Match**: `"sensitive_tool"` - excludes exactly "sensitive_tool"
- **Prefix Wildcard**: `"update_*"` - excludes any tool starting with "update_"
- **Suffix Wildcard**: `"*delete"` - excludes any tool ending with "delete"
- **Substring Wildcard**: `"*admin*"` - excludes any tool containing "admin"

Excluded tools won't appear in `list_tools` responses and attempts to call them will return errors.

### Google OAuth & WIF Setup
The container requires the following AWS-sourced environment variables:
- Google service account configuration for Workload Identity Federation
- Service Account email for Google API access
- OAuth client configuration for token validation

## Local Development

### Requirements
- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (recommended for dependency management)
- Docker (for containerized workflows)
- AWS credentials (for Google WIF configuration)

### Setting up Local Environment

From the `docker/mcp_proxy/` directory:

```zsh
# Create and activate a virtual environment
uv venv
source .venv/bin/activate

# Install dependencies
uv pip install -e .

# or run sync (will take care of venv + installs)
uv sync
```

Run the server locally:
```zsh
uv run python -m mcp_proxy
```

The aggregated server will be available at `http://localhost:8000/mcp`

## Helper Scripts for Docker Build & Deploy

The `docker/mcp_proxy/` directory includes helper scripts to streamline building and deploying Docker containers:

- **build-and-deploy.sh**: Builds the Docker image and (optionally) pushes it to ECR

### Build and Deploy to ECR

While testing you can build the container locally (and deploy to ecr if needed)
From the `docker/mcp_proxy/` directory:
```zsh
./build-and-deploy.sh [--deploy]
```
This script will:
- Build the Docker image for the MCP Proxy
- Tag the image with the current git commit hash
- Optionally push the image to AWS ECR (with `--deploy` flag)

### Local Testing
```zsh
./run-local-docker.sh [--debug]
```
- Runs the container locally on port 8000
- Use `--debug` flag for interactive debugging

### Requirements
- AWS authentication (via `aws sso login` or equivalent)
- Docker installed and running
- Proper AWS ECR permissions

## Usage

### Production Deployment
After deployment to ECR, the image can be used in ECS task definitions:
```
<account-id>.dkr.ecr.<region>.amazonaws.com/mcp-proxy:sha-<git-commit-hash>
```

#### OAuth Discovery Integration (Recommended)
Configure VS Code to use OAuth 2.1 discovery for automatic authentication setup:
```json
{
  "servers": {
    "mcp-proxy": {
      "url": "https://your-mcp-proxy-domain.com/mcp",
      "type": "http"
    }
  }
}
```

### Activity Monitoring
The system provides structured logging with dedicated log streams for different concerns:

#### Authentication Logs (`auth.log`)
All OAuth and authentication activities are logged separately:
- OAuth token validation (success/failure)
- User authentication and session establishment
- Google Workspace membership verification
- Authentication cache operations
- Client ID validation and OAuth discovery

#### Application Logs (stdout)
General server operations and user activities:
- Server startup and configuration
- MCP tool calls and resource access
- Backend server health and connectivity
- General request routing and processing

```

#### Log Volume Structure
```
/app/
├── auth/           # Authentication logs (read/write by proxy)
├── keepalive/      # Backend health logs (read/write by proxy)
└── backend/        # Backend-specific data and logs (configurable)

/logs/              # Log monitor container read-only access
├── auth/           # Authentication log monitoring
├── keepalive/      # Keep-alive log monitoring
└── backend/        # Backend log monitoring
```

## Testing OAuth 2.1 Discovery

### Discovery Endpoints Testing
Test the OAuth discovery implementation:

```bash
# Test Protected Resource Metadata
curl -H "Accept: application/json" \
     https://your-mcp-proxy-domain.com/.well-known/oauth-protected-resource

# Test Authorization Server Metadata
curl -H "Accept: application/json" \
     https://your-mcp-proxy-domain.com/.well-known/oauth-authorization-server

# Test Client Configuration Help
curl -H "Accept: application/json" \
     https://your-mcp-proxy-domain.com/oauth/client-config
```

### Expected Responses
- **Protected Resource**: Resource URI, authorization servers, supported scopes
- **Authorization Server**: Google's live OpenID configuration (cached for 1 hour)
- **Client Config**: Comprehensive setup instructions and examples

### Troubleshooting OAuth Issues

For detailed authentication troubleshooting, including example logs for both successful and failed OAuth flows, see:

**[OAuth 2.1 Discovery Setup Guide - Troubleshooting Section](../../docs-assets/OAuth-2.1-Discovery-Setup.md#troubleshooting)**

Common OAuth issues:
1. **Discovery endpoint not found (404):**
   - Ensure server is running and discovery routes are configured
   - Check load balancer routing for `/.well-known/*` paths

2. **Client connection fails:**
   - Verify OAuth client configuration in Google Cloud Console
   - Check authorized redirect URIs match client settings
   - Ensure user belongs to your Google Workspace domain

3. **Token validation fails:**
   - Confirm OAuth scopes include `openid`, `email`, `profile`
   - Verify Google Workspace membership
   - Check token hasn't expired

## Troubleshooting

### Authentication Issues
- **OAuth Token**: Ensure you have valid Google OAuth credentials via helper script
- **Token Validation**: Verify the OAuth token can access Google's userinfo endpoint
- **Workspace Membership**: Check user belongs to the configured Google Workspace domain
- **Token Expiration**: OAuth tokens expire and may need refresh
- Review Google WIF configuration and AWS credentials

### Backend Connectivity
- Ensure all backend servers in `servers.json` are properly configured
- Check server logs for backend initialization errors
- Verify backend server dependencies and environments

### URL Path Issues
The middleware automatically handles both `/mcp` and `/mcp/` paths - no manual redirect configuration needed.

## Development Notes

- **Stateless Design**: Each request is independently authenticated and routed
- **User Context**: Thread-local user context enables comprehensive logging across the request lifecycle
- **Caching Strategy**: OAuth token validation cached for 5 minutes to reduce authentication overhead
- **Error Handling**: Comprehensive error logging with user context for debugging

## See Also
- Root `README.md` for project overview and CDK deployment
- Backend-specific documentation for your configured MCP servers
- MCP protocol documentation for client integration details
