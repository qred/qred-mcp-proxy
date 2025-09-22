# MCP OAuth 2.1 Sidecar Service

An OAuth 2.1 sidecar service for MCP (Model Context Protocol) servers with client-specific routing and Dynamic Client Registration support.

## Features

- **Client-Specific Routing**: Automatically detects client type and provides optimized OAuth endpoints
- **OAuth 2.1 Discovery**: RFC 8414 compliant authorization server metadata discovery
- **Dynamic Client Registration**: RFC 7591 compliant automatic client credential provisioning
- **OAuth Proxy**: Fixes common OAuth implementation issues in MCP clients
- **Google Workspace Integration**: Enterprise-grade authentication with workspace validation
- **Callback Forwarding**: Handles localhost callbacks for Claude Code and desktop clients
- **Token Management**: Ensures refresh tokens are properly issued and managed

## Architecture

This service acts as an intelligent OAuth sidecar that:

1. **Detects Client Type** based on User-Agent headers and DCR client names
2. **Routes Endpoints** - Claude Code gets proxy endpoints, others get direct Google OAuth
3. **Handles DCR requests** from MCP clients (Claude Code, VS Code, etc.)
4. **Proxies authorization requests** to fix missing scopes and parameters (Claude Code only)
5. **Forwards OAuth callbacks** using browser redirects for localhost clients
6. **Proxies token exchange** to inject missing client credentials (Claude Code only)
7. **Fixes response formatting** to ensure client compatibility

### Client-Specific Behavior

#### Claude Code Clients
- **Detection**: User-Agent contains `"Claude Code"` and client identification patterns
- **Endpoints**: Proxy endpoints (`/oauth/auth`, `/oauth/token`)
- **Behavior**: Full OAuth proxy with localhost callback forwarding
- **Reason**: Claude Code has OAuth implementation issues requiring proxy intervention

#### Standard MCP Clients
- **Detection**: All other clients (VS Code, Claude Web/Desktop, etc.)
- **Endpoints**: Direct Google OAuth endpoints
- **Behavior**: Direct communication with Google OAuth for optimal performance
- **Reason**: These clients have proper OAuth implementations

## Environment Variables

- `GOOGLE_OAUTH`: JSON string containing Google OAuth client credentials
- `PORT`: Service port (default: 8080)
- `HOST`: Service host (default: 0.0.0.0)

## Usage

### Docker

```bash
docker build -t mcp-oauth .
docker run -p 8080:8080 -e GOOGLE_OAUTH='{"web":{"client_id":"...","client_secret":"..."}}' mcp-oauth
```

With custom settings:
```bash
docker run -p 9090:9090 -e GOOGLE_OAUTH='{"web":{"client_id":"...","client_secret":"..."}}' mcp-oauth --port 9090 --host 0.0.0.0 --debug
```

### Local Development

```bash
uv sync
export GOOGLE_OAUTH='{"web":{"client_id":"...","client_secret":"..."}}'
uv run mcp-oauth --debug
```

### Command Line Options

```bash
uv run mcp-oauth --help
uv run mcp-oauth --port 8080 --host 0.0.0.0
uv run mcp-oauth --debug
uv run mcp-oauth --log-level debug
```

## Endpoints

### Discovery Endpoints
- `/.well-known/oauth-authorization-server` - OAuth discovery metadata (client-specific)
- `/.well-known/oauth-protected-resource` - Protected resource metadata

### OAuth Endpoints  
- `/oauth/register` - Dynamic Client Registration (POST)
- `/oauth/auth` - Authorization endpoint proxy (Claude Code only)
- `/oauth/token` - Token endpoint proxy (Claude Code only)
- `/oauth/auth_callback` - OAuth callback handler (Claude Code only)
- `/oauth/client-config` - Configuration help and documentation

### Utility Endpoints
- `/health` - Health check endpoint (for loadbalancer health)
- `/validate` - Token validation endpoint (for MCP proxy)

## Client Configuration

MCP clients should use OAuth discovery to automatically find endpoints. The OAuth sidecar provides client-specific endpoints based on automatic detection:

### For Claude Code
```json
{
  "server_url": "http://your-mcp-server/mcp",
  "oauth_discovery": true,
  "oauth_issuer": "https://accounts.google.com"
}
```
Will receive proxy endpoints for localhost callback handling.

### For VS Code/Claude Web/Desktop
```json
{
  "server_url": "http://your-mcp-server/mcp", 
  "oauth_discovery": true,
  "oauth_issuer": "https://accounts.google.com"
}
```
Will receive direct Google OAuth endpoints for optimal performance.

The OAuth service will be discovered at: `http://your-oauth-service:8080`

## Documentation

- **[Client-Specific OAuth Routing](../../docs-assets/Client-Specific-OAuth-Routing.md)**: Detailed routing implementation
- **[OAuth 2.1 DCR Implementation](../../docs-assets/OAuth-2.1-DCR-Implementation.md)**: Dynamic Client Registration details
- **[OAuth 2.1 Discovery Setup](../../docs-assets/OAuth-2.1-Discovery-Setup.md)**: Complete setup guide
