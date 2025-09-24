# MCP OAuth 2.1 Sidecar Service

An OAuth 2.1 sidecar service for MCP (Model Context Protocol) servers with unified authentication flow and Dynamic Client Registration support.

## Features

- **Dynamic Client Registration**: RFC 7591 compliant automatic client credential provisioning
- **OAuth 2.1 Discovery**: RFC 8414 compliant authorization server metadata discovery
- **Unified Authentication Flow**: All MCP clients follow the same OAuth flow
- **OAuth Proxy**: Fixes common OAuth implementation issues in MCP clients
- **Google Workspace Integration**: Enterprise-grade authentication with workspace validation
- **Callback Forwarding**: Handles localhost callbacks for desktop and CLI clients
- **Token Management**: Ensures refresh tokens are properly issued and managed

## Architecture

This service acts as an intelligent OAuth sidecar that:

1. **Provides Dynamic Client Registration** for all MCP clients automatically
2. **Unified OAuth Endpoints** - All clients use the same authentication flow
3. **Handles DCR requests** from MCP clients (Claude Code, VS Code, etc.)
4. **Processes authorization requests** with proper scopes and parameters
5. **Forwards OAuth callbacks** using browser redirects for localhost clients
6. **Manages token exchange** with client credentials from DCR
7. **Ensures response compatibility** for all client types

### Authentication Flow

All MCP clients follow the same unified authentication flow:

1. **Client Registration**: Automatic DCR provides OAuth credentials
2. **Authorization**: Standard OAuth 2.0/OpenID Connect flow with Google
3. **Token Exchange**: Secure token handling with proper validation
4. **Callback Handling**: Browser redirects for localhost-based clients

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

MCP clients should use OAuth discovery to automatically find endpoints. The OAuth sidecar provides unified endpoints for all client types:

### For All MCP Clients
```json
{
  "server_url": "http://your-mcp-server/mcp",
  "oauth_discovery": true,
  "oauth_issuer": "https://accounts.google.com"
}
```

All clients receive the same OAuth endpoints and follow the unified authentication flow with automatic Dynamic Client Registration.

The OAuth service will be discovered at: `http://your-oauth-service:8080`

## Documentation

- **[OAuth 2.1 DCR Implementation](../../docs-assets/OAuth-2.1-DCR-Implementation.md)**: Dynamic Client Registration details
- **[OAuth 2.1 Discovery Setup](../../docs-assets/OAuth-2.1-Discovery-Setup.md)**: Complete setup guide
