"""FastAPI server for MCP OAuth service."""

import asyncio
import json
import os
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.middleware.cors import CORSMiddleware

# OAuth validation functionality (extracted from main MCP server)
from .token_validation import validate_oauth_token
from .utils.logger import logger

# Configuration for HTTPS enforcement
# Domains that should force HTTPS when behind load balancer
FORCE_HTTPS_DOMAINS = os.getenv("FORCE_HTTPS_DOMAINS", "").split(",")

# OAuth callback forwarding for Claude Code localhost callbacks
# Format: {session_id: (localhost_callback_url, timestamp)}
_callback_forwarding: dict[str, tuple[str, float]] = {}
_callback_forwarding_ttl = 900  # 15 minutes TTL for callback sessions


def get_request_scheme(request: Request) -> str:
    """
    Determine the appropriate scheme for the request.

    For production deployment behind load balancer, detect HTTPS context
    based on configured domains.
    """
    # Use proper hostname validation instead of substring check

    parsed_url = urlparse(str(request.url))
    hostname = parsed_url.hostname

    if not hostname:
        return str(request.url.scheme)

    # Check if any configured domains should force HTTPS
    should_force_https = any(
        domain.strip() and hostname.endswith(domain.strip())
        for domain in FORCE_HTTPS_DOMAINS
        if domain.strip()
    )
    return "https" if should_force_https else str(request.url.scheme)


def is_production_domain(request: Request) -> bool:
    """
    Check if the request is from a production domain that should use HTTPS.

    Uses proper hostname validation instead of substring checks.
    """

    parsed_url = urlparse(str(request.url))
    hostname = parsed_url.hostname

    if not hostname:
        return False

    return any(
        domain.strip() and hostname.endswith(domain.strip())
        for domain in FORCE_HTTPS_DOMAINS
        if domain.strip()
    )


# DCR (Dynamic Client Registration) global variables - initialized during OAuth config loading
dcr_client_id: str | None = None
dcr_client_secret: str | None = None
valid_mcp_callbacks: list[str] | None = None

# OAuth configuration - initialized during startup
_oauth_info: dict[str, Any] = {}

# MCP server configuration - initialized during startup
_mcp_servers_config: dict[str, Any] = {}
_required_groups: set[str] = set()

# Scheduled refresh system
_refresh_task: asyncio.Task | None = None
_refresh_groups_interval_minutes: int = 15  # Default groups refresh interval
_refresh_users_interval_minutes: int = 60  # Default users refresh interval


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Handle application startup and shutdown events."""
    # Startup
    logger.info("Application startup - initializing MCP servers config...")
    await initialize_mcp_servers_config_async()

    yield

    # Shutdown
    logger.info("Application shutdown requested...")
    stop_scheduled_refresh()
    logger.info("Application shutdown completed")


# FastAPI app
app = FastAPI(
    title="MCP OAuth Service",
    description="OAuth 2.1 service for MCP servers with Dynamic Client Registration support",
    version="0.1.0",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, be more restrictive
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def initialize_oauth_config() -> None:
    """Initialize OAuth configuration from environment variables."""
    global dcr_client_id, dcr_client_secret, valid_mcp_callbacks, _oauth_info

    # Parse the Google OAuth configuration from environment variable
    try:
        oauth_secret_json = os.getenv("GOOGLE_OAUTH", "")
        if not oauth_secret_json.strip():
            raise ValueError("GOOGLE_OAUTH environment variable is empty or not set")

        _oauth_info = json.loads(oauth_secret_json)

        if not _oauth_info:
            raise ValueError("Parsed JSON from GOOGLE_OAUTH is empty")

        # Validate OAuth config structure
        client_id = _oauth_info.get("web", {}).get("client_id")
        if not client_id:
            logger.warning(
                "No client_id found in OAuth config - client ID validation will be disabled"
            )
        elif not client_id.endswith(".googleusercontent.com"):
            logger.warning(
                "OAuth client_id does not appear to be a valid Google client ID: %s",
                client_id,
            )

        # Check DCR credentials for Claude Dynamic Client Registration
        dcr_client_id = _oauth_info.get("web", {}).get("client_id")
        dcr_client_secret = _oauth_info.get("web", {}).get("client_secret")

        if dcr_client_id and dcr_client_secret:
            # Basic validation of client_id format
            if dcr_client_id.endswith(".googleusercontent.com"):
                logger.info(
                    f"DCR credentials loaded successfully for client: {dcr_client_id}"
                )
            else:
                logger.warning(
                    f"DCR client_id does not appear to be a valid Google client ID: {dcr_client_id}"
                )

            # Validate client_secret length (Google client secrets are typically 24 chars)
            if len(dcr_client_secret) < 20:
                logger.warning(
                    "DCR client_secret appears to be too short - may be invalid"
                )

            logger.info("Dynamic Client Registration (DCR) credentials: AVAILABLE")
        else:
            logger.warning(
                "DCR credentials not found - Dynamic Client Registration will fail"
            )

        # Extract valid MCP callback URIs from OAuth config (fallback to hardcoded list)
        valid_mcp_callbacks = _oauth_info.get("web", {}).get("redirect_uris")

        logger.info(
            f"Successfully loaded Google OAuth configuration for client: {client_id or 'unknown'}"
        )

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse GOOGLE_OAUTH as JSON: {e}")
        raise ValueError(
            f"Invalid JSON in GOOGLE_OAUTH environment variable: {e}"
        ) from e
    except ValueError as e:
        logger.error(f"Google OAuth configuration error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error loading Google OAuth configuration: {e}")
        raise


def get_oauth_client_id() -> str | None:
    """Get the configured OAuth client ID."""
    client_id = _oauth_info.get("web", {}).get("client_id")
    return str(client_id) if client_id is not None else None


def initialize_mcp_servers_config() -> None:
    """Initialize MCP servers configuration (synchronous version for CLI)."""
    global \
        _mcp_servers_config, \
        _required_groups, \
        _refresh_groups_interval_minutes, \
        _refresh_users_interval_minutes

    # Get refresh intervals from environment
    _refresh_groups_interval_minutes = int(
        os.getenv("MCP_OAUTH_REFRESH_GROUPS_INTERVAL", "15")
    )
    _refresh_users_interval_minutes = int(
        os.getenv("MCP_OAUTH_REFRESH_USERS_INTERVAL", "60")
    )

    # Get MCP servers config path from environment
    config_path = os.getenv("MCP_SERVERS_CONFIG_PATH")
    if not config_path:
        logger.info("MCP_SERVERS_CONFIG_PATH not set - skipping group/user management")
        return

    try:
        # Load MCP servers configuration
        with Path(config_path).open() as f:
            _mcp_servers_config = json.load(f)

        # Extract all required groups from server configurations
        mcp_servers = _mcp_servers_config.get("mcpServers", {})
        groups_found = set()

        for server_name, server_config in mcp_servers.items():
            required_groups = server_config.get("required_groups", [])
            if required_groups:
                groups_found.update(required_groups)
                logger.debug(
                    f"Server '{server_name}' requires groups: {required_groups}"
                )

        _required_groups = groups_found

        if _required_groups:
            logger.info(f"Loaded MCP servers config from {config_path}")
            logger.info(
                f"Found {len(mcp_servers)} servers with {len(_required_groups)} unique required groups: {sorted(_required_groups)}"
            )
            logger.info(
                f"Scheduled refresh system will start on app startup (groups: {_refresh_groups_interval_minutes}min, users: {_refresh_users_interval_minutes}min)"
            )
        else:
            logger.info(
                f"Loaded MCP servers config from {config_path} - no group requirements found"
            )

    except FileNotFoundError:
        logger.warning(f"MCP servers config file not found: {config_path}")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse MCP servers config as JSON: {e}")
    except Exception as e:
        logger.error(f"Unexpected error loading MCP servers config: {e}")


async def initialize_mcp_servers_config_async() -> None:
    """Initialize MCP servers configuration and start scheduled refresh (async version for FastAPI lifespan)."""
    global _refresh_task

    # First do the synchronous initialization
    initialize_mcp_servers_config()

    # Then start the scheduled refresh if we have groups
    if _required_groups:
        try:
            # Start the scheduled refresh system
            _refresh_task = asyncio.create_task(_start_scheduled_refresh())
            logger.info(
                f"Started scheduled refresh system (groups: {_refresh_groups_interval_minutes}min, users: {_refresh_users_interval_minutes}min)"
            )
        except Exception as e:
            logger.error(f"Failed to start scheduled refresh system: {e}")


async def _start_scheduled_refresh() -> None:
    """Start the scheduled refresh system for groups and users with independent intervals."""
    if not _required_groups:
        return

    try:
        # Import Google WIF for group operations
        from .gcp.google_wif import google_wif_config

        logger.info("Starting scheduled group and user refresh system...")

        # Initial load
        await _refresh_groups_and_users(google_wif_config, is_initial=True)

        # Start independent refresh tasks for groups and users
        async def groups_refresh_loop() -> None:
            """Independent refresh loop for groups."""
            while True:
                try:
                    await asyncio.sleep(_refresh_groups_interval_minutes * 60)
                    logger.info(
                        "⏰ Groups refresh interval reached (%d minutes)",
                        _refresh_groups_interval_minutes,
                    )
                    await _refresh_groups_and_users(
                        google_wif_config,
                        is_initial=False,
                        refresh_groups=True,
                        refresh_users=False,
                    )
                except asyncio.CancelledError:
                    logger.info("Groups refresh loop cancelled")
                    raise
                except Exception as e:
                    logger.error("Error in groups refresh loop: %s", e)
                    # Continue the loop after error

        async def users_refresh_loop() -> None:
            """Independent refresh loop for users."""
            while True:
                try:
                    await asyncio.sleep(_refresh_users_interval_minutes * 60)
                    logger.info(
                        "⏰ Users refresh interval reached (%d minutes)",
                        _refresh_users_interval_minutes,
                    )
                    await _refresh_groups_and_users(
                        google_wif_config,
                        is_initial=False,
                        refresh_groups=False,
                        refresh_users=True,
                    )
                except asyncio.CancelledError:
                    logger.info("Users refresh loop cancelled")
                    raise
                except Exception as e:
                    logger.error("Error in users refresh loop: %s", e)
                    # Continue the loop after error

        # Start both refresh loops concurrently
        await asyncio.gather(
            groups_refresh_loop(), users_refresh_loop(), return_exceptions=True
        )

    except ImportError as e:
        logger.error(f"Failed to import Google WIF module: {e}")
    except asyncio.CancelledError:
        logger.info("Scheduled refresh system stopped")
        raise
    except Exception as e:
        logger.error(f"Unexpected error in scheduled refresh system: {e}")
        # Continue the loop to keep trying


async def _refresh_groups_and_users(
    google_wif_config: Any,
    is_initial: bool = False,
    refresh_groups: bool = True,
    refresh_users: bool = True,
) -> None:
    """Refresh group memberships and user data."""
    refresh_type = "Initial" if is_initial else "Scheduled"
    actions = []
    if refresh_groups:
        actions.append("groups")
    if refresh_users:
        actions.append("users")

    if not actions:
        logger.debug("No refresh actions requested")
        return

    # More detailed logging about what we're refreshing
    action_str = "/".join(actions)
    if is_initial:
        logger.info(f"🚀 {refresh_type} refresh starting for {action_str}...")
    else:
        logger.info(f"🔄 {refresh_type} refresh starting for {action_str}...")

    start_time = time.time()
    success_count = 0
    error_count = 0

    try:
        if refresh_groups and _required_groups:
            logger.info(
                f"🔄 REFRESH: Attempting to refresh {len(_required_groups)} groups: {sorted(_required_groups)}"
            )
            # Method 1: Try to use the internal group loading method for efficiency
            try:
                # Access the internal method to load all groups at once
                group_list = list(_required_groups)
                logger.debug(
                    f"🔄 REFRESH: Calling internal method with groups: {group_list}"
                )
                # Call the refresh method that loads all group members with force refresh
                if hasattr(google_wif_config, "refresh_groups"):
                    await google_wif_config.refresh_groups(group_list)
                    success_count = len(group_list)
                    logger.info(
                        f"✅ REFRESH: Successfully refreshed {success_count} groups using refresh method"
                    )
                elif hasattr(google_wif_config, "_GoogleWIF__get_group_members"):
                    await google_wif_config._GoogleWIF__get_group_members(
                        group_list, force_refresh=True
                    )
                    success_count = len(group_list)
                    logger.info(
                        f"✅ REFRESH: Successfully bulk-refreshed {success_count} groups using internal method"
                    )
                else:
                    raise AttributeError("Internal method not available")

            except Exception as bulk_error:
                logger.warning(
                    f"❌ REFRESH: Bulk refresh failed, falling back to individual group refresh: {bulk_error}"
                )

                # Method 2: Fallback to individual group refreshes
                for group_name in _required_groups:
                    try:
                        # Force refresh by clearing data for this group and then loading it
                        logger.debug(
                            f"🔄 REFRESH: Clearing data and refreshing group: {group_name}"
                        )
                        google_wif_config.clear_group_data([group_name])

                        # Trigger group data loading by checking a dummy user
                        # This will populate the lookup with fresh data
                        dummy_email = "cache-loader@example.com"
                        await google_wif_config.check_user_groups(
                            dummy_email, [group_name]
                        )

                        success_count += 1
                        logger.debug(f"✅ REFRESH: Refreshed group '{group_name}'")

                    except Exception as group_error:
                        error_count += 1
                        logger.warning(
                            f"❌ REFRESH: Failed to refresh group '{group_name}': {group_error}"
                        )

        # User refresh logic - refresh the user cache to keep workspace user data current
        if refresh_users:
            logger.info(
                "🔄 REFRESH: Attempting to refresh user cache for default org unit"
            )
            try:
                # Call the Google WIF user refresh method
                # This will refresh the google_users cache with current workspace users
                google_wif_config.refresh_users()  # Uses default org unit path from config
                logger.info("✅ REFRESH: Successfully refreshed user cache")
                # Users are refreshed as a whole org unit, so count as 1 successful operation
                success_count += 1
            except Exception as user_error:
                error_count += 1
                logger.warning(
                    f"❌ REFRESH: Failed to refresh user cache: {user_error}"
                )

        duration = time.time() - start_time

        # More detailed completion logging
        if is_initial:
            logger.info(
                f"🚀 {refresh_type} refresh completed in {duration:.2f}s: {success_count} items refreshed, {error_count} errors"
            )
        else:
            logger.info(
                f"✅ {refresh_type} {action_str} refresh completed in {duration:.2f}s: {success_count} items refreshed, {error_count} errors"
            )

        if error_count > 0:
            logger.warning(
                "Some refresh operations failed - validation may be slower for affected items"
            )

    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            f"❌ {refresh_type} {action_str} refresh failed after {duration:.2f}s: {e}"
        )


def stop_scheduled_refresh() -> None:
    """Stop the scheduled refresh system."""
    global _refresh_task
    if _refresh_task and not _refresh_task.done():
        _refresh_task.cancel()
        logger.info("Stopped scheduled refresh system")


def get_required_groups() -> set[str]:
    """Get the set of all required groups from MCP server configurations."""
    return _required_groups.copy()


# Route handlers
@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource(request: Request) -> JSONResponse:
    """Handle OAuth 2.0 Protected Resource Metadata (RFC 9728) discovery."""
    # For production deployment behind load balancer, always use HTTPS
    scheme = get_request_scheme(request)
    base_url = f"{scheme}://{request.url.netloc}"

    # Get the canonical URI for this MCP server
    resource_uri = f"{base_url}/mcp"

    metadata = {
        "resource": resource_uri,
        "authorization_servers": [
            base_url  # Point to our server so clients discover our registration endpoint
        ],
        "scopes_supported": ["openid", "email", "profile"],
        "bearer_methods_supported": ["header"],
    }

    return JSONResponse(
        metadata,
        headers={
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=3600",  # Cache for 1 hour
        },
    )


@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server(request: Request) -> JSONResponse:
    """Handle OAuth 2.0 Authorization Server Metadata (RFC 8414) discovery with client-specific routing."""
    # For production deployment behind load balancer, always use HTTPS
    scheme = get_request_scheme(request)
    base_url = f"{scheme}://{request.url.netloc}"

    # Log the User-Agent for debugging, but default to proxy endpoints for ambiguous clients
    user_agent = request.headers.get("user-agent", "")

    # For ambiguous user agents like "node", default to proxy endpoints since we can't reliably detect
    # the specific client type at discovery time. The DCR endpoint will make the final decision.
    is_ambiguous_client = user_agent in ["node", ""] or not user_agent.strip()

    logger.info(
        "OAuth discovery request from User-Agent: %s, ambiguous client: %s",
        user_agent[:100] + "..." if len(user_agent) > 100 else user_agent,
        is_ambiguous_client,
    )

    metadata = {
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": f"{base_url}/oauth/auth",  # Point to our proxy endpoint
        "token_endpoint": f"{base_url}/oauth/token",  # Point to our token proxy
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        # Dynamic Client Registration endpoint
        "registration_endpoint": f"{base_url}/oauth/register",
        "registration_endpoint_auth_methods_supported": ["none"],
        # Supported OAuth flows and methods
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["S256"],  # PKCE support
        # Additional metadata
        "service_documentation": f"{base_url}/oauth/client-config",
        "client_type": "proxy_default",  # Marker for debugging
    }

    logger.info("Returned proxy OAuth endpoints")

    return JSONResponse(
        metadata,
        headers={
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=3600",  # Cache for 1 hour
        },
    )


@app.get("/oauth/client-config")
async def client_config_help(request: Request) -> JSONResponse:
    """Handle client configuration help endpoint."""
    # For production deployment behind load balancer, detect HTTPS context
    scheme = get_request_scheme(request)
    base_url = f"{scheme}://{request.url.netloc}"

    help_content = {
        "title": "MCP OAuth 2.1 Discovery Configuration",
        "description": "This MCP OAuth service supports OAuth 2.1 discovery and Dynamic Client Registration with intelligent endpoint routing based on client needs.",
        "oauth_service_url": base_url,
        "client_detection": {
            "approach": "Two-stage detection: discovery provides defaults, DCR makes final decision",
            "discovery_behavior": "Ambiguous User-Agents get proxy endpoints, clear User-Agents get direct endpoints",
            "dcr_refinement": "DCR analyzes redirect URIs and client type to provide optimal endpoints",
        },
        "discovery_endpoints": {
            "protected_resource_metadata": f"{base_url}/.well-known/oauth-protected-resource",
            "authorization_server_metadata": f"{base_url}/.well-known/oauth-authorization-server",
        },
        "endpoint_routing": {
            "proxy_endpoints": {
                "authorization_endpoint": f"{base_url}/oauth/auth",
                "token_endpoint": f"{base_url}/oauth/token",
                "used_for": "Localhost callbacks, Claude Code clients, ambiguous User-Agents",
            },
            "direct_endpoints": {
                "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                "token_endpoint": "https://oauth2.googleapis.com/token",
                "used_for": "Standard callbacks (https), clear User-Agent clients",
            },
        },
        "dynamic_client_registration": {
            "endpoint": f"{base_url}/oauth/register",
            "method": "POST",
            "supported": True,
            "description": "RFC 7591 compliant client registration for MCP clients (uses pre-registered Google OAuth credentials)",
            "allowed_redirect_uris": [
                "https://claude.ai/api/mcp/auth_callback",
                "https://claude.com/api/mcp/auth_callback",
                "http://127.0.0.1:33418",
                "https://vscode.dev/redirect",
                f"{base_url}/oauth/auth_callback",  # Our proxy callback (dynamic)
            ],
            "localhost_callbacks_supported": "http://localhost:PORT/callback (ports 1024-65535) for Claude Desktop/Code",
        },
        "oauth_provider": {
            "issuer": "https://accounts.google.com",
            "type": "Google OAuth 2.0",
            "workspace_requirement": "Google Workspace membership required",
        },
        "setup_steps_dcr": [
            "1. MCP client performs Dynamic Client Registration POST to /oauth/register",
            "2. Include appropriate callback URI(s) for your client in redirect_uris array",
            "3. Receive client_id and client_secret in response",
            "4. Configure MCP client with OAuth discovery pointing to this service",
            "5. Client will automatically discover OAuth endpoints and authenticate",
            "6. DCR analyzes client needs and provides optimal endpoints (proxy for localhost, direct for standard callbacks)",
        ],
    }

    return JSONResponse(
        help_content,
        headers={
            "Content-Type": "application/json",
            "Cache-Control": "public, max-age=300",  # Cache for 5 minutes
        },
    )


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "service": "mcp-oauth", "version": "0.1.0"}


@app.get("/admin/refresh-status")
async def refresh_status() -> dict[str, Any]:
    """Get the status of the scheduled refresh system."""
    status = {
        "refresh_enabled": bool(_required_groups),
        "refresh_architecture": "independent_loops",  # Indicate the new architecture
        "refresh_groups_interval_minutes": _refresh_groups_interval_minutes,
        "refresh_users_interval_minutes": _refresh_users_interval_minutes,
        "required_groups": sorted(_required_groups) if _required_groups else [],
        "refresh_task_running": (
            _refresh_task is not None and not _refresh_task.done()
            if _refresh_task
            else False
        ),
        "total_groups": len(_required_groups),
        "description": "Groups and users refresh independently at their own intervals",
        "user_refresh_enabled": True,  # Now we actually refresh users
        "user_org_unit": os.getenv(
            "GOOGLE_ORG_UNIT_PATH", "/"
        ),  # The org unit we refresh users for
    }

    # Add task status if available
    if _refresh_task:
        status["refresh_task_status"] = (
            "running" if not _refresh_task.done() else "completed"
        )
        if _refresh_task.done() and _refresh_task.exception():
            status["refresh_task_error"] = str(_refresh_task.exception())

    return status


@app.post("/oauth/register")
async def dynamic_client_registration(request: Request) -> JSONResponse:
    """Handle OAuth 2.1 Dynamic Client Registration (RFC 7591)."""
    logger.info("Dynamic Client Registration request received")

    try:
        # Parse request body
        request_body = await request.json()
        logger.info("DCR request body: %s", request_body)

    except Exception as e:
        logger.warning("Failed to parse DCR request body: %s", e)
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "Request body must be valid JSON",
            },
        )

    # Validate redirect URIs
    redirect_uris = request_body.get("redirect_uris", [])
    if not redirect_uris or not isinstance(redirect_uris, list):
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_redirect_uri",
                "error_description": "redirect_uris must be a non-empty array",
            },
        )

    # Validate allowed callback URLs for MCP clients
    if not valid_mcp_callbacks:
        # For production deployment behind load balancer, detect HTTPS context
        scheme = get_request_scheme(request)
        base_url = f"{scheme}://{request.url.netloc}"

        # Fallback to hardcoded list if not loaded from OAuth config
        fallback_callbacks = {
            # Claude (cloud) callbacks
            "https://claude.ai/api/mcp/auth_callback",
            "https://claude.com/api/mcp/auth_callback",
            # VS Code callbacks
            "http://127.0.0.1:33418",
            # Our proxy callback for localhost forwarding (dynamically determined)
            f"{base_url}/oauth/auth_callback",
        }
        valid_mcp_callbacks_set = fallback_callbacks
    else:
        # Use callbacks from OAuth config
        valid_mcp_callbacks_set = set(valid_mcp_callbacks)

    # Handle Claude Code with dynamic localhost callbacks via forwarding
    client_name = request_body.get("client_name", "")
    user_agent = request.headers.get("user-agent", "")

    # Use both client_name (from request body) and user-agent (from headers) for detection
    logger.info(
        "DCR client detection - client_name: '%s', user_agent: '%s'",
        client_name,
        user_agent[:100] + "..." if len(user_agent) > 100 else user_agent,
    )

    valid_redirects = []

    # For production deployment behind load balancer, detect HTTPS context
    scheme = get_request_scheme(request)
    base_url = f"{scheme}://{request.url.netloc}"

    for uri in redirect_uris:
        if uri in valid_mcp_callbacks_set:
            valid_redirects.append(uri)
        # Special case: Accept localhost callbacks (we'll fix them in the auth proxy)
        elif uri.startswith("http://localhost:"):
            # Extract and validate port number
            try:
                port_part = uri.replace("http://localhost:", "").replace(
                    "/callback", ""
                )
                port = int(port_part)
                if 1024 <= port <= 65535:
                    # Accept the localhost URL - our auth proxy will handle the forwarding
                    valid_redirects.append(uri)
                    logger.info(
                        "Accepted Claude Code localhost callback: %s (will be proxied)",
                        uri,
                    )
                else:
                    logger.warning(
                        "Invalid redirect URI rejected (port out of range): %s", uri
                    )
            except ValueError:
                logger.warning("Invalid redirect URI rejected (invalid port): %s", uri)
        else:
            logger.warning("Invalid redirect URI rejected: %s", uri)

    if not valid_redirects:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_redirect_uri",
                "error_description": f"Only approved MCP client callback URLs are allowed: {', '.join(sorted(valid_mcp_callbacks_set))}",
            },
        )

    # Get pre-registered client credentials from global variables
    client_id = dcr_client_id
    client_secret = dcr_client_secret

    if not client_id or not client_secret:
        logger.error("DCR credentials not loaded - check OAuth configuration")
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_error",
                "error_description": "Dynamic Client Registration credentials not configured",
            },
        )

    # Current timestamp
    issued_at = int(datetime.now(UTC).timestamp())
    # Set expiration to 1 year from now (0 means no expiration per RFC 7591)
    expires_at = issued_at + (365 * 24 * 60 * 60)  # 1 year

    # Build response according to RFC 7591 Section 3.2.1
    registration_response = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": issued_at,
        "client_secret_expires_at": expires_at,
        # Return registered metadata (RFC 7591 requires this)
        "redirect_uris": valid_redirects,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "client_name": request_body.get("client_name", "MCP Client"),
        "scope": "openid email profile",
        # Additional metadata for client compatibility
        "application_type": "web",
        # Authorization server endpoints - conditional based on client needs
        "authorization_endpoint": f"{base_url}/oauth/auth",
        "token_endpoint": f"{base_url}/oauth/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "issuer": "https://accounts.google.com",
        # JWKS for token verification
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        # Additional OAuth metadata
        "scopes_supported": ["openid", "email", "profile"],
        "default_scopes": ["openid", "email", "profile"],
        "require_auth_time": False,
        "require_pushed_authorization_requests": False,
    }

    # For Claude Code, we need to tell it to use our proxy callback for token exchange
    proxy_callback = f"{base_url}/oauth/auth_callback"

    # Override the redirect_uris to point to our proxy callback
    registration_response["redirect_uris"] = [proxy_callback]
    registration_response["original_redirect_uri"] = valid_redirects[
        0
    ]  # Claude Code's localhost
    registration_response["preferred_redirect_uri"] = (
        proxy_callback  # Use our proxy for token exchange
    )

    logger.info(
        "Claude Code DCR: Configured for proxy-based OAuth flow with callback forwarding"
    )

    # Log successful registration with endpoint decision
    logger.info(
        "DCR successful - Client Type: %s, Endpoint Type: %s, Using Client ID: %s, Redirect URIs: %s",
        "Standard",
        "proxy",
        client_id[:20] + "..." if len(client_id) > 20 else client_id,
        valid_redirects,
    )

    return JSONResponse(
        status_code=201,  # RFC 7591 requires 201 Created
        content=registration_response,
        headers={
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )


@app.get("/oauth/auth")
async def oauth_authorization_proxy(request: Request) -> Response:
    """Proxy OAuth authorization requests, fixing client's broken parameters."""

    # Get all query parameters from client's authorization request
    params = dict(request.query_params)

    logger.info(
        "Authorization proxy request received with parameters: %s",
        {
            k: v if k not in ["client_id", "client_secret"] else "***"
            for k, v in params.items()
        },
    )

    # Required parameters for OAuth authorization
    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    state = params.get("state")

    if not client_id:
        logger.error("Authorization request missing client_id")
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "client_id is required",
            },
        )

    if not redirect_uri:
        logger.error("Authorization request missing redirect_uri")
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": "redirect_uri is required",
            },
        )

    # Build corrected parameters for Google OAuth
    corrected_params = {
        "response_type": "code",
        "client_id": client_id,
        "scope": "openid email profile",  # Add missing scopes!
        "state": state or "",
    }

    # For Claude Code localhost callbacks, use our proxy callback
    scheme = get_request_scheme(request)
    base_url = f"{scheme}://{request.url.netloc}"
    proxy_callback = f"{base_url}/oauth/auth_callback"
    corrected_params["redirect_uri"] = proxy_callback

    # Create forwarding session and embed session ID in OAuth state
    session_id = str(uuid.uuid4())
    current_time = time.time()
    _callback_forwarding[session_id] = (redirect_uri, current_time)

    # Encode session ID into OAuth state parameter for correlation
    original_state = state or ""
    corrected_params["state"] = (
        f"{original_state}|{session_id}" if original_state else session_id
    )

    logger.info(
        "Created auth forwarding session %s: %s -> %s",
        session_id[:8],
        proxy_callback,
        redirect_uri,
    )
    logger.info(
        "Modified OAuth state: '%s' -> '%s'", original_state, corrected_params["state"]
    )

    # Copy PKCE parameters if present
    if "code_challenge" in params:
        corrected_params["code_challenge"] = params["code_challenge"]
    if "code_challenge_method" in params:
        corrected_params["code_challenge_method"] = params["code_challenge_method"]

    # Copy other optional parameters
    if "resource" in params:
        corrected_params["resource"] = params["resource"]

    # Force access_type=offline to ensure we get refresh tokens
    if "access_type" in params:
        if params["access_type"] != "offline":
            corrected_params["access_type"] = "offline"
            logger.info(
                "Changed access_type from '%s' to 'offline' for refresh token support",
                params["access_type"],
            )
        else:
            corrected_params["access_type"] = params["access_type"]
    else:
        corrected_params["access_type"] = "offline"
        logger.info("Added missing access_type=offline for refresh token support")

    # Handle prompt parameter - ensure we can get refresh tokens
    if "prompt" in params and params["prompt"] != "none":
        corrected_params["prompt"] = params["prompt"]
    elif "prompt" in params and params["prompt"] == "none":
        logger.info(
            "Removed prompt=none to enable refresh token (Google will show consent if needed)"
        )
    else:
        # Force consent to ensure we get a refresh token
        corrected_params["prompt"] = "consent"
        logger.info("Added prompt=consent to force refresh token issuance")

    # Build the corrected Google OAuth URL
    google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth"

    logger.info(
        "Proxying authorization request: %s -> %s",
        redirect_uri,
        corrected_params["redirect_uri"],
    )
    logger.info("Added missing scopes: %s", corrected_params["scope"])
    logger.info(
        "OAuth parameters being sent to Google: access_type=%s, prompt=%s",
        corrected_params.get("access_type", "not_set"),
        corrected_params.get("prompt", "not_set"),
    )

    # Build query string with proper URL encoding
    from urllib.parse import urlencode

    query_string = urlencode(corrected_params)

    # Redirect to Google OAuth with corrected parameters
    return RedirectResponse(url=f"{google_auth_url}?{query_string}", status_code=302)


@app.get("/oauth/auth_callback")
async def oauth_callback_forwarding(request: Request) -> Response:
    """Handle OAuth callback forwarding for localhost callbacks."""
    # Get all query parameters from the OAuth redirect
    query_params = dict(request.query_params)

    logger.info(
        "OAuth callback received with parameters: %s",
        {
            k: v if k not in ["code", "state"] else "***"
            for k, v in query_params.items()
        },
    )

    # OAuth error handling
    error = query_params.get("error")
    if error:
        logger.warning(
            "OAuth callback received error: %s - %s",
            error,
            query_params.get("error_description", "No description"),
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": error,
                "error_description": query_params.get(
                    "error_description", "OAuth authorization failed"
                ),
            },
        )

    # Check if we have an authorization code
    auth_code = query_params.get("code")
    if not auth_code:
        logger.warning("OAuth callback missing authorization code")
        return JSONResponse(
            status_code=400,
            content={
                "error": "missing_code",
                "error_description": "Authorization code is required",
            },
        )

    # Clean up expired sessions
    current_time = time.time()
    expired_sessions = [
        sid
        for sid, (_, timestamp) in _callback_forwarding.items()
        if current_time - timestamp > _callback_forwarding_ttl
    ]
    for expired_sid in expired_sessions:
        del _callback_forwarding[expired_sid]
        logger.debug(
            "Cleaned up expired callback forwarding session: %s", expired_sid[:8]
        )

    # Extract session ID from OAuth state parameter
    oauth_state = query_params.get("state", "")
    session_id = None
    original_state = ""

    logger.info(
        "Processing OAuth callback - state parameter: '%s', active sessions: %s",
        oauth_state,
        list(_callback_forwarding.keys()),
    )

    if oauth_state:
        if "|" in oauth_state:
            original_state, session_id = oauth_state.rsplit("|", 1)
            logger.info(
                "Extracted session ID from compound state: original='%s', session_id='%s'",
                original_state,
                session_id[:8] + "..." if session_id else "None",
            )
        else:
            # Assume the entire state is our session ID if it looks like a UUID
            if len(oauth_state) == 36 and oauth_state.count("-") == 4:
                session_id = oauth_state
                logger.info(
                    "Using entire state as session ID: %s", session_id[:8] + "..."
                )
            else:
                original_state = oauth_state
                logger.info(
                    "Treating state as original client state: %s", original_state
                )

    if not session_id:
        logger.warning(
            "OAuth callback missing session correlation - no session ID in state parameter"
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": "missing_session",
                "error_description": "Cannot correlate OAuth callback to forwarding session",
            },
        )

    # Find the specific forwarding session
    if session_id not in _callback_forwarding:
        logger.warning("OAuth callback session %s not found or expired", session_id[:8])
        return JSONResponse(
            status_code=404,
            content={
                "error": "session_not_found",
                "error_description": "Forwarding session not found or expired",
            },
        )

    localhost_callback, timestamp = _callback_forwarding[session_id]

    # Check if session is still valid
    if current_time - timestamp > _callback_forwarding_ttl:
        del _callback_forwarding[session_id]
        logger.warning("OAuth callback session %s expired", session_id[:8])
        return JSONResponse(
            status_code=410,
            content={
                "error": "session_expired",
                "error_description": "Forwarding session has expired",
            },
        )

    # Prepare query parameters for forwarding (restore original state if it existed)
    forward_params = dict(query_params)
    if original_state:
        forward_params["state"] = original_state
    elif "state" in forward_params:
        # Remove our session ID from state parameter
        del forward_params["state"]

    # Return HTML page with JavaScript redirect for browser-based forwarding
    logger.info(
        "Redirecting OAuth callback from session %s to %s via browser",
        session_id[:8],
        localhost_callback,
    )

    # Build the redirect URL with query parameters
    from urllib.parse import urlencode

    query_string = urlencode(forward_params)
    redirect_url = f"{localhost_callback}?{query_string}"

    # Return HTML page with JavaScript redirect
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>OAuth Callback - Redirecting...</title>
        <meta charset="utf-8">
    </head>
    <body>
        <div style="text-align: center; font-family: Arial, sans-serif; margin-top: 100px;">
            <h2>OAuth Authorization Complete</h2>
            <p>Redirecting to your application...</p>
            <p><em>If you are not redirected automatically, <a href="{redirect_url}">click here</a>.</em></p>
        </div>
        <script>
            // Redirect immediately
            window.location.href = "{redirect_url}";
        </script>
    </body>
    </html>
    """

    # Clean up the session
    del _callback_forwarding[session_id]

    # Return HTML redirect page
    return HTMLResponse(
        content=html_content,
        status_code=200,
        headers={"Content-Type": "text/html; charset=utf-8"},
    )


@app.post("/oauth/token")
async def oauth_token_proxy(request: Request) -> Response:
    """Proxy OAuth token exchange requests to fix redirect_uri parameter and inject credentials."""

    logger.info(
        "Token exchange request received from %s to %s",
        request.client.host if request.client else "unknown",
        str(request.url),
    )

    # Get form data from client's token exchange request
    if request.headers.get("content-type", "").startswith(
        "application/x-www-form-urlencoded"
    ):
        form_data = await request.form()
        params = {k: v for k, v in form_data.items() if isinstance(v, str)}
    else:
        params = (
            dict(await request.json())
            if request.headers.get("content-type") == "application/json"
            else {}
        )

    logger.info(
        "Token exchange proxy request received with grant_type: %s",
        params.get("grant_type", "unknown"),
    )
    logger.debug(
        "Original token exchange parameters: %s",
        {
            k: v if k not in ["client_secret", "code", "code_verifier"] else "***"
            for k, v in params.items()
        },
    )

    # Debug logging for all authentication methods
    auth_header = request.headers.get("authorization", "")
    logger.debug("🔍 AUTH DEBUG - Authorization header present: %s", bool(auth_header))
    logger.debug(
        "🔍 AUTH DEBUG - Authorization header type: %s",
        auth_header.split(" ")[0] if auth_header else "none",
    )
    logger.debug(
        "🔍 AUTH DEBUG - Content-Type: %s", request.headers.get("content-type", "none")
    )
    logger.debug(
        "🔍 AUTH DEBUG - Request headers: %s",
        {k: "***" if "auth" in k.lower() else v for k, v in request.headers.items()},
    )

    # Check for client credentials in request body
    client_id_body = params.get("client_id")
    client_secret_body = params.get("client_secret")

    # Check for client credentials in Authorization header (HTTP Basic Auth)
    client_id_header = None
    client_secret_header = None
    if auth_header and auth_header.startswith("Basic "):
        try:
            import base64

            basic_auth = auth_header[6:]  # Remove "Basic " prefix
            decoded = base64.b64decode(basic_auth).decode("utf-8")
            if ":" in decoded:
                client_id_header, client_secret_header = decoded.split(":", 1)
                logger.debug("🔍 AUTH DEBUG - Basic Auth credentials found in header")
            else:
                logger.warning(
                    "🔍 AUTH DEBUG - Invalid Basic Auth format (no colon separator)"
                )
        except Exception as e:
            logger.warning("🔍 AUTH DEBUG - Failed to decode Basic Auth header: %s", e)

    # Determine final client credentials (header takes precedence per OAuth 2.0 spec)
    client_id = client_id_header or client_id_body
    client_secret = client_secret_header or client_secret_body

    # Log credential sources
    logger.info("🔍 AUTH DEBUG - Client credentials summary:")
    logger.info(
        "🔍 AUTH DEBUG - client_id in body: %s",
        "present" if client_id_body else "missing",
    )
    logger.info(
        "🔍 AUTH DEBUG - client_secret in body: %s",
        "present" if client_secret_body else "missing",
    )
    logger.info(
        "🔍 AUTH DEBUG - client_id in header: %s",
        "present" if client_id_header else "missing",
    )
    logger.info(
        "🔍 AUTH DEBUG - client_secret in header: %s",
        "present" if client_secret_header else "missing",
    )
    logger.info(
        "🔍 AUTH DEBUG - Final client_id: %s (from %s)",
        "present" if client_id else "missing",
        "header" if client_id_header else "body" if client_id_body else "none",
    )
    logger.info(
        "🔍 AUTH DEBUG - Final client_secret: %s (from %s)",
        "present" if client_secret else "missing",
        "header" if client_secret_header else "body" if client_secret_body else "none",
    )

    # Validate client credentials are provided
    if not client_id or not client_secret:
        logger.error(
            "Token exchange failed - missing client credentials: client_id=%s, client_secret=%s",
            "present" if client_id else "missing",
            "present" if client_secret else "missing",
        )
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_client",
                "error_description": "Client authentication failed - missing or invalid client credentials",
            },
        )

    # Validate client credentials match our expected DCR credentials
    if dcr_client_id and client_id != dcr_client_id:
        logger.error(
            "Token exchange failed - invalid client_id: expected %s, got %s",
            dcr_client_id[:20] + "..." if len(dcr_client_id) > 20 else dcr_client_id,
            client_id[:20] + "..." if client_id and len(client_id) > 20 else client_id,
        )
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_client",
                "error_description": "Client authentication failed - invalid client_id",
            },
        )

    if dcr_client_secret and client_secret != dcr_client_secret:
        logger.error("Token exchange failed - invalid client_secret")
        return JSONResponse(
            status_code=401,
            content={
                "error": "invalid_client",
                "error_description": "Client authentication failed - invalid client_secret",
            },
        )

    logger.info("✅ Client credentials validated successfully")

    # Prepare corrected parameters for all token requests (including refresh_token)
    corrected_params = dict(params)

    # Set client credentials in corrected parameters (use from body if present, otherwise from header)
    corrected_params["client_id"] = client_id
    corrected_params["client_secret"] = client_secret

    # Handle authorization_code specific redirect_uri fixing
    if params.get("grant_type") == "authorization_code":
        original_redirect_uri = params.get("redirect_uri")

        # If client is sending its localhost callback, replace with our proxy callback
        if original_redirect_uri:
            scheme = get_request_scheme(request)
            base_url = f"{scheme}://{request.url.netloc}"
            proxy_callback = f"{base_url}/oauth/auth_callback"
            corrected_params["redirect_uri"] = proxy_callback

            logger.info(
                "Token exchange: Fixed redirect_uri %s -> %s",
                original_redirect_uri,
                proxy_callback,
            )

    # Forward the corrected token exchange request to Google
    logger.info(
        "Forwarding %s token exchange request to Google OAuth",
        params.get("grant_type", "unknown"),
    )
    logger.debug(
        "Token exchange parameters: %s",
        {
            k: v if k not in ["client_secret", "code", "refresh_token"] else "***"
            for k, v in corrected_params.items()
        },
    )

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://oauth2.googleapis.com/token",
                data=corrected_params,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0,
            )

        logger.info(
            "Token exchange response from Google: status=%d", response.status_code
        )

        # Log the exact response we got from Google
        logger.info(
            "🔍 Raw Google response - Status: %d, Headers: %s",
            response.status_code,
            dict(response.headers),
        )
        logger.info(
            "🔍 Raw Google response - Content length: %d bytes", len(response.content)
        )

        # Try to decode and log the actual token structure
        try:
            import json

            if response.headers.get("content-encoding") == "gzip":
                import gzip

                decompressed_content = gzip.decompress(response.content)
                logger.info(
                    "🔍 Google response is gzipped - decompressed size: %d bytes",
                    len(decompressed_content),
                )
                token_data = json.loads(decompressed_content.decode("utf-8"))
            else:
                token_data = response.json()

            logger.info(
                "🔍 Google token response structure: %s",
                {k: f"<{type(v).__name__}>" for k, v in token_data.items()},
            )
        except Exception as e:
            logger.warning("🔍 Could not decode Google response: %s", e)

        # Log success details if request succeeded
        if response.status_code == 200:
            try:
                token_response = response.json()
                logger.info("Token exchange successful - received tokens from Google")
                logger.debug("Token types in response: %s", list(token_response.keys()))
                # Check if we got the expected tokens
                if "access_token" in token_response:
                    logger.info("✅ Received access_token from Google")
                if "refresh_token" in token_response:
                    logger.info("✅ Received refresh_token from Google")
                else:
                    logger.warning(
                        "⚠️ No refresh_token received from Google - this may cause token expiration issues"
                    )
                if "id_token" in token_response:
                    logger.info("✅ Received id_token from Google")
            except Exception:
                logger.info("Token exchange successful - response is not JSON")

        # Log error details if request failed
        if response.status_code != 200:
            try:
                error_body = response.json()
                logger.error("Token exchange failed - Google error: %s", error_body)
            except Exception:
                logger.error(
                    "Token exchange failed - Google response body: %s",
                    response.text[:500],
                )

        logger.info("Forwarding token response back to client")

        # Check if the response claims to be gzipped but httpx already decompressed it
        content_encoding = response.headers.get("content-encoding", "").lower()
        response_headers = dict(response.headers)
        response_content = response.content

        if content_encoding == "gzip":
            # Check if content is actually gzipped or if httpx already decompressed it
            import json

            try:
                # Try to read as JSON - if this works, httpx already decompressed it
                token_data = json.loads(response.content.decode("utf-8"))

                # Content is already decompressed JSON, remove misleading gzip header
                logger.info(
                    "✅ Content already decompressed by httpx, removing gzip header"
                )
                response_headers.pop("content-encoding", None)
                response_headers["content-length"] = str(len(response.content))

                logger.info(
                    "🔍 Token data from Google: %s",
                    {
                        k: (
                            f"{str(v)[:20]}..."
                            if k in ["access_token", "refresh_token", "id_token"]
                            else v
                        )
                        for k, v in token_data.items()
                    },
                )

            except (json.JSONDecodeError, UnicodeDecodeError):
                # Content is actually gzipped, decompress it
                logger.info("🔍 Content is actually gzipped, decompressing...")
                try:
                    import gzip

                    response_content = gzip.decompress(response.content)
                    response_headers.pop("content-encoding", None)
                    response_headers["content-length"] = str(len(response_content))
                    logger.info(
                        "✅ Decompressed response: %d -> %d bytes",
                        len(response.content),
                        len(response_content),
                    )
                except Exception as e:
                    logger.error("❌ Failed to decompress gzipped response: %s", e)
                    # Fall back to original response
                    pass

        logger.info(
            "✅ Sending response to client: status=%d, content_length=%d bytes",
            response.status_code,
            len(response_content),
        )
        logger.info(
            "🔍 Final response - Content-Encoding: %s, Content-Length: %s",
            response_headers.get("content-encoding", "none"),
            response_headers.get("content-length", "unknown"),
        )

        return Response(
            content=response_content,
            status_code=response.status_code,
            headers=response_headers,
        )

    except httpx.RequestError as e:
        logger.error("Token exchange request failed: %s", e)
        return JSONResponse(
            status_code=502,
            content={
                "error": "token_exchange_failed",
                "error_description": "Unable to connect to OAuth provider",
            },
        )


@app.post("/validate")
async def validate_token_endpoint(request: Request) -> JSONResponse:
    """Validate OAuth token for MCP server."""
    try:
        body = await request.json()
        token = body.get("token")

        if not token:
            raise HTTPException(status_code=400, detail="Token required")

        # Get expected client ID for validation
        expected_client_id = get_oauth_client_id()

        # Validate token using centralized validation function
        result = await validate_oauth_token(token, expected_client_id)

        return JSONResponse(
            {
                "valid": result.is_valid,
                "client_id": result.client_id if result.is_valid else None,
                "user_email": result.user_email,
                "user_name": result.user_name,
                "error": result.error,
            }
        )

    except Exception as e:
        logger.error(f"Token validation error: {e}")
        raise HTTPException(status_code=500, detail="Token validation failed") from e


@app.post("/validate/user")
async def validate_user_with_groups(request: Request) -> JSONResponse:
    """Validate OAuth token and return user info with group memberships."""
    try:
        body = await request.json()
        token = body.get("token")
        groups_to_check = body.get("groups", [])

        if not token:
            raise HTTPException(status_code=400, detail="Token required")

        if not isinstance(groups_to_check, list):
            raise HTTPException(status_code=400, detail="Groups must be a list")

        # Get expected client ID for validation
        expected_client_id = get_oauth_client_id()

        # Import Google WIF for group validation
        from .gcp.google_wif import google_wif_config

        # Validate token and check group memberships
        if groups_to_check:
            # Use group validation if groups are specified
            validation_result = (
                await google_wif_config.validate_oauth_token_with_groups(
                    access_token=token,
                    required_groups=None,  # Don't require groups, just check membership
                    expected_client_id=expected_client_id,
                )
            )
        else:
            # Standard validation without group checking
            validation_result = await google_wif_config.validate_oauth_token(
                access_token=token, expected_client_id=expected_client_id
            )

        if not validation_result.is_valid or not validation_result.user_info:
            return JSONResponse(
                {
                    "valid": False,
                    "error_type": validation_result.error_type,
                    "error_description": validation_result.error_description,
                    "user_email": None,
                    "user_name": None,
                    "groups": {},
                }
            )

        user_email = validation_result.user_info.email
        user_name = validation_result.user_info.name

        # Check group memberships if groups were specified
        group_memberships = {}
        if groups_to_check:
            try:
                group_memberships = await google_wif_config.check_user_groups(
                    user_email, groups_to_check
                )
                logger.info(
                    "User %s group membership check: %s", user_email, group_memberships
                )
            except Exception as group_error:
                logger.warning(
                    "Failed to check group memberships for user %s: %s",
                    user_email,
                    group_error,
                )
                # Return empty group memberships on error, but don't fail the validation
                group_memberships = dict.fromkeys(groups_to_check, False)

        return JSONResponse(
            {
                "valid": True,
                "user_email": user_email,
                "user_name": user_name,
                "permissions": validation_result.user_info.permissions,
                "groups": group_memberships,
                "error_type": None,
                "error_description": None,
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User validation error: {e}")
        raise HTTPException(status_code=500, detail="User validation failed") from e
