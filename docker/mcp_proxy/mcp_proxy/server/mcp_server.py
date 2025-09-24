"""Create a local SSE server that proxies requests to a stdio MCP server."""

import contextlib
import logging
import os
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

import uvicorn
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.server import Server as MCPServerSDK  # Renamed to avoid conflict
from mcp.server.sse import SseServerTransport
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import BaseRoute, Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from ..utils.config_loader import HttpServerParameters, ServerParameters
from ..utils.logger import logger
from ..utils.process_health import validate_backend_processes
from ..utils.startup_mitigation import StartupMitigation
from ..utils.startup_monitor import StartupMonitor
from .aggregated_proxy_server import create_aggregated_proxy_server, set_user_context
from .oauth_client import validate_request_user
from .proxy_server import create_proxy_server

# Configure httpx logging to prevent token leakage and reduce noise
logging.getLogger("httpx").setLevel(logging.WARNING)

# Configuration for HTTPS enforcement
# Domains that should force HTTPS when behind load balancer
FORCE_HTTPS_DOMAINS = os.getenv("FORCE_HTTPS_DOMAINS", "").split(",")


def _is_production_domain(request: Request) -> bool:
    """
    Check if the request is from a production domain that should use HTTPS.

    Uses proper hostname validation instead of substring checks.
    """
    from urllib.parse import urlparse

    parsed_url = urlparse(str(request.url))
    hostname = parsed_url.hostname

    if not hostname:
        return False

    return any(
        domain.strip() and hostname.endswith(domain.strip())
        for domain in FORCE_HTTPS_DOMAINS
        if domain.strip()
    )


def _extract_token_from_request(request: Request) -> str | None:
    """Extract OAuth token from request Authorization header."""
    auth_header: str | None = request.headers.get("authorization")
    if not auth_header:
        return None

    if not auth_header.startswith("Bearer "):
        return None

    return auth_header[7:]  # Remove "Bearer " prefix


async def _validate_user_request(
    request: Request,
) -> tuple[bool, str | None, str | None, str | None]:
    """
    Validate user request using OAuth sidecar.

    Returns:
        tuple: (is_valid, user_email, error_code, access_token)
    """
    token = _extract_token_from_request(request)
    if not token:
        logger.debug("OAuth validation: No Bearer token found in request")
        return False, None, "missing_token", None

    logger.debug("OAuth validation: Validating user token...")
    result = await validate_request_user(token)

    if result.is_valid:
        logger.info(
            "OAuth validation: User %s authenticated successfully",
            result.user_email or "unknown",
        )
        return True, result.user_email, None, token
    else:
        logger.warning(
            "OAuth validation: Authentication failed for user - %s",
            result.error or "unknown error",
        )
        # Map validation errors to appropriate error codes
        if "not active" in (result.error or "").lower():
            return False, None, "invalid_token", None
        elif "client" in (result.error or "").lower():
            return False, None, "invalid_client", None
        elif "workspace" in (result.error or "").lower():
            return False, None, "workspace_denied", None
        else:
            return False, None, "invalid_token", None


class MCPPathMiddleware:
    """Middleware to add trailing slash to /mcp path for proper Mount handling."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Add trailing slash to MCP path to make it work with Mount
        if scope.get("type") == "http":
            path = scope.get("path", "")
            if path == "/mcp":
                scope["path"] = "/mcp/"
                if scope.get("raw_path"):
                    scope["raw_path"] = b"/mcp/"
        await self.app(scope, receive, send)


@dataclass
class MCPServerSettings:
    """Settings for the MCP server."""

    bind_host: str
    port: int
    stateless: bool = False
    allow_origins: list[str] | None = None
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    google_auth_required: bool = False  # Whether Google user authentication is required
    aggregated_mode: bool = (
        False  # Whether to run in aggregated mode (single server with all tools)
    )


# To store last activity for multiple servers if needed, though status endpoint is global for now.
_global_status: dict[str, Any] = {
    "api_last_activity": datetime.now(UTC).isoformat(),
    "server_instances": {},  # Could be used to store per-instance status later
    "authentication": {
        "type": "oauth_sidecar",
        "google_auth_required": False,  # Will be updated based on settings
        "validation_method": "oauth_sidecar_proxy",
    },
}


def _update_global_activity() -> None:
    _global_status["api_last_activity"] = datetime.now(UTC).isoformat()


async def _handle_status(_: Request) -> Response:
    """Handle the status endpoint to provide server information."""
    return JSONResponse(_global_status)


def create_single_instance_routes(
    mcp_server_instance: MCPServerSDK[object],
    *,
    stateless_instance: bool,
    google_auth_required: bool = False,
) -> tuple[list[BaseRoute], StreamableHTTPSessionManager]:  # Return the manager itself
    """Create Starlette routes and the HTTP session manager for a single MCP server instance."""
    logger.debug(
        "Creating routes for a single MCP server instance (stateless: %s, google_auth_required: %s)",
        stateless_instance,
        google_auth_required,
    )

    sse_transport = SseServerTransport("/messages/")
    http_session_manager = StreamableHTTPSessionManager(
        app=mcp_server_instance,
        event_store=None,
        json_response=True,
        stateless=stateless_instance,
    )

    async def handle_sse_instance(request: Request) -> Response:
        # Validate user if Google auth is required
        if google_auth_required:
            (
                user_valid,
                _user_email,
                error_code,
                _access_token,
            ) = await _validate_user_request(request)
            if not user_valid:
                # Include WWW-Authenticate header as per RFC 6750 for OAuth discovery
                base_url = (
                    f"https://{request.url.netloc}"
                    if _is_production_domain(request)
                    else f"{request.url.scheme}://{request.url.netloc}"
                )

                if error_code == "missing_token":
                    # No token provided - return basic WWW-Authenticate header
                    auth_header = 'Bearer realm="MCP Server"'
                    error_desc = "OAuth Bearer token required for MCP access"
                elif error_code == "invalid_client":
                    # Token issued for wrong client - signal DCR re-registration
                    auth_header = 'Bearer realm="MCP Server", error="invalid_client", error_description="Token was issued for a different client ID"'
                    error_desc = (
                        "OAuth token client ID mismatch - DCR re-registration required"
                    )
                else:
                    # Invalid token or other errors - include error details
                    auth_header = 'Bearer realm="MCP Server", error="invalid_token", error_description="Token validation failed"'
                    error_desc = (
                        "OAuth Bearer token is invalid or user not in Google Workspace"
                    )

                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "unauthorized",
                        "error_description": error_desc,
                        "oauth_discovery": {
                            "protected_resource_metadata": f"{base_url}/.well-known/oauth-protected-resource",
                            "authorization_server_metadata": f"{base_url}/.well-known/oauth-authorization-server",
                        },
                    },
                    headers={
                        "WWW-Authenticate": auth_header,
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    },
                )

            # Log SSE connection activity (logging moved to OAuth sidecar)

        # Add SSE-specific headers to prevent timeouts and enable CORS
        # Set headers directly on the request scope for SSE transport
        request.scope.setdefault("response_headers", []).extend(
            [
                (b"cache-control", b"no-cache"),
                (b"connection", b"keep-alive"),
                (b"x-accel-buffering", b"no"),  # Critical for nginx/ALB deployments
                (b"access-control-allow-origin", b"*"),  # Enable CORS
                (b"access-control-allow-headers", b"cache-control"),
            ]
        )

        async with sse_transport.connect_sse(
            request.scope,
            request.receive,
            request._send,
        ) as (read_stream, write_stream):
            _update_global_activity()
            await mcp_server_instance.run(
                read_stream,
                write_stream,
                mcp_server_instance.create_initialization_options(),
            )
        return Response()

    async def handle_streamable_http_instance(
        scope: Scope, receive: Receive, send: Send
    ) -> None:
        # Extract request details
        method = scope.get("method", "UNKNOWN")
        path = scope.get("path", "/")
        client_info = "unknown"
        if scope.get("client"):
            client_info = f"{scope['client'][0]}:{scope['client'][1]}"

        # Get headers for user agent detection
        headers = {}
        if scope.get("headers"):
            headers = {k.decode(): v.decode() for k, v in scope["headers"]}

        user_agent = headers.get("user-agent", "unknown")
        is_mcp_request = path.startswith("/mcp")

        # Simplified logging - only log significant events
        if is_mcp_request:
            # Log new sessions and authenticated requests more quietly
            auth_header = headers.get("authorization", "NONE")
            has_auth = (
                auth_header.startswith("Bearer ") if auth_header != "NONE" else False
            )

            if method == "POST" and has_auth:
                # This is likely a new authenticated MCP session
                logger.info(
                    "MCP session: %s from %s (%s)", method, client_info, user_agent
                )

            # Detailed debugging only when debug is enabled
            logger.debug(
                "🔍 REQUEST: %s %s from %s | User-Agent: %s | Auth: %s",
                method,
                path,
                client_info,
                user_agent,
                "Bearer token present" if has_auth else "NONE",
            )
        else:
            # Non-MCP requests at debug level only
            logger.debug("Request: %s %s from %s", method, path, client_info)

        # Handle CORS preflight requests
        if scope.get("method") == "OPTIONS":
            from starlette.responses import Response as StarletteResponse

            logger.debug("Handling CORS preflight request for %s", path)
            response = StarletteResponse(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept",
                    "Access-Control-Max-Age": "86400",
                },
            )
            await response(scope, receive, send)
            return

        # Validate user if Google auth is required
        user_email = None
        access_token = None
        if google_auth_required:
            request = Request(scope, receive)
            (
                user_valid,
                user_email,
                error_code,
                access_token,
            ) = await _validate_user_request(request)
            if not user_valid:
                # Include WWW-Authenticate header as per RFC 6750 for OAuth discovery
                base_url = (
                    f"https://{request.url.netloc}"
                    if _is_production_domain(request)
                    else f"{request.url.scheme}://{request.url.netloc}"
                )

                if error_code == "missing_token":
                    # No token provided - return basic WWW-Authenticate header
                    auth_header = 'Bearer realm="MCP Server"'
                    error_desc = "OAuth Bearer token required for MCP access"
                elif error_code == "invalid_client":
                    # Token issued for wrong client - signal DCR re-registration
                    auth_header = 'Bearer realm="MCP Server", error="invalid_client", error_description="Token was issued for a different client ID"'
                    error_desc = (
                        "OAuth token client ID mismatch - DCR re-registration required"
                    )
                else:
                    # Invalid token or other errors - include error details
                    auth_header = 'Bearer realm="MCP Server", error="invalid_token", error_description="Token validation failed"'
                    error_desc = (
                        "OAuth Bearer token is invalid or user not in Google Workspace"
                    )

                # For VS Code OAuth discovery compatibility, return specific error format
                response = JSONResponse(
                    status_code=401,
                    content={
                        "error": "unauthorized",
                        "error_description": error_desc,
                        "oauth_discovery": {
                            "protected_resource_metadata": f"{base_url}/.well-known/oauth-protected-resource",
                            "authorization_server_metadata": f"{base_url}/.well-known/oauth-authorization-server",
                        },
                    },
                    headers={
                        "WWW-Authenticate": auth_header,
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    },
                )
                await response(scope, receive, send)
                return

            # Set user context for tool call logging
            if user_email:
                set_user_context(user_email, access_token or "")

                # Extract more details from the request
                path = scope.get("path", "/mcp")
                method = scope.get("method", "UNKNOWN")
                remote_addr = "unknown"
                if scope.get("client"):
                    remote_addr = scope["client"][0]

                # Skip logging for health check endpoints
                if "/status" not in path:
                    # Only log significant activities, not every request
                    if method == "POST" and path.startswith("/mcp"):
                        # MCP session logging moved to OAuth sidecar
                        logger.debug(
                            "MCP session from %s: %s %s",
                            user_email or "anonymous",
                            method,
                            path,
                        )

                    # Log tool-specific activities with debug details when enabled
                    logger.debug(
                        "User activity - User: %s, Action: http_request, Details: %s",
                        user_email,
                        {
                            "endpoint": path,
                            "method": method,
                            "remote_addr": remote_addr,
                        },
                    )
                else:
                    # Log status checks at debug level only
                    logger.debug(
                        "Health check request from user %s: %s %s",
                        user_email,
                        method,
                        path,
                    )

        _update_global_activity()
        await http_session_manager.handle_request(scope, receive, send)

    # Create routes - always mount under /mcp/
    routes: list[BaseRoute] = [
        Mount("/mcp/", app=handle_streamable_http_instance),
        Route("/sse", endpoint=handle_sse_instance),
        Mount("/messages/", app=sse_transport.handle_post_message),
    ]

    return routes, http_session_manager


async def run_mcp_server(
    mcp_settings: MCPServerSettings,
    default_server_params: StdioServerParameters | None = None,
    named_server_params: dict[str, ServerParameters] | None = None,
    excluded_tools: dict[str, list[str]] | None = None,
    required_groups: dict[str, list[str]] | None = None,
) -> None:
    """Run stdio client(s) and expose an MCP server with multiple possible backends."""
    if named_server_params is None:
        named_server_params = {}
    if excluded_tools is None:
        excluded_tools = {}
    if required_groups is None:
        required_groups = {}

    # Update global status with authentication settings
    _global_status["authentication"]["google_auth_required"] = (
        mcp_settings.google_auth_required
    )

    all_routes: list[BaseRoute] = [
        Route(
            "/status", endpoint=_handle_status
        ),  # Global status endpoint - always public
    ]
    # Use AsyncExitStack to manage lifecycles of multiple components
    async with contextlib.AsyncExitStack() as stack:
        # Manage lifespans of all StreamableHTTPSessionManagers
        @contextlib.asynccontextmanager
        async def combined_lifespan(_app: Starlette) -> AsyncIterator[None]:
            logger.info("Main application lifespan starting...")
            # All http_session_managers' .run() are already entered into the stack
            yield
            logger.info("Main application lifespan shutting down...")

        # Check if aggregated mode is enabled
        if mcp_settings.aggregated_mode:
            # Initialize startup monitoring
            startup_monitor = StartupMonitor()
            startup_monitor.start_phase("AGGREGATED_MODE_STARTUP")

            logger.info(
                "Running in AGGREGATED MODE - combining all backends into single MCP server"
            )

            # Collect all backend server parameters
            all_backends: dict[str, ServerParameters] = {}
            if default_server_params:
                all_backends["default"] = default_server_params
            all_backends.update(named_server_params)

            if not all_backends:
                logger.error("No backend servers configured for aggregated mode.")
                return

            # Phase 1: Apply startup mitigations (only for STDIO servers)
            startup_monitor.start_phase("MITIGATION")

            # Separate HTTP and STDIO servers
            stdio_backends = {
                name: params
                for name, params in all_backends.items()
                if isinstance(params, StdioServerParameters)
            }
            http_backends = {
                name: params
                for name, params in all_backends.items()
                if isinstance(params, HttpServerParameters)
            }

            if stdio_backends:
                logger.info(
                    "Applying startup mitigations for %d STDIO backends...",
                    len(stdio_backends),
                )
                mitigation_start = time.time()

                try:
                    mitigated_stdio_backends = (
                        await StartupMitigation.apply_startup_mitigations(
                            stdio_backends
                        )
                    )
                    mitigation_duration = time.time() - mitigation_start
                    logger.info(
                        "Startup mitigations completed in %.2fs", mitigation_duration
                    )

                    # Record mitigation for monitoring
                    for backend_name in stdio_backends:
                        if (
                            backend_name in mitigated_stdio_backends
                            and mitigated_stdio_backends[backend_name]
                            != stdio_backends[backend_name]
                        ):
                            startup_monitor.record_mitigation_applied(backend_name)

                    # Combine HTTP and mitigated STDIO backends
                    all_backends = {**http_backends, **mitigated_stdio_backends}

                except Exception as e:
                    mitigation_duration = time.time() - mitigation_start
                    logger.warning(
                        "Startup mitigations failed after %.2fs: %s",
                        mitigation_duration,
                        e,
                    )
                    logger.warning("Continuing with original backend configurations...")
            else:
                logger.info("No STDIO backends found, skipping startup mitigations")

            startup_monitor.end_phase("MITIGATION")

            # Phase 2: Health checks
            startup_monitor.start_phase("HEALTH_CHECKS")
            logger.info(
                "Running pre-startup health checks on %d backends...", len(all_backends)
            )
            health_results = await validate_backend_processes(
                all_backends, max_concurrent=3
            )

            # Record health check results
            for name, (is_healthy, error, duration) in health_results.items():
                startup_monitor.record_backend_health_check(
                    name, is_healthy, error, duration
                )

            healthy_backends = {
                name: params
                for name, params in all_backends.items()
                if health_results.get(name, (False, None, 0.0))[0]
            }
            failed_backends = {
                name: error
                for name, (is_healthy, error, duration) in health_results.items()
                if not is_healthy
            }

            if failed_backends:
                logger.warning(
                    "Some backends failed health checks and will be excluded:"
                )
                for name, error in failed_backends.items():
                    logger.warning("  - %s: %s", name, error)
                    startup_monitor.record_backend_skipped(
                        name, f"Health check failed: {error}"
                    )

            startup_monitor.end_phase("HEALTH_CHECKS")

            # Check if we should continue
            should_continue, reason = startup_monitor.should_continue_startup()
            if not should_continue:
                logger.error("Startup cannot continue: %s", reason)
                startup_monitor.log_startup_report()
                return

            logger.info("Continuing startup: %s", reason)
            logger.info(
                "Using %d healthy backends: %s",
                len(healthy_backends),
                ", ".join(healthy_backends.keys()),
            )

            # Phase 3: Session creation
            startup_monitor.start_phase("SESSION_CREATION")
            logger.info(
                "Using long-lived sessions approach - keep-alive tasks will be created"
            )

            # Create backend sessions only for healthy backends
            backend_sessions = {}
            for name, params in healthy_backends.items():
                session_start = time.time()
                try:
                    if isinstance(params, HttpServerParameters):
                        logger.info(
                            "Setting up backend '%s': HTTP %s", name, params.url
                        )
                        http_streams = await stack.enter_async_context(
                            streamablehttp_client(
                                url=params.url, headers=params.headers
                            )
                        )
                        session = await stack.enter_async_context(
                            ClientSession(*http_streams[:2])
                        )
                    else:
                        logger.info(
                            "Setting up backend '%s': %s %s",
                            name,
                            params.command,
                            " ".join(params.args),
                        )
                        stdio_streams = await stack.enter_async_context(
                            stdio_client(params)
                        )
                        session = await stack.enter_async_context(
                            ClientSession(*stdio_streams)
                        )
                    backend_sessions[name] = session

                    session_duration = time.time() - session_start
                    startup_monitor.record_session_result(
                        name, True, None, session_duration
                    )

                except Exception as e:
                    session_duration = time.time() - session_start
                    startup_monitor.record_session_result(
                        name, False, str(e), session_duration
                    )
                    logger.error(
                        "Failed to create session for backend '%s': %s", name, e
                    )

            startup_monitor.end_phase("SESSION_CREATION")

            # Phase 4: Aggregated server creation
            startup_monitor.start_phase("AGGREGATED_SERVER_CREATION")

            # Create the aggregated proxy server
            aggregated_proxy = await create_aggregated_proxy_server(
                backend_sessions,
                healthy_backends,  # Pass healthy backend params for keep-alive detection
                "Qred Aggregated MCP Server",
                excluded_tools,
                required_groups,
                stack,  # Pass the stack for session recovery
            )

            # Create routes for the aggregated server (/mcp with DCR support)
            standard_routes, http_manager = create_single_instance_routes(
                aggregated_proxy,
                stateless_instance=mcp_settings.stateless,
                google_auth_required=mcp_settings.google_auth_required,
            )
            await stack.enter_async_context(http_manager.run())
            all_routes.extend(standard_routes)

            # Update status for all healthy backends
            for name in healthy_backends:
                _global_status["server_instances"][name] = "configured (aggregated)"

            # Mark failed backends in status
            for name in failed_backends:
                _global_status["server_instances"][name] = (
                    f"failed health check: {failed_backends[name]}"
                )

            startup_monitor.end_phase("AGGREGATED_SERVER_CREATION")
            startup_monitor.end_phase("AGGREGATED_MODE_STARTUP")

            # Log comprehensive startup report
            startup_monitor.log_startup_report()

            logger.info(
                "Aggregated server configured with %d healthy backends",
                len(healthy_backends),
            )

        else:
            # Original individual server mode
            logger.info(
                "Running in INDIVIDUAL MODE - separate endpoints for each backend"
            )

            # Setup default server if configured
            # Setup default server if configured
            if default_server_params:
                logger.info(
                    "Setting up default server: %s %s",
                    default_server_params.command,
                    " ".join(default_server_params.args),
                )
                stdio_streams = await stack.enter_async_context(
                    stdio_client(default_server_params)
                )
                session = await stack.enter_async_context(ClientSession(*stdio_streams))
                proxy = await create_proxy_server(session)

                # Create routes (/mcp with DCR support)
                instance_routes, http_manager = create_single_instance_routes(
                    proxy,
                    stateless_instance=mcp_settings.stateless,
                    google_auth_required=mcp_settings.google_auth_required,
                )
                await stack.enter_async_context(http_manager.run())
                all_routes.extend(instance_routes)

                _global_status["server_instances"]["default"] = "configured"

            # Setup named servers
            for name, params in named_server_params.items():
                if isinstance(params, HttpServerParameters):
                    # HTTP transport
                    logger.info(
                        "Setting up named HTTP server '%s': %s",
                        name,
                        params.url,
                    )
                    http_streams = await stack.enter_async_context(
                        streamablehttp_client(url=params.url, headers=params.headers)
                    )
                    session_named = await stack.enter_async_context(
                        ClientSession(*http_streams[:2])
                    )

                else:
                    # STDIO transport (StdioServerParameters)
                    logger.info(
                        "Setting up named STDIO server '%s': %s %s",
                        name,
                        params.command,
                        " ".join(params.args),
                    )
                    stdio_streams_named = await stack.enter_async_context(
                        stdio_client(params)
                    )
                    session_named = await stack.enter_async_context(
                        ClientSession(*stdio_streams_named)
                    )

                proxy_named = await create_proxy_server(session_named)

                instance_routes_named, http_manager_named = (
                    create_single_instance_routes(
                        proxy_named,
                        stateless_instance=mcp_settings.stateless,
                        google_auth_required=mcp_settings.google_auth_required,
                    )
                )
                await stack.enter_async_context(
                    http_manager_named.run(),
                )  # Manage lifespan by calling run()

                # Mount these routes under /servers/<name>/
                server_mount = Mount(f"/servers/{name}", routes=instance_routes_named)
                all_routes.append(server_mount)
                _global_status["server_instances"][name] = "configured"

        if not default_server_params and not named_server_params:
            logger.error("No servers configured to run.")
            return

        middleware: list[Middleware] = [
            Middleware(MCPPathMiddleware),  # Always add MCP path middleware first
        ]
        if mcp_settings.allow_origins:
            middleware.append(
                Middleware(
                    CORSMiddleware,
                    allow_origins=mcp_settings.allow_origins,
                    allow_methods=["*"],
                    allow_headers=["*"],
                ),
            )

        starlette_app = Starlette(
            debug=(mcp_settings.log_level == "DEBUG"),
            routes=all_routes,
            middleware=middleware,
            lifespan=combined_lifespan,
        )

        starlette_app.router.redirect_slashes = False

        config = uvicorn.Config(
            starlette_app,
            host=mcp_settings.bind_host,
            port=mcp_settings.port,
            log_level=mcp_settings.log_level.lower(),
            access_log=mcp_settings.log_level
            == "DEBUG",  # Only show access logs in DEBUG mode
            # Timeouts for production stability
            timeout_keep_alive=180,  # 3 minutes - reduced since we have backend keep-alive
            timeout_graceful_shutdown=30,  # 30 seconds graceful shutdown for cleanup
        )
        http_server = uvicorn.Server(config)

        # Print out the MCP URLs for all configured servers
        base_url = f"http://{mcp_settings.bind_host}:{mcp_settings.port}"
        mcp_urls = []

        if mcp_settings.aggregated_mode:
            # In aggregated mode, single /mcp endpoint with DCR support
            mcp_urls.append(f"{base_url}/mcp")
        else:
            # Add default server if configured
            if default_server_params:
                mcp_urls.append(f"{base_url}/mcp")

            # Add named servers
            mcp_urls.extend(
                [f"{base_url}/servers/{name}/mcp" for name in named_server_params]
            )

        # Display the MCP URLs prominently
        if mcp_urls:
            logger.info("Serving MCP Servers:")

            for url in mcp_urls:
                auth_note = (
                    " (Google auth required)"
                    if mcp_settings.google_auth_required
                    else ""
                )
                dcr_note = " (includes DCR support)" if url.endswith("/mcp") else ""
                logger.info("  - %s%s%s", url, auth_note, dcr_note)

        # Display authentication information
        if mcp_settings.google_auth_required:
            logger.info("Google OAuth authentication: ENABLED (using OAuth sidecar)")
            logger.info("  - Protected endpoints: /mcp/* (401 if OAuth token invalid)")
            logger.info("  - Public endpoints: /status")
            if mcp_settings.aggregated_mode:
                logger.info("  - Mode: Aggregated")
                logger.info("    * /mcp/ (token validation via OAuth sidecar)")
            else:
                logger.info("  - Mode: Individual (separate endpoints per server)")
            logger.info("  - Authentication: OAuth Bearer token required")
            logger.info("  - Validation: Token validated via OAuth sidecar service")
            logger.info("  - Status endpoint: %s/status", base_url)

        else:
            logger.info("Google OAuth authentication: DISABLED")
            logger.info("  - All endpoints publicly accessible")

        logger.debug(
            "Serving incoming MCP requests on %s:%s",
            mcp_settings.bind_host,
            mcp_settings.port,
        )
        await http_server.serve()
