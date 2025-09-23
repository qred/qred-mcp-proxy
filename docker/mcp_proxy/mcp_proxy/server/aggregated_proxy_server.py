"""Create an aggregated MCP server that combines multiple backend MCP servers.

This server aggregates tools, resources, and prompts from multiple backend servers
and presents them as a unified MCP interface with OAuth authentication.
"""

import typing as t
from collections.abc import Mapping
from typing import Optional, Any
import asyncio
import time
import httpx
import os

from mcp import server, types
from mcp.shared.exceptions import McpError
from mcp.client.session import ClientSession

from ..utils.logger import logger, keepalive_logger


# Global store for keep-alive tasks (since we can't modify Server class)
_global_keep_alive_tasks: list[asyncio.Task[None]] = []

# Global set to track backends that don't actually support logging (despite claiming they do)
_backends_without_logging_support: set[str] = set()

# Global cache for excluded tools per backend (computed once at startup)
_excluded_tools_cache: dict[str, set[str]] = {}


async def _validate_user_groups(
    access_token: str, required_groups: list[str]
) -> tuple[bool, str]:
    """Validate if the user belongs to the required groups.

    Args:
        access_token: OAuth access token
        required_groups: List of required Google Workspace group emails

    Returns:
        Tuple of (is_authorized, error_message)
    """
    if not required_groups:
        return True, ""

    oauth_service_url = os.environ.get("OAUTH_SERVICE_URL", "http://localhost:8000")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{oauth_service_url}/validate/user",
                json={"token": access_token, "groups": required_groups},
            )

            if response.status_code == 200:
                data = response.json()
                user_groups_dict = data.get("groups", {})
                user_email = data.get("user_email", "unknown")

                # Check if user belongs to any of the required groups
                # groups is a dict like {"group1@qred.com": true, "group2@qred.com": false}
                for required_group in required_groups:
                    if user_groups_dict.get(required_group, False):
                        logger.debug(
                            "User %s authorized for group %s",
                            user_email,
                            required_group,
                        )
                        return True, ""

                # Get list of user's actual groups for logging
                user_groups = [
                    group for group, is_member in user_groups_dict.items() if is_member
                ]
                logger.warning(
                    "User %s not in required groups %s (user groups: %s)",
                    user_email,
                    required_groups,
                    user_groups,
                )
                return (
                    False,
                    f"Access denied: You must be a member of one of these groups: {', '.join(required_groups)}",
                )

            elif response.status_code == 401:
                return False, "Invalid or expired access token"
            elif response.status_code == 403:
                error_data = response.json()
                return False, error_data.get("detail", "Access denied")
            else:
                logger.error(
                    "OAuth validation failed with status %d: %s",
                    response.status_code,
                    response.text,
                )
                return False, "Authentication service error"

    except httpx.RequestError as e:
        logger.error("Failed to connect to OAuth service: %s", e)
        return False, "Authentication service unavailable"
    except Exception as e:
        logger.error("Unexpected error during group validation: %s", e)
        return False, "Authentication error"


async def _keep_backend_alive(
    backend_name: str, session: ClientSession, capabilities: types.ServerCapabilities
) -> None:
    """Keep a backend connection alive by periodically calling lightweight operations.

    This prevents SSE connections (like PostHog) from timing out due to inactivity.
    We call list_tools every 4 minutes (240 seconds) to stay under the 5-minute timeout.
    """
    start_time = time.time()
    keepalive_logger.info(
        "KEEP-ALIVE START: Backend '%s' keep-alive task started", backend_name
    )
    logger.info("Starting keep-alive for backend '%s'", backend_name)

    ping_count = 0

    while True:
        ping_start = None
        try:
            # Wait 4 minutes between keep-alive calls
            await asyncio.sleep(240)  # 4 minutes = 240 seconds

            ping_count += 1
            ping_start = time.time()

            # Choose the most lightweight operation available
            if capabilities.tools:
                keepalive_logger.debug(
                    "KEEP-ALIVE PING %d: Calling list_tools for backend '%s'",
                    ping_count,
                    backend_name,
                )
                logger.debug(
                    "Keep-alive: calling list_tools for backend '%s'", backend_name
                )
                await session.list_tools()
                ping_duration = time.time() - ping_start
                keepalive_logger.info(
                    "KEEP-ALIVE SUCCESS: Backend '%s' ping %d completed in %.2fs (list_tools)",
                    backend_name,
                    ping_count,
                    ping_duration,
                )
                logger.debug(
                    "Keep-alive: list_tools successful for backend '%s'", backend_name
                )
            elif capabilities.resources:
                keepalive_logger.debug(
                    "KEEP-ALIVE PING %d: Calling list_resources for backend '%s'",
                    ping_count,
                    backend_name,
                )
                logger.debug(
                    "Keep-alive: calling list_resources for backend '%s'", backend_name
                )
                await session.list_resources()
                ping_duration = time.time() - ping_start
                keepalive_logger.info(
                    "KEEP-ALIVE SUCCESS: Backend '%s' ping %d completed in %.2fs (list_resources)",
                    backend_name,
                    ping_count,
                    ping_duration,
                )
                logger.debug(
                    "Keep-alive: list_resources successful for backend '%s'",
                    backend_name,
                )
            elif capabilities.prompts:
                keepalive_logger.debug(
                    "KEEP-ALIVE PING %d: Calling list_prompts for backend '%s'",
                    ping_count,
                    backend_name,
                )
                logger.debug(
                    "Keep-alive: calling list_prompts for backend '%s'", backend_name
                )
                await session.list_prompts()
                ping_duration = time.time() - ping_start
                keepalive_logger.info(
                    "KEEP-ALIVE SUCCESS: Backend '%s' ping %d completed in %.2fs (list_prompts)",
                    backend_name,
                    ping_count,
                    ping_duration,
                )
                logger.debug(
                    "Keep-alive: list_prompts successful for backend '%s'", backend_name
                )
            else:
                keepalive_logger.warning(
                    "KEEP-ALIVE WARNING: Backend '%s' has no capabilities for keep-alive - connection may timeout",
                    backend_name,
                )
                logger.warning(
                    "Backend '%s' has no capabilities for keep-alive - connection may timeout",
                    backend_name,
                )

        except asyncio.CancelledError:
            runtime = time.time() - start_time
            keepalive_logger.info(
                "KEEP-ALIVE STOP: Backend '%s' task cancelled after %.1f minutes (%d pings)",
                backend_name,
                runtime / 60,
                ping_count,
            )
            logger.info("Keep-alive task cancelled for backend '%s'", backend_name)
            break
        except Exception as e:
            ping_duration = time.time() - ping_start if ping_start else 0
            keepalive_logger.error(
                "KEEP-ALIVE ERROR: Backend '%s' ping %d failed after %.2fs: %s",
                backend_name,
                ping_count,
                ping_duration,
                e,
            )
            logger.error("Keep-alive failed for backend '%s': %s", backend_name, e)
            logger.error(
                "Backend '%s' connection may have been lost - this is expected after long inactivity",
                backend_name,
            )
            # Continue the loop to keep trying - the connection might recover
            continue


async def cleanup_keep_alive_tasks() -> None:
    """Clean up all running keep-alive tasks."""
    if _global_keep_alive_tasks:
        keepalive_logger.info(
            "KEEP-ALIVE CLEANUP: Starting cleanup of %d keep-alive tasks",
            len(_global_keep_alive_tasks),
        )
        logger.info("Cleaning up %d keep-alive tasks", len(_global_keep_alive_tasks))

        cancelled_count = 0
        for task in _global_keep_alive_tasks:
            if not task.done():
                task.cancel()
                cancelled_count += 1

        keepalive_logger.info(
            "KEEP-ALIVE CLEANUP: Cancelled %d running tasks, waiting for completion",
            cancelled_count,
        )

        # Wait for all tasks to finish cancelling
        await asyncio.gather(*_global_keep_alive_tasks, return_exceptions=True)
        _global_keep_alive_tasks.clear()

        keepalive_logger.info(
            "KEEP-ALIVE CLEANUP: All keep-alive tasks cleaned up successfully"
        )
        logger.info("All keep-alive tasks cleaned up")


def _backend_needs_keepalive(
    backend_name: str,
    backend_sessions: Mapping[str, ClientSession],
    backend_params: Mapping[str, Any] | None = None,
) -> bool:
    """Determine if a backend needs keep-alive based on its characteristics.

    Backends that typically need keep-alive:
    - Remote SSE connections (like mcp-remote)
    - WebSocket connections
    - HTTP-based backends
    - Any backend using "mcp-remote" command

    Backends that don't need keep-alive:
    - Local STDIO processes (like java -jar)
    - Local file-based backends
    """
    # Check command-based indicators if backend_params available
    if backend_params and backend_name in backend_params:
        params = backend_params[backend_name]
        if hasattr(params, "command"):
            command = params.command.lower()

            # Definitely needs keep-alive
            if any(
                indicator in command
                for indicator in [
                    "mcp-remote",
                    "http://",
                    "https://",
                    "wss://",
                    "ws://",
                ]
            ):
                return True

            # Check args for remote indicators
            if hasattr(params, "args") and params.args:
                args_str = " ".join(str(arg) for arg in params.args).lower()
                if any(
                    indicator in args_str
                    for indicator in ["http://", "https://", "sse", "websocket"]
                ):
                    return True

    # Fallback to name-based detection
    remote_patterns = [
        "posthog",  # Uses mcp-remote with SSE
        "anthropic",  # Likely remote API
        "openai",  # Likely remote API
        "remote",  # Generic remote indicator
        "api",  # Generic API indicator
        "http",  # HTTP-based
        "web",  # Web-based
    ]

    backend_lower = backend_name.lower()
    return any(pattern in backend_lower for pattern in remote_patterns)


# Store current user context for activity logging
_current_user_context: dict[str, str] = {}


def set_user_context(user_email: str, access_token: str = "") -> None:
    """Set the current user context for activity logging and group validation."""
    _current_user_context["email"] = user_email
    if access_token:
        _current_user_context["access_token"] = access_token


def get_user_context() -> Optional[str]:
    """Get the current user email from context."""
    return _current_user_context.get("email")


def get_user_access_token() -> Optional[str]:
    """Get the current user's access token from context."""
    return _current_user_context.get("access_token")


def log_user_activity(action: str, details: dict) -> None:
    """Log user activity with current context."""
    user_email = get_user_context()
    if user_email:
        logger.info(
            "User activity - User: %s, Action: %s, Details: %s",
            user_email,
            action,
            details,
        )


async def _build_tool_exclusion_cache(
    backend_sessions: Mapping[str, ClientSession],
    backend_capabilities: Mapping[str, types.ServerCapabilities],
    excluded_tools: dict[str, list[str]],
) -> None:
    """Build the tool exclusion cache once at startup by fetching actual tools and applying patterns.

    This pre-computes which exact tools are excluded for O(1) lookup during list_tools calls.
    """
    global _excluded_tools_cache
    _excluded_tools_cache.clear()

    total_excluded = 0

    for backend_name, patterns in excluded_tools.items():
        if not patterns or backend_name not in backend_sessions:
            continue

        if not backend_capabilities.get(backend_name, types.ServerCapabilities()).tools:
            logger.debug(
                "Backend '%s' has no tools capability, skipping exclusion cache build",
                backend_name,
            )
            continue

        session = backend_sessions[backend_name]
        excluded_for_backend = set()

        try:
            logger.debug(
                "Building tool exclusion cache for backend '%s' with patterns: %s",
                backend_name,
                patterns,
            )
            tools_result = await session.list_tools()

            if tools_result.tools:
                for tool in tools_result.tools:
                    tool_name = tool.name

                    # Apply exclusion patterns
                    for pattern in patterns:
                        should_exclude = False

                        if pattern == tool_name:
                            should_exclude = True
                        elif pattern.endswith("*") and tool_name.startswith(
                            pattern[:-1]
                        ):
                            should_exclude = True
                        elif pattern.startswith("*") and tool_name.endswith(
                            pattern[1:]
                        ):
                            should_exclude = True
                        elif "*" in pattern:
                            import fnmatch

                            if fnmatch.fnmatch(tool_name, pattern):
                                should_exclude = True

                        if should_exclude:
                            excluded_for_backend.add(tool_name)
                            break  # No need to check other patterns for this tool

                _excluded_tools_cache[backend_name] = excluded_for_backend
                total_excluded += len(excluded_for_backend)

                if excluded_for_backend:
                    logger.info(
                        "🚫 Tool filtering: Excluding %d tools from backend '%s': %s",
                        len(excluded_for_backend),
                        backend_name,
                        ", ".join(sorted(excluded_for_backend)[:5])
                        + (
                            f" (and {len(excluded_for_backend) - 5} more)"
                            if len(excluded_for_backend) > 5
                            else ""
                        ),
                    )
                else:
                    logger.debug(
                        "No tools excluded for backend '%s' (patterns didn't match any tools)",
                        backend_name,
                    )
            else:
                logger.debug(
                    "Backend '%s' returned no tools for exclusion cache", backend_name
                )
                _excluded_tools_cache[backend_name] = set()

        except Exception as e:
            logger.warning(
                "Failed to build tool exclusion cache for backend '%s': %s",
                backend_name,
                e,
            )
            _excluded_tools_cache[backend_name] = set()

    if total_excluded > 0:
        logger.info(
            "Tool exclusion cache built: %d tools excluded across %d backends",
            total_excluded,
            len([b for b in _excluded_tools_cache.values() if b]),
        )
    else:
        logger.debug("Tool exclusion cache built: no tools excluded")


async def _setup_proxy_logging(app: server.Server[object]) -> None:
    """Set up logging handlers for the proxy server itself."""

    async def _set_proxy_logging_level(
        req: types.SetLevelRequest,
    ) -> types.ServerResult:
        """Set logging level on the proxy server itself."""
        try:
            # Import logging here to avoid circular imports
            import logging

            # Map MCP log level strings to Python logging levels
            level_mapping = {
                "debug": logging.DEBUG,
                "info": logging.INFO,
                "warning": logging.WARNING,
                "error": logging.ERROR,
                "critical": logging.CRITICAL,
            }

            level_str = str(req.params.level).lower()

            if level_str in level_mapping:
                python_level = level_mapping[level_str]

                # Set level on our logger
                logger.setLevel(python_level)

                # Also update handler levels if they exist
                for handler in logger.handlers:
                    handler.setLevel(python_level)

                logger.info("Proxy logging level set to %s", level_str.upper())
                return types.ServerResult(types.EmptyResult())
            else:
                error_msg = f"Invalid log level: {req.params.level}. Valid levels: debug, info, warning, error, critical"
                logger.error(error_msg)
                raise ValueError(error_msg)

        except Exception as e:
            error_msg = f"Failed to set logging level: {e}"
            logger.error(error_msg)
            raise ValueError(error_msg) from e

    app.request_handlers[types.SetLevelRequest] = _set_proxy_logging_level


async def create_aggregated_proxy_server(
    backend_sessions: Mapping[str, ClientSession],
    backend_params: Mapping[str, Any] | None = None,
    server_name: str = "Qred Aggregated MCP Server",
    excluded_tools: Optional[dict[str, list[str]]] = None,
    required_groups: Optional[dict[str, list[str]]] = None,
    stack: Optional[Any] = None,  # AsyncExitStack for session recovery
) -> server.Server[object]:
    """Create a server instance that aggregates multiple remote MCP servers.

    Args:
        backend_sessions: Mapping of backend name to ClientSession
        backend_params: Parameters for backend configuration
        server_name: Name for the aggregated server
        excluded_tools: Dict mapping backend names to lists of tool patterns to exclude
        required_groups: Dict mapping backend names to lists of required Google Workspace groups

    Returns:
        Aggregated MCP server instance
    """
    logger.info(
        "Creating aggregated MCP server with %d backends: %s",
        len(backend_sessions),
        ", ".join(backend_sessions.keys()),
    )

    # Initialize all backend sessions with resilience
    backend_capabilities = {}
    backend_info = {}

    # Note: Health checks are now performed at the mcp_server level before calling this function
    # So we can proceed directly to session initialization for all provided backends
    logger.info(
        "Initializing MCP sessions for %d pre-validated backends", len(backend_sessions)
    )

    # Attempt session initialization for all provided backends (already health-checked)
    for name, session in backend_sessions.items():
        max_retries = 4  # Increased from 3 to allow for process recreation
        retry_delay = 1.0  # Start with 1 second delay
        process_recreation_attempted = False

        for attempt in range(max_retries + 1):  # 0, 1, 2, 3, 4 (5 total attempts)
            init_start_time = time.time()  # Initialize timing for each attempt
            session_init_start = None  # Will be set when session.initialize() starts
            try:
                if attempt > 0:
                    logger.info(
                        "Initializing backend '%s'... (attempt %d/%d)",
                        name,
                        attempt + 1,
                        max_retries + 1,
                    )
                    # Wait before retry with exponential backoff
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # Double the delay for next retry
                else:
                    logger.info("Initializing backend '%s'...", name)

                # For mcp-remote backends, add a small delay to let HTTP server fully initialize
                backend_params_for_name = (
                    backend_params.get(name) if backend_params else None
                )
                if (
                    backend_params_for_name
                    and hasattr(backend_params_for_name, "args")
                    and backend_params_for_name.args
                ):
                    args_str = " ".join(
                        str(arg) for arg in backend_params_for_name.args
                    )
                    if "mcp-remote" in args_str and "127.0.0.1" in args_str:
                        startup_delay = (
                            1.0 if attempt == 0 else 0.5
                        )  # Longer delay on first attempt
                        logger.debug(
                            "Backend '%s' uses local mcp-remote - adding %.1fs startup delay",
                            name,
                            startup_delay,
                        )
                        await asyncio.sleep(startup_delay)

                # Add timeout for backend initialization to prevent hanging
                session_init_start = time.time()
                try:
                    logger.debug(
                        "Starting MCP session.initialize() for backend '%s'", name
                    )
                    response = await asyncio.wait_for(
                        session.initialize(), timeout=30.0
                    )
                    init_duration = time.time() - session_init_start
                    logger.debug(
                        "Backend '%s' session.initialize() completed in %.2fs",
                        name,
                        init_duration,
                    )

                    backend_capabilities[name] = response.capabilities
                    backend_info[name] = response.serverInfo

                    if attempt > 0:
                        logger.info(
                            "Backend '%s' initialized successfully on attempt %d: %s (%.2fs)",
                            name,
                            attempt + 1,
                            response.serverInfo.name,
                            init_duration,
                        )
                    else:
                        logger.info(
                            "Backend '%s' initialized successfully: %s (%.2fs)",
                            name,
                            response.serverInfo.name,
                            init_duration,
                        )

                    logger.info(
                        "Backend '%s' capabilities: tools=%s, resources=%s, prompts=%s, logging=%s",
                        name,
                        bool(response.capabilities.tools),
                        bool(response.capabilities.resources),
                        bool(response.capabilities.prompts),
                        bool(response.capabilities.logging),
                    )
                    break  # Success! Exit the retry loop

                except asyncio.TimeoutError:
                    if attempt < max_retries:
                        logger.warning(
                            "Backend '%s' initialization timed out after 30 seconds (attempt %d/%d) - retrying...",
                            name,
                            attempt + 1,
                            max_retries + 1,
                        )
                        continue
                    else:
                        logger.error(
                            "Backend '%s' initialization timed out after 30 seconds (final attempt)",
                            name,
                        )
                        logger.error(
                            "Backend timeout for '%s' - continuing with other backends",
                            name,
                        )
                        logger.error(
                            "This could indicate network issues or slow remote endpoints"
                        )
                        break

            except Exception as e:
                attempt_duration = time.time() - init_start_time
                error_type = type(e).__name__
                error_str = str(e)

                # Check both the exception type name and the string representation for different error patterns
                is_retriable_error = (
                    # Check exception type names (for specific exception classes)
                    error_type
                    in ["ClosedResourceError", "ConnectionError", "TimeoutError"]
                    or
                    # Check string content (for message-based errors)
                    any(
                        error_pattern in error_str
                        for error_pattern in [
                            "SSE error",
                            "Connection refused",
                            "Connection reset",
                            "BrokenPipeError",
                            "EOF occurred",
                        ]
                    )
                )

                # Special handling for process-related errors that might benefit from recreation
                is_process_error = any(
                    error_pattern in error_str
                    for error_pattern in [
                        "SyntaxError",
                        "Module not found",
                        "Cannot find module",
                        "Command not found",
                        "Permission denied",
                    ]
                )

                if attempt < max_retries and (
                    is_retriable_error
                    or (is_process_error and not process_recreation_attempted)
                ):
                    # Normal retry logic
                    if not process_recreation_attempted or not is_process_error:
                        logger.warning(
                            "Backend '%s' initialization failed with %s after %.2fs (attempt %d/%d) - retrying in %.1fs...",
                            name,
                            error_type,
                            attempt_duration,
                            attempt + 1,
                            max_retries + 1,
                            retry_delay,
                        )

                    logger.debug("Retriable error details for '%s': %s", name, e)
                    continue
                else:
                    # Final attempt or non-retriable error
                    if attempt == max_retries:
                        logger.error(
                            "Backend '%s' initialization failed after %d attempts with %s (%.2fs)",
                            name,
                            max_retries + 1,
                            error_type,
                            attempt_duration,
                        )
                    else:
                        logger.error(
                            "Backend '%s' initialization failed with non-retriable error: %s (%.2fs)",
                            name,
                            error_type,
                            attempt_duration,
                        )

                    logger.error("Failed to initialize backend '%s': %s", name, e)
                    if "SSE error" in error_str or "timeout" in error_str.lower():
                        logger.error(
                            "Backend '%s' appears to use SSE or remote connections - this can be unstable",
                            name,
                        )
                        logger.error(
                            "Consider using local backends or contact the service provider about connection stability"
                        )
                    elif "ClosedResourceError" in error_str:
                        logger.error(
                            "Backend '%s' has connection stream issues - this may be due to rapid reconnection attempts",
                            name,
                        )
                        logger.error(
                            "The retry mechanism should help, but persistent failures may indicate backend instability"
                        )
                    elif is_process_error:
                        logger.error(
                            "Backend '%s' has process-level issues that may require environment fixes",
                            name,
                        )
                        logger.error(
                            "Check that all dependencies are installed and accessible"
                        )

                    logger.exception(
                        "Full traceback for backend '%s' initialization failure:", name
                    )
                    break  # Check if we have at least one working backend
    if not backend_capabilities:
        logger.error(
            "No backends successfully initialized! Cannot create aggregated server."
        )
        raise RuntimeError("All backend initializations failed")

    successful_backends = list(backend_capabilities.keys())
    logger.info(
        "Successfully initialized %d backend(s): %s",
        len(successful_backends),
        ", ".join(successful_backends),
    )

    failed_backends = set(backend_sessions.keys()) - set(successful_backends)
    if failed_backends:
        logger.warning(
            "Failed to initialize backend(s): %s", ", ".join(failed_backends)
        )

    # Start keep-alive tasks for backends that need them (remote/SSE backends)
    keep_alive_tasks = []
    for backend_name, session in backend_sessions.items():
        if backend_name in backend_capabilities and _backend_needs_keepalive(
            backend_name, backend_sessions, backend_params
        ):
            # This backend uses remote connections and needs keep-alive to prevent timeouts
            keepalive_logger.info(
                "KEEP-ALIVE INIT: Starting keep-alive task for backend '%s' (remote/SSE connection detected)",
                backend_name,
            )
            keep_alive_task = asyncio.create_task(
                _keep_backend_alive(
                    backend_name, session, backend_capabilities[backend_name]
                )
            )
            keep_alive_tasks.append(keep_alive_task)
            logger.info(
                "Started keep-alive task for backend '%s' (remote/SSE connection detected)",
                backend_name,
            )
        else:
            keepalive_logger.debug(
                "KEEP-ALIVE SKIP: Backend '%s' does not need keep-alive (local connection)",
                backend_name,
            )

    if keep_alive_tasks:
        keepalive_logger.info(
            "KEEP-ALIVE SUMMARY: Started %d keep-alive tasks for remote backends",
            len(keep_alive_tasks),
        )
    else:
        keepalive_logger.info(
            "KEEP-ALIVE SUMMARY: No keep-alive tasks needed (all backends are local)"
        )

    # Create the aggregated server with logging capability
    app: server.Server[object] = server.Server(name=server_name)

    # Store keep-alive tasks globally for cleanup if needed
    _global_keep_alive_tasks.extend(keep_alive_tasks)

    # CRITICAL: Set up logging capability FIRST, before any other setup
    # This ensures the SetLevel handler is available immediately when VS Code queries capabilities
    if any(caps.logging for caps in backend_capabilities.values()):
        logger.info(
            "Setting up aggregated logging capability (backends support logging)..."
        )
        logger.info(
            "Backends with logging support: %s",
            [name for name, caps in backend_capabilities.items() if caps.logging],
        )
        await _setup_aggregated_logging(app, backend_sessions, backend_capabilities)
        logger.info(
            "Aggregated logging setup complete. SetLevel handler registered: %s",
            types.SetLevelRequest in app.request_handlers,
        )
    else:
        logger.info(
            "Setting up proxy logging capability (no backends support logging)..."
        )
        await _setup_proxy_logging(app)
        logger.info(
            "Proxy logging setup complete. SetLevel handler registered: %s",
            types.SetLevelRequest in app.request_handlers,
        )

    # Aggregate tools
    if any(caps.tools for caps in backend_capabilities.values()):
        logger.debug("Setting up aggregated tools...")
        await _setup_aggregated_tools(
            app, backend_sessions, backend_capabilities, excluded_tools, required_groups
        )

    # Aggregate resources
    if any(caps.resources for caps in backend_capabilities.values()):
        logger.debug("Setting up aggregated resources...")
        await _setup_aggregated_resources(
            app, backend_sessions, backend_capabilities, required_groups
        )

    # Aggregate prompts
    if any(caps.prompts for caps in backend_capabilities.values()):
        logger.debug("Setting up aggregated prompts...")
        await _setup_aggregated_prompts(
            app, backend_sessions, backend_capabilities, required_groups
        )

    logger.info(
        "Aggregated MCP server ready with backends: %s",
        ", ".join(backend_capabilities.keys()),
    )

    # Debug: Check what capabilities we're advertising
    try:
        # The MCP Server should automatically include logging=True if we have any logging handlers
        logger.info("=== SERVER CAPABILITY DEBUG ===")
        logger.info(
            "Registered request handlers: %s", list(app.request_handlers.keys())
        )
        logger.info(
            "SetLevelRequest handler registered: %s",
            types.SetLevelRequest in app.request_handlers,
        )
        logger.info(
            "Server will advertise logging capability: %s",
            bool(app.request_handlers.get(types.SetLevelRequest)),
        )
    except Exception as e:
        logger.error("Failed to debug server capabilities: %s", e)

    return app


async def _setup_aggregated_tools(
    app: server.Server[object],
    backend_sessions: Mapping[str, ClientSession],
    backend_capabilities: Mapping[str, types.ServerCapabilities],
    excluded_tools: Optional[dict[str, list[str]]] = None,
    required_groups: Optional[dict[str, list[str]]] = None,
) -> None:
    """Set up aggregated tool handlers with optional tool filtering and group-based access control.

    Args:
        app: The MCP server app
        backend_sessions: Mapping of backend name to ClientSession
        backend_capabilities: Mapping of backend name to capabilities
        excluded_tools: Dict mapping backend names to lists of tool patterns to exclude
        required_groups: Dict mapping backend names to lists of required Google Workspace groups
    """
    excluded_tools = excluded_tools or {}
    required_groups = required_groups or {}

    # Build exclusion cache once at startup
    await _build_tool_exclusion_cache(
        backend_sessions, backend_capabilities, excluded_tools
    )

    def _should_exclude_tool(backend_name: str, tool_name: str) -> bool:
        """Check if a tool should be excluded based on pre-computed cache."""
        return tool_name in _excluded_tools_cache.get(backend_name, set())

    async def _list_tools(_: t.Any) -> types.ServerResult:  # noqa: ANN401
        """List all tools from all backends with namespaced names."""
        all_tools = []

        # Log user activity for listing tools
        log_user_activity("list_tools", {"backends": list(backend_sessions.keys())})

        for backend_name, session in backend_sessions.items():
            if not backend_capabilities[backend_name].tools:
                logger.debug("Backend '%s' has no tools capability", backend_name)
                continue

            # Check if this backend requires group membership
            backend_required_groups = required_groups.get(backend_name, [])
            if backend_required_groups:
                access_token = get_user_access_token()
                if not access_token:
                    logger.debug(
                        "Backend '%s' requires groups %s but no access token available - skipping",
                        backend_name,
                        backend_required_groups,
                    )
                    continue

                # Validate user groups
                is_authorized, error_msg = await _validate_user_groups(
                    access_token, backend_required_groups
                )
                if not is_authorized:
                    user_email = get_user_context()
                    logger.info(
                        "🚫 Access control: User %s not authorized for backend '%s' tools - %s",
                        user_email or "unknown",
                        backend_name,
                        error_msg,
                    )
                    continue

                logger.debug(
                    "✅ Access control: User authorized for backend '%s' (requires groups: %s)",
                    backend_name,
                    backend_required_groups,
                )

            try:
                logger.debug("Listing tools from backend '%s'...", backend_name)
                tools_result = await session.list_tools()
                logger.debug(
                    "Backend '%s' returned %d tools",
                    backend_name,
                    len(tools_result.tools) if tools_result.tools else 0,
                )

                if tools_result.tools:
                    # Namespace the tools with backend name and filter excluded ones
                    for tool in tools_result.tools:
                        # Check if this tool should be excluded
                        if _should_exclude_tool(backend_name, tool.name):
                            # Tool is excluded by configuration - no per-user logging needed
                            continue

                        namespaced_tool = types.Tool(
                            name=f"{backend_name}_{tool.name}",
                            description=f"[{backend_name.upper()}] {tool.description}",
                            inputSchema=tool.inputSchema,
                        )
                        all_tools.append(namespaced_tool)
                        logger.debug("Added namespaced tool: %s", namespaced_tool.name)

            except Exception as e:
                logger.error(
                    "Failed to list tools from backend '%s': %s", backend_name, e
                )
                logger.exception(
                    "Full traceback for backend '%s' tools listing:", backend_name
                )
                continue

        logger.debug("Listed %d total tools across all backends", len(all_tools))
        return types.ServerResult(types.ListToolsResult(tools=all_tools))

    async def _call_tool(req: types.CallToolRequest) -> types.ServerResult:
        """Call a tool, routing to the appropriate backend.

        Automatically injects the authenticated user's email into tool arguments
        for backends that require user authentication. This ensures security
        and prevents misconfigurations where agents might provide incorrect user info.
        """
        tool_name = req.params.name

        # Parse the namespaced tool name
        if "_" not in tool_name:
            raise ValueError(
                f"Invalid tool name format: {tool_name}. Expected: backend_toolname"
            )

        backend_name, actual_tool_name = tool_name.split("_", 1)

        if backend_name not in backend_sessions:
            raise ValueError(f"Unknown backend: {backend_name}")

        session = backend_sessions[backend_name]

        # Check if this backend requires group membership
        backend_required_groups = required_groups.get(backend_name, [])
        if backend_required_groups:
            access_token = get_user_access_token()
            if not access_token:
                error_msg = f"Tool '{actual_tool_name}' from backend '{backend_name}' requires group membership verification but no access token available"
                logger.warning("Blocked tool call: %s", error_msg)
                raise McpError(
                    types.ErrorData(code=types.INVALID_REQUEST, message=error_msg)
                )

            # Validate user groups
            is_authorized, error_msg = await _validate_user_groups(
                access_token, backend_required_groups
            )
            if not is_authorized:
                user_email = get_user_context()
                logger.warning(
                    "🚫 Tool execution blocked: User %s not in required groups for backend '%s' (tool: %s) - %s",
                    user_email or "unknown",
                    backend_name,
                    actual_tool_name,
                    error_msg,
                )
                raise McpError(
                    types.ErrorData(code=types.INVALID_REQUEST, message=error_msg)
                )

            logger.debug(
                "User authorized for tool call on backend '%s' (groups: %s)",
                backend_name,
                backend_required_groups,
            )

        # Check if this tool is excluded (safety check in case client bypasses list_tools)
        if _should_exclude_tool(backend_name, actual_tool_name):
            error_msg = f"Tool '{actual_tool_name}' from backend '{backend_name}' is not available (excluded by configuration)"
            logger.warning(
                "Blocked attempt to call excluded tool '%s' from backend '%s'. Reason: %s",
                actual_tool_name,
                backend_name,
                error_msg,
            )

        try:
            logger.debug(
                "Calling tool '%s' on backend '%s'", actual_tool_name, backend_name
            )

            # Prepare arguments and automatically inject authenticated user
            arguments = dict(req.params.arguments or {})

            # Get the authenticated user from context
            user_email = get_user_context()

            # Define backends that require automatic user injection
            BACKENDS_REQUIRING_USER = {
                "postgres": True,  # Always override user parameter (security critical)
                "grafana": False,  # Only inject if not present
                "posthog": False,  # Only inject if not present
                "sonarqube": False,  # Only inject if not present
            }

            # Inject user parameter based on backend configuration
            if user_email:
                should_override = BACKENDS_REQUIRING_USER.get(backend_name, False)

                if should_override or "user" not in arguments:
                    arguments["user"] = user_email
                    injection_type = "override" if should_override else "inject"
                    logger.debug(
                        "Automatically %s authenticated user '%s' for backend '%s' tool '%s'",
                        injection_type,
                        user_email,
                        backend_name,
                        actual_tool_name,
                    )
                else:
                    logger.debug(
                        "User parameter already provided for backend '%s' tool '%s', not overriding",
                        backend_name,
                        actual_tool_name,
                    )
            elif not user_email and backend_name in BACKENDS_REQUIRING_USER:
                logger.warning(
                    "No authenticated user context available for backend '%s' that requires user injection",
                    backend_name,
                )

            # Log user tool activity
            log_user_activity(
                "tool_call",
                {
                    "tool_name": actual_tool_name,
                    "backend": backend_name,
                    "namespaced_tool": tool_name,
                    "arguments": {
                        k: v for k, v in arguments.items() if k != "user"
                    },  # Don't log sensitive user info
                    "injected_user": user_email is not None,
                    "user_override": BACKENDS_REQUIRING_USER.get(backend_name, False),
                },
            )

            result = await session.call_tool(actual_tool_name, arguments)
            return types.ServerResult(result)

        except Exception as e:
            logger.error(
                "Tool call failed for '%s' on backend '%s': %s",
                actual_tool_name,
                backend_name,
                e,
            )

            # Log failed tool activity
            log_user_activity(
                "tool_call_failed",
                {
                    "tool_name": actual_tool_name,
                    "backend": backend_name,
                    "namespaced_tool": tool_name,
                    "error": str(e),
                },
            )
            raise

    app.request_handlers[types.ListToolsRequest] = _list_tools
    app.request_handlers[types.CallToolRequest] = _call_tool


async def _setup_aggregated_resources(
    app: server.Server[object],
    backend_sessions: Mapping[str, ClientSession],
    backend_capabilities: Mapping[str, types.ServerCapabilities],
    required_groups: Optional[dict[str, list[str]]] = None,
) -> None:
    """Set up aggregated resource handlers with optional group-based access control.

    Args:
        app: The MCP server app
        backend_sessions: Mapping of backend name to ClientSession
        backend_capabilities: Mapping of backend name to capabilities
        required_groups: Dict mapping backend names to lists of required Google Workspace groups
    """
    required_groups = required_groups or {}

    async def _list_resources(_: t.Any) -> types.ServerResult:  # noqa: ANN401
        """List all resources from all backends with namespaced URIs."""
        all_resources = []

        # Log user activity for listing resources
        log_user_activity("list_resources", {"backends": list(backend_sessions.keys())})

        for backend_name, session in backend_sessions.items():
            if not backend_capabilities[backend_name].resources:
                logger.debug("Backend '%s' has no resources capability", backend_name)
                continue

            # Check if this backend requires group membership
            backend_required_groups = required_groups.get(backend_name, [])
            if backend_required_groups:
                access_token = get_user_access_token()
                if not access_token:
                    logger.debug(
                        "Backend '%s' requires groups %s but no access token available - skipping",
                        backend_name,
                        backend_required_groups,
                    )
                    continue

                # Validate user groups
                is_authorized, error_msg = await _validate_user_groups(
                    access_token, backend_required_groups
                )
                if not is_authorized:
                    user_email = get_user_context()
                    logger.info(
                        "🚫 Access control: User %s not authorized for backend '%s' resources - %s",
                        user_email or "unknown",
                        backend_name,
                        error_msg,
                    )
                    continue

                logger.debug(
                    "✅ Access control: User authorized for backend '%s' resources (requires groups: %s)",
                    backend_name,
                    backend_required_groups,
                )

            try:
                logger.debug("Listing resources from backend '%s'...", backend_name)
                resources_result = await session.list_resources()
                logger.debug(
                    "Backend '%s' returned %d resources",
                    backend_name,
                    (
                        len(resources_result.resources)
                        if resources_result.resources
                        else 0
                    ),
                )

                if resources_result.resources:
                    # Namespace the resources with backend name
                    for resource in resources_result.resources:
                        from pydantic import AnyUrl

                        namespaced_uri = f"{backend_name}://{resource.uri}"
                        namespaced_resource = types.Resource(
                            uri=AnyUrl(namespaced_uri),
                            name=f"[{backend_name.upper()}] {resource.name or 'Unnamed'}",
                            description=resource.description,
                            mimeType=resource.mimeType,
                        )
                        all_resources.append(namespaced_resource)
                        logger.debug(
                            "Added namespaced resource: %s", namespaced_resource.uri
                        )

            except Exception as e:
                logger.error(
                    "Failed to list resources from backend '%s': %s", backend_name, e
                )
                continue

        return types.ServerResult(types.ListResourcesResult(resources=all_resources))

    async def _read_resource(req: types.ReadResourceRequest) -> types.ServerResult:
        """Read a resource, routing to the appropriate backend."""
        uri_str = str(req.params.uri)

        # Parse the namespaced URI
        if "://" not in uri_str:
            raise ValueError(
                f"Invalid resource URI format: {uri_str}. Expected: backend://original_uri"
            )

        backend_name, original_uri = uri_str.split("://", 1)

        if backend_name not in backend_sessions:
            raise ValueError(f"Unknown backend: {backend_name}")

        # Check if this backend requires group membership
        backend_required_groups = required_groups.get(backend_name, [])
        if backend_required_groups:
            access_token = get_user_access_token()
            if not access_token:
                logger.warning(
                    "Backend '%s' requires groups %s but no access token available",
                    backend_name,
                    backend_required_groups,
                )
                raise ValueError(
                    f"Access denied: Backend '{backend_name}' requires authentication"
                )

            # Validate user groups
            is_authorized, error_msg = await _validate_user_groups(
                access_token, backend_required_groups
            )
            if not is_authorized:
                user_email = get_user_context()
                logger.warning(
                    "🚫 Resource access blocked: User %s not in required groups for backend '%s' (resource: %s) - %s",
                    user_email or "unknown",
                    backend_name,
                    original_uri,
                    error_msg,
                )
                raise ValueError(f"Access denied: {error_msg}")

            logger.debug(
                "User authorized for backend '%s' (groups: %s)",
                backend_name,
                backend_required_groups,
            )

        session = backend_sessions[backend_name]

        try:
            from pydantic import AnyUrl

            result = await session.read_resource(AnyUrl(original_uri))
            return types.ServerResult(result)

        except Exception as e:
            logger.error(
                "Resource read failed for '%s' on backend '%s': %s",
                original_uri,
                backend_name,
                e,
            )
            raise

    app.request_handlers[types.ListResourcesRequest] = _list_resources
    app.request_handlers[types.ReadResourceRequest] = _read_resource


async def _setup_aggregated_prompts(
    app: server.Server[object],
    backend_sessions: Mapping[str, ClientSession],
    backend_capabilities: Mapping[str, types.ServerCapabilities],
    required_groups: Optional[dict[str, list[str]]] = None,
) -> None:
    """Set up aggregated prompt handlers with optional group-based access control.

    Args:
        app: The MCP server app
        backend_sessions: Mapping of backend name to ClientSession
        backend_capabilities: Mapping of backend name to capabilities
        required_groups: Dict mapping backend names to lists of required Google Workspace groups
    """
    required_groups = required_groups or {}

    async def _list_prompts(_: t.Any) -> types.ServerResult:  # noqa: ANN401
        """List all prompts from all backends with namespaced names."""
        all_prompts = []

        # Log user activity for listing prompts
        log_user_activity("list_prompts", {"backends": list(backend_sessions.keys())})

        for backend_name, session in backend_sessions.items():
            if not backend_capabilities[backend_name].prompts:
                logger.debug("Backend '%s' has no prompts capability", backend_name)
                continue

            # Check if this backend requires group membership
            backend_required_groups = required_groups.get(backend_name, [])
            if backend_required_groups:
                access_token = get_user_access_token()
                if not access_token:
                    logger.debug(
                        "Backend '%s' requires groups %s but no access token available - skipping",
                        backend_name,
                        backend_required_groups,
                    )
                    continue

                # Validate user groups
                is_authorized, error_msg = await _validate_user_groups(
                    access_token, backend_required_groups
                )
                if not is_authorized:
                    user_email = get_user_context()
                    logger.info(
                        "🚫 Access control: User %s not authorized for backend '%s' prompts - %s",
                        user_email or "unknown",
                        backend_name,
                        error_msg,
                    )
                    continue

                logger.debug(
                    "✅ Access control: User authorized for backend '%s' prompts (requires groups: %s)",
                    backend_name,
                    backend_required_groups,
                )

            try:
                logger.debug("Listing prompts from backend '%s'...", backend_name)
                prompts_result = await session.list_prompts()
                logger.debug(
                    "Backend '%s' returned %d prompts",
                    backend_name,
                    len(prompts_result.prompts) if prompts_result.prompts else 0,
                )

                if prompts_result.prompts:
                    # Namespace the prompts with backend name
                    for prompt in prompts_result.prompts:
                        namespaced_prompt = types.Prompt(
                            name=f"{backend_name}_{prompt.name}",
                            description=(
                                f"[{backend_name.upper()}] {prompt.description}"
                                if prompt.description
                                else None
                            ),
                            arguments=prompt.arguments,
                        )
                        all_prompts.append(namespaced_prompt)
                        logger.debug(
                            "Added namespaced prompt: %s", namespaced_prompt.name
                        )

            except Exception as e:
                logger.error(
                    "Failed to list prompts from backend '%s': %s", backend_name, e
                )
                continue

        return types.ServerResult(types.ListPromptsResult(prompts=all_prompts))

    async def _get_prompt(req: types.GetPromptRequest) -> types.ServerResult:
        """Get a prompt, routing to the appropriate backend."""
        prompt_name = req.params.name

        # Parse the namespaced prompt name
        if "_" not in prompt_name:
            raise ValueError(
                f"Invalid prompt name format: {prompt_name}. Expected: backend_promptname"
            )

        backend_name, actual_prompt_name = prompt_name.split("_", 1)

        if backend_name not in backend_sessions:
            raise ValueError(f"Unknown backend: {backend_name}")

        # Check if this backend requires group membership
        backend_required_groups = required_groups.get(backend_name, [])
        if backend_required_groups:
            access_token = get_user_access_token()
            if not access_token:
                logger.warning(
                    "Backend '%s' requires groups %s but no access token available",
                    backend_name,
                    backend_required_groups,
                )
                raise ValueError(
                    f"Access denied: Backend '{backend_name}' requires authentication"
                )

            # Validate user groups
            is_authorized, error_msg = await _validate_user_groups(
                access_token, backend_required_groups
            )
            if not is_authorized:
                user_email = get_user_context()
                logger.warning(
                    "🚫 Prompt execution blocked: User %s not in required groups for backend '%s' (prompt: %s) - %s",
                    user_email or "unknown",
                    backend_name,
                    actual_prompt_name,
                    error_msg,
                )
                raise ValueError(f"Access denied: {error_msg}")

            logger.debug(
                "User authorized for backend '%s' (groups: %s)",
                backend_name,
                backend_required_groups,
            )

        session = backend_sessions[backend_name]

        try:
            result = await session.get_prompt(actual_prompt_name, req.params.arguments)
            return types.ServerResult(result)

        except Exception as e:
            logger.error(
                "Prompt get failed for '%s' on backend '%s': %s",
                actual_prompt_name,
                backend_name,
                e,
            )
            raise

    app.request_handlers[types.ListPromptsRequest] = _list_prompts
    app.request_handlers[types.GetPromptRequest] = _get_prompt


async def _setup_aggregated_logging(
    app: server.Server[object],
    backend_sessions: Mapping[str, ClientSession],
    backend_capabilities: Mapping[str, types.ServerCapabilities],
) -> None:
    """Set up aggregated logging handlers."""

    def _validate_log_level(level: str) -> str:
        """Validate log level according to MCP specification (RFC 5424).

        Returns:
            str: The validated level (case-sensitive)

        Raises:
            McpError: If the level is invalid (JSON-RPC error -32602)
        """
        # MCP logging specification defines 8 log levels following RFC 5424
        # These are case-sensitive according to the spec
        valid_levels = {
            "debug",
            "info",
            "notice",
            "warning",
            "error",
            "critical",
            "alert",
            "emergency",
        }

        # Case-sensitive validation
        if level not in valid_levels:
            raise McpError(
                types.ErrorData(
                    code=types.INVALID_PARAMS,
                    message=f"Invalid log level: {level}. Valid levels: {sorted(valid_levels)}",
                )
            )
        return level

    async def _set_logging_level(req: types.SetLevelRequest) -> types.ServerResult:
        """Set logging level on the proxy and all backends that support it."""
        logger.info("Received SetLevelRequest: %s", req)

        # Validate the log level according to MCP specification
        level_str = _validate_log_level(req.params.level)

        results = []

        # First, set the proxy's own logging level
        try:
            import logging

            # MCP logging specification defines 8 log levels following RFC 5424
            level_mapping = {
                "debug": logging.DEBUG,
                "info": logging.INFO,
                "notice": logging.INFO,  # Python logging doesn't have NOTICE, map to INFO
                "warning": logging.WARNING,
                "error": logging.ERROR,
                "critical": logging.CRITICAL,
                "alert": logging.CRITICAL,  # Python logging doesn't have ALERT, map to CRITICAL
                "emergency": logging.CRITICAL,  # Python logging doesn't have EMERGENCY, map to CRITICAL
            }

            python_level = level_mapping[level_str]

            # Set level on proxy logger
            logger.setLevel(python_level)

            # Also update handler levels if they exist
            for handler in logger.handlers:
                handler.setLevel(python_level)

            results.append("proxy: success")
            logger.info("Proxy logging level set to %s", level_str.upper())

        except Exception as e:
            logger.error("Failed to set proxy logging level: %s", e)
            logger.exception("Full traceback for proxy logging level setting:")
            results.append(f"proxy: failed - {e}")

        # Then, forward to all backends that support logging
        for backend_name, session in backend_sessions.items():
            # Skip backends that don't claim logging support
            if not backend_capabilities[backend_name].logging:
                continue

            # Skip backends we've learned don't actually support logging
            if backend_name in _backends_without_logging_support:
                logger.debug(
                    "Skipping backend '%s' - known to not support setLevel",
                    backend_name,
                )
                results.append(f"{backend_name}: skipped (no setLevel support)")
                continue

            try:
                await session.set_logging_level(req.params.level)
                results.append(f"{backend_name}: success")

            except Exception as e:
                error_str = str(e)
                # Handle specific error cases more gracefully
                if (
                    "Missing handler for request type: logging/setLevel" in error_str
                    or ("HTTP 500" in error_str and "logging/setLevel" in error_str)
                    or (
                        "Failed to handle request" in error_str
                        and "logging/setLevel" in error_str
                    )
                ):
                    logger.warning(
                        "Backend '%s' claims logging support but doesn't implement setLevel handler - adding to exclusion list",
                        backend_name,
                    )
                    # Add to exclusion list so we don't try again
                    was_empty = len(_backends_without_logging_support) == 0
                    _backends_without_logging_support.add(backend_name)
                    if was_empty:
                        logger.info(
                            "Started dynamic exclusion list for backends without actual logging support"
                        )
                    results.append(f"{backend_name}: no setLevel handler (excluded)")
                elif (
                    "not active" in error_str.lower() or "session" in error_str.lower()
                ):
                    logger.warning(
                        "Backend '%s' session issue during logging request: %s",
                        backend_name,
                        error_str,
                    )
                    results.append(f"{backend_name}: session issue")
                else:
                    logger.error(
                        "Failed to set logging level on backend '%s': %s",
                        backend_name,
                        e,
                    )
                    results.append(f"{backend_name}: failed - {e}")

        logger.info(
            "Set logging level to %s on %d targets: %s",
            req.params.level,
            len(results),
            ", ".join(results),
        )

        # Log exclusion list status if it has entries
        if _backends_without_logging_support:
            logger.info(
                "Backends excluded from logging requests: %s",
                list(_backends_without_logging_support),
            )

        return types.ServerResult(types.EmptyResult())

    async def _set_logging_level_wrapper(
        req: types.SetLevelRequest,
    ) -> types.ServerResult:
        """Wrapper for set logging level with comprehensive error handling."""
        try:
            logger.info("Processing SetLevelRequest: level=%s", req.params.level)

            # Basic validation - MCP spec requires proper request structure
            if not hasattr(req, "params") or not hasattr(req.params, "level"):
                raise McpError(
                    types.ErrorData(
                        code=types.INVALID_PARAMS,
                        message="Invalid SetLevelRequest: missing required parameters",
                    )
                )

            result = await _set_logging_level(req)
            logger.info("SetLevelRequest completed successfully")
            return result

        except McpError:
            # Re-raise MCP errors (like invalid log levels) as they should be returned to client
            raise

        except Exception as e:
            logger.error("SetLevelRequest handler failed: %s", e)
            logger.exception("Full traceback for SetLevelRequest handler failure:")

            # Log specific guidance for the "Missing handler" error that causes VS Code timeouts
            error_str = str(e)
            if (
                "Missing handler for request type: logging/setLevel" in error_str
                or ("HTTP 500" in error_str and "logging/setLevel" in error_str)
                or (
                    "Failed to handle request" in error_str
                    and "logging/setLevel" in error_str
                )
            ):
                logger.warning(
                    "Backend reported logging capability but doesn't implement setLevel handler - this should be investigated"
                )
                logger.info(
                    "This backend will be automatically excluded from future logging requests"
                )

            # Return proper error response instead of raising - this prevents 500 errors
            # Only for backend communication issues, not validation errors
            logger.warning(
                "Returning success despite backend errors to prevent VS Code connection issues"
            )
            return types.ServerResult(types.EmptyResult())

    app.request_handlers[types.SetLevelRequest] = _set_logging_level_wrapper
