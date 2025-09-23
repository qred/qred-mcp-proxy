"""Create an MCP server that proxies requests through an MCP client.

This server is created independent of any transport mechanism.
"""

import typing as t

from mcp import server, types
from mcp.client.session import ClientSession
from mcp.shared.exceptions import McpError

from ..utils.logger import logger


async def create_proxy_server(
    remote_app: ClientSession,
) -> server.Server[object]:
    """Create a server instance from a remote app."""
    logger.debug("Sending initialization request to remote MCP server...")
    response = await remote_app.initialize()
    capabilities = response.capabilities

    logger.debug("Configuring proxied MCP server...")
    app: server.Server[object] = server.Server(name=response.serverInfo.name)

    if capabilities.prompts:
        logger.debug("Capabilities: adding Prompts...")

        async def _list_prompts(_: t.Any) -> types.ServerResult:
            result = await remote_app.list_prompts()
            return types.ServerResult(result)

        app.request_handlers[types.ListPromptsRequest] = _list_prompts

        async def _get_prompt(req: types.GetPromptRequest) -> types.ServerResult:
            result = await remote_app.get_prompt(req.params.name, req.params.arguments)
            return types.ServerResult(result)

        app.request_handlers[types.GetPromptRequest] = _get_prompt

    if capabilities.resources:
        logger.debug("Capabilities: adding Resources...")

        async def _list_resources(_: t.Any) -> types.ServerResult:
            result = await remote_app.list_resources()
            return types.ServerResult(result)

        app.request_handlers[types.ListResourcesRequest] = _list_resources

        async def _list_resource_templates(
            _: t.Any,
        ) -> types.ServerResult:
            result = await remote_app.list_resource_templates()
            return types.ServerResult(result)

        app.request_handlers[types.ListResourceTemplatesRequest] = (
            _list_resource_templates
        )

        async def _read_resource(req: types.ReadResourceRequest) -> types.ServerResult:
            result = await remote_app.read_resource(req.params.uri)
            return types.ServerResult(result)

        app.request_handlers[types.ReadResourceRequest] = _read_resource

    if capabilities.logging:
        logger.debug("Capabilities: adding Logging...")

        async def _set_logging_level(req: types.SetLevelRequest) -> types.ServerResult:
            def _validate_log_level(level: str) -> str:
                """Validate log level according to MCP specification (RFC 5424)."""
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

                # Case-sensitive validation per MCP spec
                if level not in valid_levels:
                    raise McpError(
                        types.ErrorData(
                            code=types.INVALID_PARAMS,
                            message=f"Invalid log level: {level}. Valid levels: {sorted(valid_levels)}",
                        )
                    )
                return level

            try:
                # Gracefully handle requests during session initialization
                logger.debug("SetLevelRequest received - processing gracefully")

                # Validate request structure before processing
                if not hasattr(req, "params"):
                    logger.debug(
                        "SetLevelRequest missing 'params' attribute - returning error per MCP spec"
                    )
                    raise McpError(
                        types.ErrorData(
                            code=types.INVALID_PARAMS,
                            message="SetLevelRequest missing required 'params' field",
                        )
                    )

                if not hasattr(req.params, "level"):
                    logger.debug(
                        "SetLevelRequest.params missing 'level' attribute - returning error per MCP spec"
                    )
                    raise McpError(
                        types.ErrorData(
                            code=types.INVALID_PARAMS,
                            message="SetLevelRequest missing required 'level' field",
                        )
                    )

                # Additional validation: check if level is None
                if req.params.level is None:
                    logger.debug(
                        "SetLevelRequest.params.level is None - returning error per MCP spec"
                    )
                    raise McpError(
                        types.ErrorData(
                            code=types.INVALID_PARAMS,
                            message="SetLevelRequest 'level' field cannot be null",
                        )
                    )

                # Validate log level according to MCP spec
                level_str = _validate_log_level(req.params.level)

                logger.debug("Setting logging level to: %s", level_str)
                await remote_app.set_logging_level(
                    req.params.level
                )  # Use original level for backend call
                return types.ServerResult(types.EmptyResult())

            except McpError:
                # Re-raise MCP validation errors
                raise

            except Exception as e:
                # Log more specific error information for debugging
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
                        "Backend doesn't implement setLevel handler despite claiming logging support"
                    )
                else:
                    logger.debug("SetLevelRequest failed: %s", e)

                # Always return success to avoid client errors during backend communication issues
                logger.debug("Returning success to prevent client connection issues")
                return types.ServerResult(types.EmptyResult())

        app.request_handlers[types.SetLevelRequest] = _set_logging_level

    if capabilities.resources:
        logger.debug("Capabilities: adding Resources...")

        async def _subscribe_resource(
            req: types.SubscribeRequest,
        ) -> types.ServerResult:
            await remote_app.subscribe_resource(req.params.uri)
            return types.ServerResult(types.EmptyResult())

        app.request_handlers[types.SubscribeRequest] = _subscribe_resource

        async def _unsubscribe_resource(
            req: types.UnsubscribeRequest,
        ) -> types.ServerResult:
            await remote_app.unsubscribe_resource(req.params.uri)
            return types.ServerResult(types.EmptyResult())

        app.request_handlers[types.UnsubscribeRequest] = _unsubscribe_resource

    if capabilities.tools:
        logger.debug("Capabilities: adding Tools...")

        async def _list_tools(_: t.Any) -> types.ServerResult:
            tools = await remote_app.list_tools()
            return types.ServerResult(tools)

        app.request_handlers[types.ListToolsRequest] = _list_tools

        async def _call_tool(req: types.CallToolRequest) -> types.ServerResult:
            try:
                result = await remote_app.call_tool(
                    req.params.name,
                    (req.params.arguments or {}),
                )
                return types.ServerResult(result)
            except Exception as e:
                return types.ServerResult(
                    types.CallToolResult(
                        content=[types.TextContent(type="text", text=str(e))],
                        isError=True,
                    ),
                )

        app.request_handlers[types.CallToolRequest] = _call_tool

    async def _send_progress_notification(req: types.ProgressNotification) -> None:
        await remote_app.send_progress_notification(
            req.params.progressToken,
            req.params.progress,
            req.params.total,
        )

    app.notification_handlers[types.ProgressNotification] = _send_progress_notification

    async def _complete(req: types.CompleteRequest) -> types.ServerResult:
        result = await remote_app.complete(
            req.params.ref,
            req.params.argument.model_dump(),
        )
        return types.ServerResult(result)

    app.request_handlers[types.CompleteRequest] = _complete

    return app
