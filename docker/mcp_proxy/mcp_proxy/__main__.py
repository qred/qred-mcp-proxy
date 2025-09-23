"""The entry point for the mcp-proxy application. It sets up the logging and runs the main function.

Two ways to run the application:
1. Run the application as a module `uv run -m mcp_proxy`
2. Run the application directly with `mcp-proxy`

"""

import argparse
import asyncio
import json
import os
import shlex
import sys
import typing as t
from importlib.metadata import version

from mcp.client.stdio import StdioServerParameters

from .utils.config_loader import load_named_server_configs_from_file, ServerParameters
from .server.mcp_server import MCPServerSettings, run_mcp_server
from .utils.logger import logger, set_debug_mode

# Deprecated env var. Here for backwards compatibility.
SSE_URL: t.Final[str | None] = os.getenv(
    "SSE_URL",
    None,
)


def _setup_argument_parser() -> argparse.ArgumentParser:
    """Set up and return the argument parser for the MCP proxy."""
    parser = argparse.ArgumentParser(
        description=("Start the MCP proxy server with aggregated backend support and OAuth 2.1 authentication."),
        epilog=(
            "Examples:\n"
            "  mcp-proxy --named-server-config config/servers.json --port 8080 --google-auth-required\n"
            "  mcp-proxy --named-server fetch 'uvx mcp-server-fetch' --port 8080\n"
            "  mcp-proxy --named-server posthog 'mcp-remote http://posthog:8000' --port 8080\n"
            "  mcp-proxy your-command --port 8080 -e KEY VALUE\n"
            "  mcp-proxy your-command --port 8080 --allow-origin='*'\n"
            "  mcp-proxy --no-aggregated your-command --port 8080  # Use legacy single-backend mode\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    _add_arguments_to_parser(parser)
    return parser


def _add_arguments_to_parser(parser: argparse.ArgumentParser) -> None:
    """Add all arguments to the argument parser."""
    try:
        package_version = version("mcp-proxy")
    except Exception:  # noqa: BLE001
        package_version = "unknown"

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {package_version}",
        help="Show the version and exit",
    )

    parser.add_argument(
        "command_or_url",
        help=(
            "Command or URL to connect to. When a URL, will run an SSE/StreamableHTTP client. "
            "Otherwise, if --named-server is not used, this will be the command "
            "for the default stdio client. If --named-server is used, this argument "
            "is ignored for stdio mode unless no default server is desired. "
            "See corresponding options for more details."
        ),
        nargs="?",
        default=SSE_URL,
    )

    client_group = parser.add_argument_group("SSE/StreamableHTTP client options")
    client_group.add_argument(
        "-H",
        "--headers",
        nargs=2,
        action="append",
        metavar=("KEY", "VALUE"),
        help="Headers to pass to the SSE server. Can be used multiple times.",
        default=[],
    )
    client_group.add_argument(
        "--transport",
        choices=["sse", "streamablehttp"],
        default="sse",  # For backwards compatibility
        help="The transport to use for the client. Default is SSE.",
    )

    stdio_client_options = parser.add_argument_group("stdio client options")
    stdio_client_options.add_argument(
        "args",
        nargs="*",
        help=(
            "Any extra arguments to the command to spawn the default server. "
            "Ignored if only named servers are defined."
        ),
    )
    stdio_client_options.add_argument(
        "-e",
        "--env",
        nargs=2,
        action="append",
        metavar=("KEY", "VALUE"),
        help=(
            "Environment variables used when spawning the default server. Can be "
            "used multiple times. For named servers, environment is inherited or "
            "passed via --pass-environment."
        ),
        default=[],
    )
    stdio_client_options.add_argument(
        "--cwd",
        default=None,
        help=(
            "The working directory to use when spawning the default server process. "
            "Named servers inherit the proxy's CWD."
        ),
    )
    stdio_client_options.add_argument(
        "--pass-environment",
        action=argparse.BooleanOptionalAction,
        help="Pass through all environment variables when spawning all server processes.",
        default=False,
    )
    stdio_client_options.add_argument(
        "--debug",
        action=argparse.BooleanOptionalAction,
        help="Enable debug mode with detailed logging output.",
        default=False,
    )
    stdio_client_options.add_argument(
        "--named-server",
        action="append",
        nargs=2,
        metavar=("NAME", "COMMAND_STRING"),
        help=(
            "Define a named stdio server. NAME is for the URL path /servers/NAME/. "
            "COMMAND_STRING is a single string with the command and its arguments "
            "(e.g., 'uvx mcp-server-fetch --timeout 10'). "
            "These servers inherit the proxy's CWD and environment from --pass-environment."
        ),
        default=[],
        dest="named_server_definitions",
    )
    stdio_client_options.add_argument(
        "--named-server-config",
        type=str,
        default=None,
        metavar="FILE_PATH",
        help=(
            "Path to a JSON configuration file for named stdio servers. "
            "If provided, this will be the exclusive source for named server definitions, "
            "and any --named-server CLI arguments will be ignored."
        ),
    )

    mcp_server_group = parser.add_argument_group("SSE server options")
    mcp_server_group.add_argument(
        "--port",
        type=int,
        default=0,
        help="Port to expose an SSE server on. Default is a random port",
    )
    mcp_server_group.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to expose an SSE server on. Default is 127.0.0.1",
    )
    mcp_server_group.add_argument(
        "--stateless",
        action=argparse.BooleanOptionalAction,
        help="Enable stateless mode for streamable http transports. Default is False",
        default=False,
    )
    mcp_server_group.add_argument(
        "--sse-port",
        type=int,
        default=0,
        help="(deprecated) Same as --port",
    )
    mcp_server_group.add_argument(
        "--sse-host",
        default="127.0.0.1",
        help="(deprecated) Same as --host",
    )
    mcp_server_group.add_argument(
        "--allow-origin",
        nargs="+",
        default=[],
        help=(
            "Allowed origins for the SSE server. Can be used multiple times. "
            "Default is no CORS allowed."
        ),
    )
    mcp_server_group.add_argument(
        "--google-auth-required",
        action=argparse.BooleanOptionalAction,
        help="Require Google Workspace user authentication for MCP endpoints. Default is False",
        default=False,
    )
    mcp_server_group.add_argument(
        "--aggregated",
        action=argparse.BooleanOptionalAction,
        help="Run in aggregated mode (single server with all tools). Default is True",
        default=True,
    )


def _handle_sse_client_mode(
    args_parsed: argparse.Namespace,
) -> None:
    """Handle SSE/StreamableHTTP client mode - removed in this version."""
    logger.error("SSE/StreamableHTTP client mode has been removed in this version.")
    logger.error("This version focuses on aggregated server mode for better enterprise deployment.")
    logger.error("To run in server mode, remove the URL argument and use --named-server-config or --named-server arguments with --no-aggregated flag.")
    sys.exit(1)


def _configure_default_server(
    args_parsed: argparse.Namespace,
    base_env: dict[str, str],
) -> StdioServerParameters | None:
    """Configure the default server if applicable."""
    if not (
        args_parsed.command_or_url
        and not args_parsed.command_or_url.startswith(("http://", "https://"))
    ):
        return None

    default_server_env = base_env.copy()
    default_server_env.update(dict(args_parsed.env))  # Specific env vars for default server

    default_stdio_params = StdioServerParameters(
        command=args_parsed.command_or_url,
        args=args_parsed.args,
        env=default_server_env,
        cwd=args_parsed.cwd if args_parsed.cwd else None,
    )
    logger.info(
        "Configured default server: %s %s",
        args_parsed.command_or_url,
        " ".join(args_parsed.args),
    )
    return default_stdio_params


def _load_named_servers_from_config(
    config_path: str,
    base_env: dict[str, str],
) -> tuple[dict[str, ServerParameters], dict[str, list[str]], dict[str, list[str]]]:
    """Load named server configurations from a file."""
    try:
        return load_named_server_configs_from_file(config_path, base_env)
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        # Specific errors are already logged by the loader function
        # We log a generic message here before exiting
        logger.exception(
            "Failed to load server configurations from %s. Exiting.",
            config_path,
        )
        sys.exit(1)
    except Exception:  # Catch any other unexpected errors from loader
        logger.exception(
            "An unexpected error occurred while loading server configurations from %s. Exiting.",
            config_path,
        )
        sys.exit(1)


def _configure_named_servers_from_cli(
    named_server_definitions: list[tuple[str, str]],
    base_env: dict[str, str],
) -> dict[str, StdioServerParameters]:
    """Configure named servers from CLI arguments."""
    named_stdio_params: dict[str, StdioServerParameters] = {}

    for name, command_string in named_server_definitions:
        try:
            command_parts = shlex.split(command_string)
            if not command_parts:  # Handle empty command_string
                logger.error("Empty COMMAND_STRING for named server '%s'. Skipping.", name)
                continue

            command = command_parts[0]
            command_args = command_parts[1:]
            # Named servers inherit base_env (which includes passed-through env)
            # and use the proxy's CWD.
            named_stdio_params[name] = StdioServerParameters(
                command=command,
                args=command_args,
                env=base_env.copy(),  # Each named server gets a copy of the base env
                cwd=None,  # Named servers run in the proxy's CWD
            )
            logger.info("Configured named server '%s': %s", name, command_string)
        except IndexError:  # Should be caught by the check for empty command_parts
            logger.exception(
                "Invalid COMMAND_STRING for named server '%s': '%s'. Must include a command.",
                name,
                command_string,
            )
            sys.exit(1)
        except Exception:
            logger.exception("Error parsing COMMAND_STRING for named server '%s'", name)
            sys.exit(1)

    return named_stdio_params


def _create_mcp_settings(args_parsed: argparse.Namespace) -> MCPServerSettings:
    """Create MCP server settings from parsed arguments."""
    return MCPServerSettings(
        bind_host=args_parsed.host if args_parsed.host is not None else args_parsed.sse_host,
        port=args_parsed.port if args_parsed.port is not None else args_parsed.sse_port,
        stateless=args_parsed.stateless,
        allow_origins=args_parsed.allow_origin if len(args_parsed.allow_origin) > 0 else None,
        log_level="DEBUG" if args_parsed.debug else "INFO",
        google_auth_required=args_parsed.google_auth_required,
        aggregated_mode=args_parsed.aggregated,
    )


def main() -> None:
    """Start the client using asyncio."""
    parser = _setup_argument_parser()
    args_parsed = parser.parse_args()
    
    # Configure logger debug mode based on CLI argument
    set_debug_mode(args_parsed.debug)

    # Validate required arguments
    if (
        not args_parsed.command_or_url
        and not args_parsed.named_server_definitions
        and not args_parsed.named_server_config
    ):
        parser.print_help()
        logger.error(
            "Either a command_or_url for a default server or at least one --named-server "
            "(or --named-server-config) must be provided for stdio mode.",
        )
        sys.exit(1)

    # Handle SSE client mode if URL is provided
    if args_parsed.command_or_url and args_parsed.command_or_url.startswith(
        ("http://", "https://"),
    ):
        _handle_sse_client_mode(args_parsed)
        return

    # Start stdio client(s) and expose as an SSE server
    logger.debug("Configuring stdio client(s) and SSE server")

    # Base environment for all spawned processes
    base_env: dict[str, str] = {}
    if args_parsed.pass_environment:
        base_env.update(os.environ)

    # Configure default server
    default_stdio_params = _configure_default_server(args_parsed, base_env)

    # Configure named servers
    named_server_params: dict[str, ServerParameters] = {}
    # Load named servers and excluded tools configuration
    excluded_tools_config = {}
    required_groups_config = {}
    
    if args_parsed.named_server_config:
        if args_parsed.named_server_definitions:
            logger.warning(
                "--named-server CLI arguments are ignored when --named-server-config is provided.",
            )
        named_server_params, excluded_tools_config, required_groups_config = _load_named_servers_from_config(
            args_parsed.named_server_config,
            base_env,
        )
    elif args_parsed.named_server_definitions:
        stdio_params = _configure_named_servers_from_cli(
            args_parsed.named_server_definitions,
            base_env,
        )
        # Convert to ServerParameters dict - these are all STDIO parameters
        named_server_params = dict(stdio_params)

    # Ensure at least one server is configured
    if not default_stdio_params and not named_server_params:
        parser.print_help()
        logger.error(
            "No stdio servers configured. Provide a default command or use --named-server.",
        )
        sys.exit(1)

    # Create MCP server settings and run the server
    mcp_settings = _create_mcp_settings(args_parsed)
    asyncio.run(
        run_mcp_server(
            default_server_params=default_stdio_params,
            named_server_params=named_server_params,
            mcp_settings=mcp_settings,
            excluded_tools=excluded_tools_config,
            required_groups=required_groups_config,
        ),
    )


if __name__ == "__main__":
    main()