"""Main entry point for MCP OAuth service."""

import argparse
import os
import sys
import logging
import uvicorn
from importlib.metadata import version

from .server import app, initialize_oauth_config, initialize_mcp_servers_config
from .utils.logger import logger


def _setup_argument_parser() -> argparse.ArgumentParser:
    """Set up and return the argument parser for the MCP OAuth service."""
    try:
        package_version = version("mcp-oauth")
    except Exception:
        package_version = "0.1.0"

    parser = argparse.ArgumentParser(
        description="MCP OAuth 2.1 service with Dynamic Client Registration support",
        epilog=(
            "Examples:\n"
            "  mcp-oauth --port 8080 --host 0.0.0.0\n"
            "  mcp-oauth --debug\n"
            "  GOOGLE_OAUTH='{...}' mcp-oauth --port 8443\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {package_version}",
        help="Show the version and exit",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=8001,
        help="Port to run the OAuth service on. Default is 8001",
    )

    parser.add_argument(
        "--host",
        default="0.0.0.0",  # nosec B104 - Required for containerized service
        help="Host to run the OAuth service on. Default is 0.0.0.0",
    )

    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default="info",
        help="Logging level. Default is info",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode (equivalent to --log-level debug)",
    )

    parser.add_argument(
        "--mcp-servers-config-path",
        default=None,
        help="Path to MCP servers configuration file for group pre-loading. Default is from MCP_SERVERS_CONFIG_PATH env var",
    )

    parser.add_argument(
        "--refresh-groups-interval",
        type=int,
        default=15,
        help="Group refresh interval in minutes. Default is 15 minutes",
    )

    parser.add_argument(
        "--refresh-users-interval",
        type=int,
        default=60,
        help="User refresh interval in minutes. Default is 60 minutes",
    )

    return parser


def main() -> None:
    """Main entry point for the MCP OAuth service."""
    parser = _setup_argument_parser()
    args = parser.parse_args()

    # Handle debug flag
    if args.debug:
        log_level = "debug"
    else:
        log_level = args.log_level

    # Override with environment variables if present
    host = os.getenv("HOST", args.host)
    port = int(os.getenv("PORT", args.port))
    log_level = os.getenv("LOG_LEVEL", log_level).lower()
    mcp_servers_config_path = os.getenv(
        "MCP_SERVERS_CONFIG_PATH", args.mcp_servers_config_path
    )
    refresh_groups_interval = int(
        os.getenv("MCP_OAUTH_REFRESH_GROUPS_INTERVAL", args.refresh_groups_interval)
    )
    refresh_users_interval = int(
        os.getenv("MCP_OAUTH_REFRESH_USERS_INTERVAL", args.refresh_users_interval)
    )

    # Set configuration in environment for the server module to use
    if mcp_servers_config_path:
        os.environ["MCP_SERVERS_CONFIG_PATH"] = mcp_servers_config_path
    os.environ["MCP_OAUTH_REFRESH_GROUPS_INTERVAL"] = str(refresh_groups_interval)
    os.environ["MCP_OAUTH_REFRESH_USERS_INTERVAL"] = str(refresh_users_interval)

    # Initialize OAuth configuration from environment
    try:
        initialize_oauth_config()
    except Exception as e:
        logger.error(f"Failed to initialize OAuth configuration: {e}")
        logger.error(
            "Make sure GOOGLE_OAUTH environment variable is set with valid JSON"
        )
        sys.exit(1)

    # Initialize MCP servers configuration and pre-load group memberships
    try:
        initialize_mcp_servers_config()
    except Exception as e:
        logger.warning(f"Failed to initialize MCP servers configuration: {e}")
        logger.warning(
            "Group pre-loading will be skipped - this may impact performance"
        )

    # Configure httpx logging to prevent access token leakage
    # Set httpx logger to WARNING level to avoid logging request URLs with tokens
    httpx_logger = logging.getLogger("httpx")
    httpx_logger.setLevel(logging.WARNING)

    logger.info(f"Starting MCP OAuth service on {host}:{port}")
    logger.info(f"Log level: {log_level}")
    logger.info("HTTPX request logging disabled to prevent token leakage")

    # Start the server
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level,
        access_log=log_level.lower() == "debug",  # Only show access logs in DEBUG mode
    )


if __name__ == "__main__":
    main()
