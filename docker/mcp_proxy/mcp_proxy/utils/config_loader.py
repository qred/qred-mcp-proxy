"""Configuration loader for MCP proxy.

This module provides functionality to load named server configurations from JSON files.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from mcp.client.stdio import StdioServerParameters

from .logger import logger


@dataclass
class HttpServerParameters:
    """Parameters for HTTP-based MCP servers."""

    url: str
    headers: dict[str, str] | None = None


# Union type for different server parameter types
ServerParameters: TypeAlias = StdioServerParameters | HttpServerParameters


def load_named_server_configs_from_file(
    config_file_path: str,
    base_env: dict[str, str],
) -> tuple[dict[str, ServerParameters], dict[str, list[str]], dict[str, list[str]]]:
    """Loads named server configurations from a JSON file.

    Args:
        config_file_path: Path to the JSON configuration file.
        base_env: The base environment dictionary to be inherited by servers.

    Returns:
        A tuple of (named_server_parameters, excluded_tools_mapping, required_groups_mapping).

    Raises:
        FileNotFoundError: If the config file is not found.
        json.JSONDecodeError: If the config file contains invalid JSON.
        ValueError: If the config file format is invalid.
    """
    named_server_params: dict[str, ServerParameters] = {}
    excluded_tools: dict[str, list[str]] = {}
    required_groups: dict[str, list[str]] = {}
    logger.info("Loading named server configurations from: %s", config_file_path)

    try:
        with Path(config_file_path).open() as f:
            config_data = json.load(f)
    except FileNotFoundError:
        logger.exception("Configuration file not found: %s", config_file_path)
        raise
    except json.JSONDecodeError:
        logger.exception(
            "Error decoding JSON from configuration file: %s", config_file_path
        )
        raise
    except Exception as e:
        logger.exception(
            "Unexpected error opening or reading configuration file %s",
            config_file_path,
        )
        error_message = f"Could not read configuration file: {e}"
        raise ValueError(error_message) from e

    if not isinstance(config_data, dict) or "mcpServers" not in config_data:
        msg = f"Invalid config file format in {config_file_path}. Missing 'mcpServers' key."
        logger.error(msg)
        raise ValueError(msg)

    for name, server_config in config_data.get("mcpServers", {}).items():
        if not isinstance(server_config, dict):
            logger.warning(
                "Skipping invalid server config for '%s' in %s. Entry is not a dictionary.",
                name,
                config_file_path,
            )
            continue
        if not server_config.get(
            "enabled", True
        ):  # Default to True if 'enabled' is not present
            logger.info("Named server '%s' from config is not enabled. Skipping.", name)
            continue

        # Extract common configuration
        excluded_tool_patterns = server_config.get("excluded_tools", [])
        required_group_patterns = server_config.get("required_groups", [])
        transport_type = server_config.get("transportType", "stdio").lower()

        # Validate excluded_tools format
        if excluded_tool_patterns:
            if not isinstance(excluded_tool_patterns, list):
                logger.warning(
                    "Named server '%s' from config has invalid 'excluded_tools' (must be a list of strings). Ignoring.",
                    name,
                )
                excluded_tool_patterns = []
            else:
                # Ensure all patterns are strings
                excluded_tool_patterns = [str(p) for p in excluded_tool_patterns]
                excluded_tools[name] = excluded_tool_patterns
                logger.info(
                    "Named server '%s' configured with %d excluded tool patterns: %s",
                    name,
                    len(excluded_tool_patterns),
                    excluded_tool_patterns,
                )

        # Validate required_groups format
        if required_group_patterns:
            if not isinstance(required_group_patterns, list):
                logger.warning(
                    "Named server '%s' from config has invalid 'required_groups' (must be a list of strings). Ignoring.",
                    name,
                )
                required_group_patterns = []
            else:
                # Ensure all patterns are strings
                required_group_patterns = [str(p) for p in required_group_patterns]
                required_groups[name] = required_group_patterns
                logger.info(
                    "Named server '%s' configured with %d required groups: %s",
                    name,
                    len(required_group_patterns),
                    required_group_patterns,
                )

        # Handle different transport types
        if transport_type == "http":
            # HTTP transport configuration
            url = server_config.get("url")
            if not url:
                logger.warning(
                    "Named server '%s' from config has transportType 'http' but missing 'url'. Skipping.",
                    name,
                )
                continue

            headers = server_config.get("headers", {})
            if not isinstance(headers, dict):
                logger.warning(
                    "Named server '%s' from config has invalid 'headers' (must be a dict). Using empty headers.",
                    name,
                )
                headers = {}

            named_server_params[name] = HttpServerParameters(
                url=url,
                headers=headers,
            )
            logger.info(
                "Configured named HTTP server '%s' from config: %s",
                name,
                url,
            )

        else:
            # STDIO transport configuration (default)
            command = server_config.get("command")
            command_args = server_config.get("args", [])
            env = server_config.get("env", {})

            if not command:
                logger.warning(
                    "Named server '%s' from config is missing 'command'. Skipping.",
                    name,
                )
                continue
            if not isinstance(command_args, list):
                logger.warning(
                    "Named server '%s' from config has invalid 'args' (must be a list). Skipping.",
                    name,
                )
                continue

            new_env = base_env.copy()
            new_env.update(env)

            named_server_params[name] = StdioServerParameters(
                command=command,
                args=command_args,
                env=new_env,
                cwd=None,
            )
            logger.info(
                "Configured named STDIO server '%s' from config: %s %s",
                name,
                command,
                " ".join(command_args),
            )

    return named_server_params, excluded_tools, required_groups
