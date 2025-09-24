import logging
import os
import sys


def set_debug_mode(debug: bool) -> None:
    """Set debug mode for all loggers based on the --debug CLI flag.

    This function dynamically updates the log level of all loggers (main, keepalive)
    to either DEBUG or INFO based on the debug parameter. This allows the --debug CLI
    argument to control the verbosity of all logging output.

    Args:
        debug: True to enable DEBUG level logging, False for INFO level logging
    """
    level = logging.DEBUG if debug else logging.INFO

    # Update the root logger
    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(level)

    # Log the change
    logger.info(
        "Logger debug mode %s - all loggers set to %s level",
        "enabled" if debug else "disabled",
        "DEBUG" if debug else "INFO",
    )


## Set up default logger ##

# Determine initial log level from environment variables
if os.getenv("DEBUG_MODE", "false") == "true":
    loglevel = logging.DEBUG
else:
    env_level = os.getenv("LOGLEVEL", "INFO").upper()
    loglevel = (
        getattr(logging, env_level)
        if env_level in ["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"]
        else logging.INFO
    )

logger = logging.getLogger("mcp-oauth")
logger.setLevel(loglevel)
logger.propagate = False  # Prevent double logging by uvicorn

# Create a handler for stdout
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(loglevel)

# Create a formatter and set it for the handler
formatter = logging.Formatter("%(levelname)s - %(message)s")
stdout_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(stdout_handler)
