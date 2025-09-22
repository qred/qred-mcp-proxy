import logging
import sys
import os
from pathlib import Path

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
    
    # Update the keep-alive logger  
    keepalive_logger.setLevel(level)
    for handler in keepalive_logger.handlers:
        handler.setLevel(level)
    
    # Log the change
    logger.info("Logger debug mode %s - all loggers set to %s level", 
                "enabled" if debug else "disabled", 
                "DEBUG" if debug else "INFO")

## Set up default logger ##

# Determine initial log level from environment variables
if os.getenv('DEBUG_MODE', 'false') == 'true':
  loglevel = logging.DEBUG
else:
  env_level = os.getenv('LOGLEVEL', 'INFO').upper()
  loglevel = getattr(logging, env_level) if env_level in ['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'] else logging.INFO

logger = logging.getLogger()
logger.setLevel(loglevel)

# Create a handler for stdout
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(loglevel)

# Create a formatter and set it for the handler
formatter = logging.Formatter('%(levelname)s - %(message)s')
stdout_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(stdout_handler)

## Set up dedicated keep-alive logger ##
keepalive_logger = logging.getLogger('keepalive')
keepalive_logger.setLevel(loglevel)

# Ensure the log directory exists
keepalive_log_dir = Path(os.getenv('LOG_DIR', '/app/keepalive'))
keepalive_log_dir.mkdir(parents=True, exist_ok=True)

# Create a file handler for keep-alive logs
keepalive_file_handler = logging.FileHandler(keepalive_log_dir / 'keepalive.log')
keepalive_file_handler.setLevel(loglevel)

# Create a detailed formatter for the keep-alive log file
keepalive_formatter = logging.Formatter('%(asctime)s - KEEP_ALIVE_LOG - %(levelname)s - %(message)s')
keepalive_file_handler.setFormatter(keepalive_formatter)

# Add the file handler to the keep-alive logger
keepalive_logger.addHandler(keepalive_file_handler)

# Add console handler to ensure keep-alive logs go to console regardless
keepalive_console_handler = logging.StreamHandler()
keepalive_console_handler.setLevel(loglevel)
keepalive_console_formatter = logging.Formatter('%(asctime)s - KEEP_ALIVE - %(levelname)s - %(message)s')
keepalive_console_handler.setFormatter(keepalive_console_formatter)
keepalive_logger.addHandler(keepalive_console_handler)

# Prevent keep-alive logs from propagating to the root logger to avoid duplication
keepalive_logger.propagate = False