"""Test configuration and fixtures for MCP Proxy tests."""

import pytest
import os
import tempfile
from unittest.mock import Mock, patch
from typing import Generator


@pytest.fixture
def mock_oauth_config():
    """Mock OAuth configuration for testing."""
    return {
        "web": {
            "client_id": "test-client-id.googleusercontent.com",
            "client_secret": "test-client-secret",
            "redirect_uris": [
                "https://claude.ai/api/mcp/auth_callback",
                "https://claude.com/api/mcp/auth_callback",
                "http://127.0.0.1:33418"
            ]
        }
    }


@pytest.fixture
def mock_mcp_servers_config():
    """Mock MCP servers configuration for testing."""
    return {
        "mcpServers": {
            "test-server-1": {
                "command": "python",
                "args": ["-m", "test_server"],
                "required_groups": ["test-group-1", "shared-group"]
            },
            "test-server-2": {
                "command": "node",
                "args": ["test-server.js"],
                "required_groups": ["test-group-2", "shared-group"]
            }
        }
    }


@pytest.fixture
def mock_env_vars(mock_oauth_config, tmp_path):
    """Mock environment variables for testing."""
    config_file = tmp_path / "mcp_servers.json"
    
    env_vars = {
        "GOOGLE_OAUTH": "{}",
        "MCP_SERVERS_CONFIG_PATH": str(config_file),
        "MCP_OAUTH_REFRESH_GROUPS_INTERVAL": "5",
        "MCP_OAUTH_REFRESH_USERS_INTERVAL": "10"
    }
    
    with patch.dict(os.environ, env_vars, clear=False):
        yield env_vars, config_file


@pytest.fixture
def mock_google_wif():
    """Mock Google WIF configuration for testing."""
    mock_wif = Mock()
    mock_wif.validate_oauth_token = Mock()
    mock_wif.validate_oauth_token_with_groups = Mock()
    mock_wif.check_user_groups = Mock()
    mock_wif.refresh_groups = Mock()
    mock_wif.clear_group_data = Mock()
    return mock_wif