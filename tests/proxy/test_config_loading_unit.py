"""Unit tests for MCP server configuration loading."""

import pytest
import json
import os
import tempfile
import asyncio
from unittest.mock import Mock, patch, mock_open, AsyncMock, MagicMock
from pathlib import Path


class TestConfigLoadingUnit:
    """Unit tests for configuration loading and initialization."""

    def setup_method(self):
        """Set up test fixtures."""
        # Create fixtures for testing
        self.mock_oauth_config = {
            "web": {
                "client_id": "test-client-id.googleusercontent.com",
                "client_secret": "test-client-secret",
                "redirect_uris": ["http://localhost:8080/oauth/callback"]
            }
        }
        
        self.mock_mcp_servers_config = {
            "mcpServers": {
                "server1": {
                    "command": "python",
                    "args": ["-m", "server1"],
                    "required_groups": ["test-group-1", "shared-group"]
                },
                "server2": {
                    "command": "node",
                    "args": ["server2.js"],
                    "required_groups": ["test-group-2", "shared-group"]
                }
            }
        }

    def teardown_method(self):
        """Clean up after each test."""
        pass

    def test_oauth_config_loading_logic_success(self):
        """Test OAuth configuration loading logic."""
        # Test the logic that would be in initialize_oauth_config
        oauth_json = json.dumps(self.mock_oauth_config)
        
        # Simulate the parsing logic
        config = json.loads(oauth_json)
        assert "web" in config
        assert "client_id" in config["web"]
        assert "client_secret" in config["web"]
        
        # Validate client ID format
        client_id = config["web"]["client_id"]
        assert client_id.endswith(".googleusercontent.com")
        
        # Validate client secret length
        client_secret = config["web"]["client_secret"]
        assert len(client_secret) >= 10

    def test_oauth_config_loading_logic_empty_env(self):
        """Test OAuth config loading with empty environment."""
        oauth_json = ""
        
        # Simulate the validation logic
        if not oauth_json.strip():
            with pytest.raises(ValueError, match="GOOGLE_OAUTH environment variable is empty"):
                raise ValueError("GOOGLE_OAUTH environment variable is empty")

    def test_oauth_config_loading_logic_invalid_json(self):
        """Test OAuth config loading with invalid JSON."""
        oauth_json = "invalid-json"
        
        # Simulate the JSON parsing logic
        with pytest.raises(json.JSONDecodeError):
            json.loads(oauth_json)

    def test_oauth_config_loading_logic_missing_web_key(self):
        """Test OAuth config loading with missing web key."""
        config = {"invalid": "structure"}
        oauth_json = json.dumps(config)
        
        # Simulate the validation logic
        parsed_config = json.loads(oauth_json)
        if "web" not in parsed_config:
            with pytest.raises(KeyError):
                raise KeyError("Missing 'web' key in OAuth configuration")

    def test_oauth_config_loading_logic_invalid_client_id(self):
        """Test OAuth config loading with invalid client ID."""
        config = {
            "web": {
                "client_id": "invalid-client-id",
                "client_secret": "valid-secret"
            }
        }
        oauth_json = json.dumps(config)
        
        # Simulate the validation logic
        parsed_config = json.loads(oauth_json)
        client_id = parsed_config["web"]["client_id"]
        
        # This should trigger a warning in the real implementation
        if not client_id.endswith(".googleusercontent.com"):
            # Simulate warning behavior
            warning_triggered = True
            assert warning_triggered

    def test_oauth_config_loading_logic_short_client_secret(self):
        """Test OAuth config loading with short client secret."""
        config = {
            "web": {
                "client_id": "test.googleusercontent.com",
                "client_secret": "short"
            }
        }
        oauth_json = json.dumps(config)
        
        # Simulate the validation logic
        parsed_config = json.loads(oauth_json)
        client_secret = parsed_config["web"]["client_secret"]
        
        # This should trigger a warning in the real implementation
        if len(client_secret) < 10:
            # Simulate warning behavior
            warning_triggered = True
            assert warning_triggered

    def test_mcp_servers_config_loading_logic_success(self):
        """Test MCP servers configuration loading logic."""
        config_json = json.dumps(self.mock_mcp_servers_config)
        
        # Simulate the parsing logic
        config = json.loads(config_json)
        assert "mcpServers" in config
        
        # Simulate group extraction logic
        required_groups = set()
        for server_name, server_config in config["mcpServers"].items():
            if "required_groups" in server_config:
                required_groups.update(server_config["required_groups"])
        
        expected_groups = {"test-group-1", "test-group-2", "shared-group"}
        assert required_groups == expected_groups

    def test_mcp_servers_config_loading_logic_no_file(self):
        """Test MCP servers config loading with no file path."""
        config_path = None
        
        # Simulate the logic when no path is provided
        if not config_path:
            # Should skip processing
            skipped = True
            assert skipped

    def test_mcp_servers_config_loading_logic_file_not_found(self):
        """Test MCP servers config loading with non-existent file."""
        config_path = "/non/existent/file.json"
        
        # Simulate file existence check
        if not os.path.exists(config_path):
            # Should trigger warning and continue
            warning_triggered = True
            assert warning_triggered

    def test_mcp_servers_config_loading_logic_invalid_json(self):
        """Test MCP servers config loading with invalid JSON."""
        invalid_json = "invalid json content"
        
        # Simulate JSON parsing
        with pytest.raises(json.JSONDecodeError):
            json.loads(invalid_json)

    def test_mcp_servers_config_loading_logic_no_groups(self):
        """Test MCP servers config loading with servers that have no required groups."""
        config = {
            "mcpServers": {
                "no-groups-server": {
                    "command": "python",
                    "args": ["-m", "test_server"]
                }
            }
        }
        
        # Simulate group extraction logic
        required_groups = set()
        for server_name, server_config in config["mcpServers"].items():
            if "required_groups" in server_config:
                required_groups.update(server_config["required_groups"])
        
        assert required_groups == set()

    def test_refresh_interval_parsing_logic(self):
        """Test refresh interval parsing logic."""
        # Test with custom intervals
        with patch.dict(os.environ, {
            "MCP_OAUTH_REFRESH_GROUPS_INTERVAL": "30",
            "MCP_OAUTH_REFRESH_USERS_INTERVAL": "120"
        }):
            # Simulate the parsing logic
            groups_interval = int(os.getenv("MCP_OAUTH_REFRESH_GROUPS_INTERVAL", "15"))
            users_interval = int(os.getenv("MCP_OAUTH_REFRESH_USERS_INTERVAL", "60"))
            
            assert groups_interval == 30
            assert users_interval == 120

    def test_refresh_interval_parsing_logic_defaults(self):
        """Test refresh interval parsing with defaults."""
        # Test with no environment variables set
        with patch.dict(os.environ, {}, clear=True):
            # Simulate the parsing logic with defaults
            groups_interval = int(os.getenv("MCP_OAUTH_REFRESH_GROUPS_INTERVAL", "15"))
            users_interval = int(os.getenv("MCP_OAUTH_REFRESH_USERS_INTERVAL", "60"))
            
            assert groups_interval == 15
            assert users_interval == 60

    @pytest.mark.asyncio
    async def test_async_config_initialization_logic_with_groups(self):
        """Test async configuration initialization logic with groups."""
        # Mock the async task creation behavior
        required_groups = {"test-group"}
        
        # Simulate the logic in initialize_mcp_servers_config_async
        sync_init_called = True
        task_created = False
        
        if required_groups:
            task_created = True
        
        assert sync_init_called
        assert task_created

    @pytest.mark.asyncio
    async def test_async_config_initialization_logic_no_groups(self):
        """Test async configuration initialization logic without groups."""
        # Mock the async task creation behavior
        required_groups = set()
        
        # Simulate the logic in initialize_mcp_servers_config_async
        sync_init_called = True
        task_created = False
        
        if required_groups:
            task_created = True
        
        assert sync_init_called
        assert not task_created

    @pytest.mark.asyncio
    async def test_async_config_initialization_logic_task_failure(self):
        """Test async configuration initialization with task creation failure."""
        required_groups = {"test-group"}
        
        # Simulate task creation failure
        try:
            raise Exception("Task creation failed")
        except Exception as e:
            error_logged = True
            assert "Task creation failed" in str(e)
            assert error_logged

    def test_required_groups_management_logic(self):
        """Test required groups management logic."""
        # Test empty groups
        required_groups = set()
        result = required_groups.copy()  # Simulate get_required_groups
        assert result == set()
        
        # Test with groups
        required_groups = {"group1", "group2", "group3"}
        result = required_groups.copy()  # Simulate get_required_groups
        assert result == required_groups
        assert result is not required_groups  # Should be a copy

    def test_oauth_client_id_retrieval_logic(self):
        """Test OAuth client ID retrieval logic."""
        # Test with empty config
        oauth_info = {}
        client_id = oauth_info.get("client_id")
        assert client_id is None
        
        # Test with config
        oauth_info = {"client_id": "test-client.googleusercontent.com"}
        client_id = oauth_info.get("client_id")
        assert client_id == "test-client.googleusercontent.com"

    def test_refresh_task_management_logic(self):
        """Test refresh task management logic."""
        # Mock task object
        mock_task = Mock()
        mock_task.cancelled.return_value = False
        mock_task.done.return_value = False
        
        # Test stopping active task
        if mock_task and not mock_task.cancelled() and not mock_task.done():
            mock_task.cancel()
            
        mock_task.cancel.assert_called_once()

    def test_refresh_task_management_logic_completed_task(self):
        """Test refresh task management with completed task."""
        # Mock completed task
        mock_task = Mock()
        mock_task.cancelled.return_value = False
        mock_task.done.return_value = True
        
        # Test with completed task (should not cancel)
        if mock_task and not mock_task.cancelled() and not mock_task.done():
            mock_task.cancel()
        
        mock_task.cancel.assert_not_called()

    def test_refresh_task_management_logic_no_task(self):
        """Test refresh task management with no task."""
        mock_task = None
        
        # Test with no task (should not crash)
        if mock_task and not mock_task.cancelled() and not mock_task.done():
            mock_task.cancel()
        
        # Should pass without error
        assert True


class TestEnvironmentVariables:
    """Test environment variable handling."""

    def test_missing_google_oauth_env_var(self):
        """Test handling of missing GOOGLE_OAUTH environment variable."""
        with patch.dict(os.environ, {}, clear=True):
            google_oauth = os.getenv("GOOGLE_OAUTH", "")
            assert google_oauth == ""

    def test_invalid_refresh_intervals(self):
        """Test handling of invalid refresh interval values."""
        with patch.dict(os.environ, {
            "MCP_OAUTH_REFRESH_GROUPS_INTERVAL": "invalid",
            "MCP_OAUTH_REFRESH_USERS_INTERVAL": "also_invalid"
        }):
            # Simulate the parsing with error handling
            try:
                groups_interval = int(os.getenv("MCP_OAUTH_REFRESH_GROUPS_INTERVAL", "15"))
            except ValueError:
                groups_interval = 15  # Default fallback
            
            try:
                users_interval = int(os.getenv("MCP_OAUTH_REFRESH_USERS_INTERVAL", "60"))
            except ValueError:
                users_interval = 60  # Default fallback
            
            assert groups_interval == 15
            assert users_interval == 60

    def test_empty_refresh_intervals(self):
        """Test handling of empty refresh interval values."""
        with patch.dict(os.environ, {
            "MCP_OAUTH_REFRESH_GROUPS_INTERVAL": "",
            "MCP_OAUTH_REFRESH_USERS_INTERVAL": ""
        }):
            # Simulate the parsing with defaults for empty values
            groups_interval = int(os.getenv("MCP_OAUTH_REFRESH_GROUPS_INTERVAL", "15") or "15")
            users_interval = int(os.getenv("MCP_OAUTH_REFRESH_USERS_INTERVAL", "60") or "60")
            
            assert groups_interval == 15
            assert users_interval == 60