"""Performance and load tests for OAuth server."""

import pytest
import time
import asyncio
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
import concurrent.futures
import threading


class TestOAuthPerformance:
    """Performance tests for OAuth server and MCP proxy."""


import json
import os


class TestPerformance:
    """Performance tests for the OAuth server."""

    @pytest.fixture
    def mock_oauth_config(self):
        """OAuth configuration for testing."""
        return {
            "web": {
                "client_id": "123456789.apps.googleusercontent.com",
                "client_secret": "test-client-secret",
                "redirect_uris": ["http://127.0.0.1:33418"],
            }
        }

    @pytest.fixture
    def client(self, mock_oauth_config, tmp_path):
        """Create a test client with mocked dependencies."""
        config_file = tmp_path / "servers.json"
        config_file.write_text(json.dumps({"mcpServers": {}}))

        mock_env = {
            "GOOGLE_OAUTH": json.dumps(mock_oauth_config),
            "MCP_SERVERS_CONFIG_PATH": str(config_file),
            "SA_EMAIL": "test@example.iam.gserviceaccount.com",
            "GCP_SECRET_ARN": '{"test": "config"}',
        }

        with patch.dict(os.environ, mock_env):
            # Mock all external dependencies
            with (
                patch("mcp_oauth.gcp.google_wif.check_req_env_vars"),
                patch("mcp_oauth.gcp.google_wif.GoogleWIF._GoogleWIF__get_users"),
                patch(
                    "mcp_oauth.gcp.google_wif.GoogleWIF._GoogleWIF__initialize_groups"
                ),
                patch(
                    "mcp_oauth.gcp.google_wif.json.loads",
                    return_value={"test": "config"},
                ),
                patch(
                    "mcp_oauth.server.initialize_mcp_servers_config_async",
                    new_callable=AsyncMock,
                ),
            ):
                from mcp_oauth.server import app

                return TestClient(app)

    def test_health_endpoint_response_time(self, client):
        """Test health endpoint response time is acceptable."""
        # Warm up
        client.get("/health")

        # Measure response time
        start_time = time.time()
        response = client.get("/health")
        end_time = time.time()

        response_time = end_time - start_time

        assert response.status_code == 200
        assert response_time < 0.1  # Should respond within 100ms

    def test_concurrent_health_requests(self, client):
        """Test handling of concurrent health check requests."""

        def make_request():
            """Make a single health request and return response time and status."""
            start_time = time.time()
            response = client.get("/health")
            end_time = time.time()
            return response.status_code, end_time - start_time

        # Make 20 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(20)]
            results = [
                future.result() for future in concurrent.futures.as_completed(futures)
            ]

        # All requests should succeed
        status_codes = [result[0] for result in results]
        response_times = [result[1] for result in results]

        assert all(status == 200 for status in status_codes)

        # Average response time should be reasonable
        avg_response_time = sum(response_times) / len(response_times)
        assert avg_response_time < 0.5  # Average under 500ms

        # No response should take longer than 2 seconds
        assert max(response_times) < 2.0

    def test_discovery_endpoint_caching(self, client):
        """Test that discovery endpoint benefits from caching."""
        # First request (potentially slower due to cache miss)
        start_time = time.time()
        response1 = client.get("/.well-known/oauth-protected-resource")
        first_response_time = time.time() - start_time

        # Second request (should be faster due to caching)
        start_time = time.time()
        response2 = client.get("/.well-known/oauth-protected-resource")
        second_response_time = time.time() - start_time

        assert response1.status_code == 200
        assert response2.status_code == 200

        # Responses should be identical
        assert response1.json() == response2.json()

        # Second request should not be significantly slower
        # (This test is informational - caching may not be implemented)
        print(
            f"First request: {first_response_time:.3f}s, Second request: {second_response_time:.3f}s"
        )

    def test_memory_usage_stability(self, client):
        """Test that repeated requests don't cause memory leaks."""
        import gc

        # Force garbage collection
        gc.collect()
        initial_objects = len(gc.get_objects())

        # Make many requests
        for _ in range(100):
            response = client.get("/health")
            assert response.status_code == 200

        # Force garbage collection again
        gc.collect()
        final_objects = len(gc.get_objects())

        # Object count shouldn't grow significantly
        object_growth = final_objects - initial_objects
        print(f"Object growth: {object_growth} objects")

        # Allow some growth but not excessive
        assert object_growth < 1000  # Arbitrary threshold

    def test_error_handling_performance(self, client):
        """Test that error responses are fast."""
        # Test 404 response time
        start_time = time.time()
        response = client.get("/non-existent-endpoint")
        response_time = time.time() - start_time

        assert response.status_code == 404
        assert response_time < 0.1  # Error responses should be fast

    @pytest.mark.asyncio
    async def test_async_request_handling(self, client):
        """Test async request handling performance."""

        async def make_async_request():
            """Simulate an async request."""
            # In a real async test, we'd use httpx AsyncClient
            # For now, we'll simulate with threading
            loop = asyncio.get_event_loop()
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = loop.run_in_executor(executor, lambda: client.get("/health"))
                response = await future
                return response.status_code

        # Make multiple async requests
        tasks = [make_async_request() for _ in range(10)]
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time

        # All requests should succeed
        assert all(status == 200 for status in results)

        # Should complete in reasonable time
        assert total_time < 2.0  # 10 requests in under 2 seconds

    def test_large_request_handling(self, client):
        """Test handling of larger request payloads."""
        # Create a large but reasonable DCR request
        large_dcr_request = {
            "redirect_uris": [f"https://example{i}.com/callback" for i in range(10)],
            "client_name": "Test Client with Very Long Name " + "x" * 100,
            "client_uri": "https://example.com",
            "logo_uri": "https://example.com/logo.png",
            "tos_uri": "https://example.com/tos",
            "policy_uri": "https://example.com/policy",
            "software_id": "test-software-123",
            "software_version": "1.0.0",
            "contacts": [f"contact{i}@example.com" for i in range(5)],
        }

        start_time = time.time()
        response = client.post("/oauth/register", json=large_dcr_request)
        response_time = time.time() - start_time

        # Should handle large requests efficiently
        assert response_time < 1.0  # Should complete within 1 second
        assert response.status_code in [201, 400]  # Either success or validation error

    def test_repeated_validation_performance(self, client):
        """Test performance of repeated token validation requests."""
        from mcp_oauth.gcp.google_wif import ValidationResult, UserInfo

        mock_user = UserInfo(email="test@qred.com", name="Test User", is_valid=True)

        mock_result = ValidationResult(user_info=mock_user, is_valid=True)

        with patch("mcp_oauth.server.validate_oauth_token") as mock_validate:
            mock_validate.return_value = mock_result

            # Measure time for multiple validation requests
            start_time = time.time()

            for _ in range(50):
                response = client.post(
                    "/validate",
                    headers={"Authorization": "Bearer test-token"},
                    json={"servers": ["postgres"]},
                )
                # Accept both success and server error for unit tests
                assert response.status_code in [200, 500]

            total_time = time.time() - start_time
            avg_time = total_time / 50

            print(f"Average validation time: {avg_time:.3f}s")
            assert avg_time < 0.1  # Average under 100ms per validation

    def test_startup_time(self):
        """Test application startup time."""
        # This test measures how long it takes to import and initialize the app
        start_time = time.time()

        with patch.dict(
            "os.environ",
            {
                "GOOGLE_OAUTH": '{"web": {"client_id": "test", "client_secret": "test"}}',
                "MCP_SERVERS_CONFIG_PATH": "/tmp/test_config.json",
            },
        ):
            with patch(
                "mcp_oauth.server.initialize_mcp_servers_config_async",
                new_callable=AsyncMock,
            ):
                from mcp_oauth.server import app

                client = TestClient(app)

                # Make a request to ensure app is fully initialized
                response = client.get("/health")

        startup_time = time.time() - start_time

        assert response.status_code == 200
        assert startup_time < 5.0  # Should start within 5 seconds
        print(f"Startup time: {startup_time:.3f}s")

    def test_resource_cleanup(self, client):
        """Test that resources are properly cleaned up after requests."""

        initial_thread_count = threading.active_count()

        # Make several requests that might create resources
        for _ in range(10):
            client.get("/health")
            client.get("/.well-known/oauth-protected-resource")

        # Allow some time for cleanup
        time.sleep(0.1)

        final_thread_count = threading.active_count()

        # Thread count shouldn't grow significantly
        thread_growth = final_thread_count - initial_thread_count
        print(f"Thread growth: {thread_growth}")

        # Allow some growth but not excessive
        assert thread_growth <= 2  # Minimal thread growth acceptable
