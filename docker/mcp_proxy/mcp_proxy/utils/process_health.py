"""Simplified process health checking utilities for MCP backends."""

import asyncio
import logging
import time

import httpx
from mcp.client.stdio import StdioServerParameters

from .config_loader import HttpServerParameters, ServerParameters

logger = logging.getLogger(__name__)


class ProcessHealthChecker:
    """Check if a process can start successfully before creating MCP sessions."""

    @staticmethod
    async def check_process_health(
        params: ServerParameters, timeout: float = 10.0
    ) -> tuple[bool, str | None]:
        """
        Check if a server can be reached successfully.

        Args:
            params: The server parameters (HTTP or STDIO)
            timeout: How long to wait for health check

        Returns:
            Tuple of (is_healthy, error_message)
        """
        if isinstance(params, HttpServerParameters):
            return await ProcessHealthChecker.check_http_health(params, timeout)
        else:
            return await ProcessHealthChecker.check_stdio_health(params, timeout)

    @staticmethod
    async def check_http_health(
        params: HttpServerParameters, timeout: float = 10.0
    ) -> tuple[bool, str | None]:
        """
        Check if an HTTP MCP server is reachable.

        Args:
            params: The HTTP server parameters
            timeout: How long to wait for health check

        Returns:
            Tuple of (is_healthy, error_message)
        """
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                # Try to reach the MCP endpoint
                response = await client.get(
                    params.url, headers={"Accept": "application/json"}
                )
                if response.status_code in [
                    200,
                    404,
                    405,
                ]:  # 404/405 are acceptable for MCP endpoints
                    return True, None
                else:
                    return False, f"HTTP server returned status {response.status_code}"
        except httpx.TimeoutException:
            return False, f"HTTP health check timed out after {timeout}s"
        except httpx.ConnectError as e:
            return False, f"Failed to connect to HTTP server: {e}"
        except Exception as e:
            return False, f"HTTP health check failed: {e}"

    @staticmethod
    async def check_stdio_health(
        params: StdioServerParameters, timeout: float = 10.0
    ) -> tuple[bool, str | None]:
        """
        Check if a STDIO process can start successfully.

        Args:
            params: The stdio server parameters
            timeout: How long to wait for process health check

        Returns:
            Tuple of (is_healthy, error_message)
        """
        try:
            # For mcp-remote commands, do a quick validation
            if params.command == "npx" and params.args and "mcp-remote" in params.args:
                return await ProcessHealthChecker._check_mcp_remote_health(
                    params, timeout
                )

            # For other commands, do a basic process start check
            return await ProcessHealthChecker._check_basic_process_health(
                params, timeout
            )

        except Exception as e:
            error_msg = f"Health check failed with exception: {e}"
            logger.debug(error_msg)
            return False, error_msg

    @staticmethod
    async def _check_mcp_remote_health(
        params: StdioServerParameters, timeout: float
    ) -> tuple[bool, str | None]:
        """Check if mcp-remote command can be executed."""
        try:
            # Test if we can at least run the command without errors
            process = await asyncio.create_subprocess_exec(
                params.command,
                *params.args,
                "--help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=params.env,
            )

            try:
                _stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )

                if process.returncode == 0:
                    return True, None
                else:
                    error_output = stderr.decode() if stderr else "Unknown error"
                    return False, f"mcp-remote command failed: {error_output}"

            except TimeoutError:
                process.kill()
                await process.wait()
                return False, f"mcp-remote command timed out after {timeout}s"

        except Exception as e:
            return False, f"Failed to start mcp-remote process: {e}"

    @staticmethod
    async def _check_basic_process_health(
        params: StdioServerParameters, timeout: float
    ) -> tuple[bool, str | None]:
        """Check if a basic process can start."""
        try:
            # For Java apps, check if we can get version info
            if params.command == "java":
                process = await asyncio.create_subprocess_exec(
                    "java",
                    "-version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=params.env,
                )

                try:
                    _stdout, _stderr = await asyncio.wait_for(
                        process.communicate(), timeout=5
                    )
                    if process.returncode == 0:
                        return True, None
                    else:
                        return False, "Java not available"
                except TimeoutError:
                    process.kill()
                    await process.wait()
                    return False, "Java version check timed out"

            # For other processes, just check if the command exists
            try:
                process = await asyncio.create_subprocess_exec(
                    "which",
                    params.command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _stdout, _stderr = await process.communicate()

                if process.returncode == 0:
                    return True, None
                else:
                    return False, f"Command '{params.command}' not found in PATH"

            except Exception as e:
                return False, f"Failed to check command availability: {e}"

        except Exception as e:
            return False, f"Failed to check process health: {e}"


async def validate_backend_processes(
    backend_params: dict[str, ServerParameters], max_concurrent: int = 3
) -> dict[str, tuple[bool, str | None, float]]:
    """
    Validate multiple backend servers concurrently.

    Args:
        backend_params: Dict mapping backend names to their parameters (HTTP or STDIO)
        max_concurrent: Maximum number of concurrent health checks

    Returns:
        Dict mapping backend names to (is_healthy, error_message, duration) tuples
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def check_single_backend(
        name: str, params: ServerParameters
    ) -> tuple[str, tuple[bool, str | None, float]]:
        async with semaphore:
            logger.info("Health checking backend '%s'", name)
            start_time = time.time()
            is_healthy, error = await ProcessHealthChecker.check_process_health(params)
            duration = time.time() - start_time

            if is_healthy:
                logger.info("Backend '%s' health check passed (%.2fs)", name, duration)
            else:
                logger.warning(
                    "Backend '%s' health check failed (%.2fs): %s",
                    name,
                    duration,
                    error,
                )

            return name, (is_healthy, error, duration)

    # Run all health checks concurrently
    tasks = [
        check_single_backend(name, params) for name, params in backend_params.items()
    ]

    results = await asyncio.gather(*tasks)
    return dict(results)
