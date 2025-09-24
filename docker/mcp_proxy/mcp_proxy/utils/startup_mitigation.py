"""Simplified startup mitigation utilities for MCP backends."""

import asyncio
from pathlib import Path

from mcp.client.stdio import StdioServerParameters

from .logger import logger


class StartupMitigation:
    """Handle basic startup validation for MCP backends."""

    @staticmethod
    async def prepare_mcp_remote_environment() -> bool:
        """
        Verify the environment for mcp-remote is ready.

        Returns:
            True if preparation was successful, False otherwise
        """
        logger.info("Preparing mcp-remote environment...")

        try:
            # 1. Verify npm is working
            logger.debug("Verifying npm installation...")
            result = await asyncio.create_subprocess_exec(
                "npm",
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await result.communicate()

            if result.returncode != 0:
                logger.error("npm is not working properly: %s", stderr.decode())
                return False

            npm_version = stdout.decode().strip()
            logger.info("npm version: %s", npm_version)

            # 2. Verify mcp-remote is available
            logger.info("Verifying mcp-remote availability...")
            result = await asyncio.create_subprocess_exec(
                "npm",
                "list",
                "-g",
                "mcp-remote",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            if result.returncode == 0:
                logger.info("mcp-remote is pre-installed and available")
            else:
                # Test if it's available via npx
                logger.info("Testing mcp-remote via npx...")
                result = await asyncio.create_subprocess_exec(
                    "npx",
                    "mcp-remote",
                    "--version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await result.communicate()

                if result.returncode == 0:
                    logger.info("mcp-remote is available via npx")
                else:
                    logger.warning("mcp-remote not accessible via npx either")

            return True

        except Exception as e:
            logger.error("Failed to prepare mcp-remote environment: %s", e)
            return False

    @staticmethod
    async def verify_java_environment(jar_paths: list[str]) -> bool:
        """
        Verify Java environment and JAR files.

        Args:
            jar_paths: List of JAR file paths to verify

        Returns:
            True if Java environment is ready, False otherwise
        """
        logger.info("Verifying Java environment...")

        try:
            # 1. Check Java version
            result = await asyncio.create_subprocess_exec(
                "java",
                "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await result.communicate()

            if result.returncode != 0:
                logger.error("Java not available: %s", stderr.decode())
                return False

            # Java -version outputs to stderr for some reason
            version_output = stderr.decode() or stdout.decode()
            version_line = (
                version_output.split("\n")[0] if version_output else "Unknown"
            )
            logger.info("Java version: %s", version_line.strip())

            # 2. Verify JAR files exist
            for jar_path in jar_paths:
                if Path(jar_path).exists():
                    logger.info("JAR file verified: %s", jar_path)
                else:
                    logger.error("JAR file not found: %s", jar_path)
                    return False

            return True

        except Exception as e:
            logger.error("Failed to verify Java environment: %s", e)
            return False

    @staticmethod
    async def apply_startup_mitigations(
        backend_params: dict[str, StdioServerParameters],
    ) -> dict[str, StdioServerParameters]:
        """
        Apply basic startup validation and return backend parameters.

        Args:
            backend_params: Original backend parameters

        Returns:
            Backend parameters (unchanged since we're just validating environment)
        """
        logger.info(
            "Applying startup mitigations for %d backends...", len(backend_params)
        )

        # Identify backend types that need validation
        mcp_remote_backends = []
        java_backends = []
        jar_paths = []

        for name, params in backend_params.items():
            if params.command == "npx" and params.args and "mcp-remote" in params.args:
                mcp_remote_backends.append(name)
            elif params.command == "java" and params.args and "-jar" in params.args:
                java_backends.append(name)
                try:
                    jar_idx = params.args.index("-jar")
                    if jar_idx + 1 < len(params.args):
                        jar_paths.append(params.args[jar_idx + 1])
                except ValueError:
                    pass

        # Apply basic validations
        mitigation_results = {}

        if mcp_remote_backends:
            logger.info(
                "Found %d mcp-remote backends: %s",
                len(mcp_remote_backends),
                ", ".join(mcp_remote_backends),
            )
            mitigation_results[
                "mcp_remote_prep"
            ] = await StartupMitigation.prepare_mcp_remote_environment()

        if java_backends:
            logger.info(
                "Found %d Java backends: %s",
                len(java_backends),
                ", ".join(java_backends),
            )
            mitigation_results[
                "java_verify"
            ] = await StartupMitigation.verify_java_environment(jar_paths)

        # Log mitigation summary
        successful_mitigations = sum(
            1 for result in mitigation_results.values() if result
        )
        total_mitigations = len(mitigation_results)

        logger.info(
            "Startup mitigations completed: %d/%d successful",
            successful_mitigations,
            total_mitigations,
        )

        # Return original parameters since we're just doing validation now
        return backend_params
