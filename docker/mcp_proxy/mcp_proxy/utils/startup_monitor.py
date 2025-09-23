"""Startup monitoring and reporting for MCP server deployment."""

import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass

from .logger import logger


@dataclass
class BackendStatus:
    """Status information for a backend during startup."""

    name: str
    health_check_passed: bool
    health_check_error: Optional[str]
    health_check_duration: float
    mitigation_applied: bool
    session_created: bool
    session_error: Optional[str]
    session_duration: Optional[float]
    recovery_attempts: int
    final_status: str  # "healthy", "failed", "skipped"


class StartupMonitor:
    """Monitor and report on startup progress for debugging deployment issues."""

    def __init__(self) -> None:
        self.startup_start_time = time.time()
        self.backend_statuses: Dict[str, BackendStatus] = {}
        self.phase_times: Dict[str, float] = {}

    def start_phase(self, phase_name: str) -> None:
        """Mark the start of a startup phase."""
        self.phase_times[f"{phase_name}_start"] = time.time()
        logger.info("=== STARTUP PHASE: %s ===", phase_name)

    def end_phase(self, phase_name: str) -> None:
        """Mark the end of a startup phase."""
        start_time = self.phase_times.get(
            f"{phase_name}_start", self.startup_start_time
        )
        duration = time.time() - start_time
        self.phase_times[f"{phase_name}_duration"] = duration
        logger.info("=== PHASE COMPLETE: %s (%.2fs) ===", phase_name, duration)

    def record_backend_health_check(
        self, backend_name: str, passed: bool, error: Optional[str], duration: float
    ) -> None:
        """Record health check results for a backend."""
        if backend_name not in self.backend_statuses:
            self.backend_statuses[backend_name] = BackendStatus(
                name=backend_name,
                health_check_passed=False,
                health_check_error=None,
                health_check_duration=0.0,
                mitigation_applied=False,
                session_created=False,
                session_error=None,
                session_duration=None,
                recovery_attempts=0,
                final_status="unknown",
            )

        status = self.backend_statuses[backend_name]
        status.health_check_passed = passed
        status.health_check_error = error
        status.health_check_duration = duration
        # Set final status based on health check result
        status.final_status = "healthy" if passed else "failed"

        if passed:
            logger.debug(
                "✓ Backend '%s' health check passed (%.2fs)", backend_name, duration
            )
        else:
            logger.warning(
                "✗ Backend '%s' health check failed (%.2fs): %s",
                backend_name,
                duration,
                error,
            )

    def record_mitigation_applied(self, backend_name: str) -> None:
        """Record that mitigation was applied to a backend."""
        if backend_name in self.backend_statuses:
            self.backend_statuses[backend_name].mitigation_applied = True
            logger.debug("🔧 Mitigation applied to backend '%s'", backend_name)

    def record_session_result(
        self,
        backend_name: str,
        success: bool,
        error: Optional[str],
        duration: Optional[float],
        recovery_attempts: int = 0,
    ) -> None:
        """Record session creation results for a backend."""
        if backend_name in self.backend_statuses:
            status = self.backend_statuses[backend_name]
            status.session_created = success
            status.session_error = error
            status.session_duration = duration
            status.recovery_attempts = recovery_attempts
            status.final_status = "healthy" if success else "failed"

            if success:
                logger.info(
                    "✓ Backend '%s' session created successfully (%.2fs, %d recoveries)",
                    backend_name,
                    duration or 0,
                    recovery_attempts,
                )
            else:
                logger.error(
                    "✗ Backend '%s' session creation failed (%.2fs, %d recoveries): %s",
                    backend_name,
                    duration or 0,
                    recovery_attempts,
                    error,
                )

    def record_backend_skipped(self, backend_name: str, reason: str) -> None:
        """Record that a backend was skipped."""
        if backend_name in self.backend_statuses:
            self.backend_statuses[backend_name].final_status = "skipped"
            logger.info("⏭ Backend '%s' skipped: %s", backend_name, reason)

    def generate_startup_report(self) -> str:
        """Generate a comprehensive startup report."""
        total_duration = time.time() - self.startup_start_time

        # Count statuses
        healthy_count = sum(
            1 for s in self.backend_statuses.values() if s.final_status == "healthy"
        )
        failed_count = sum(
            1 for s in self.backend_statuses.values() if s.final_status == "failed"
        )
        skipped_count = sum(
            1 for s in self.backend_statuses.values() if s.final_status == "skipped"
        )
        total_count = len(self.backend_statuses)

        # Build report
        report_lines = [
            "",
            "=" * 60,
            "MCP PROXY STARTUP REPORT",
            "=" * 60,
            f"Total startup time: {total_duration:.2f}s",
            f"Backends: {total_count} total, {healthy_count} healthy, {failed_count} failed, {skipped_count} skipped",
            "",
        ]

        # Phase timing
        if self.phase_times:
            report_lines.append("PHASE TIMING:")
            for phase_name, duration in self.phase_times.items():
                if phase_name.endswith("_duration"):
                    phase = phase_name.replace("_duration", "")
                    report_lines.append(f"  {phase}: {duration:.2f}s")
            report_lines.append("")

        # Backend details
        if self.backend_statuses:
            report_lines.append("BACKEND DETAILS:")

            for backend_name, status in self.backend_statuses.items():
                icon = {"healthy": "✓", "failed": "✗", "skipped": "⏭", "unknown": "?"}[
                    status.final_status
                ]
                report_lines.append(f"  {icon} {backend_name} ({status.final_status})")

                if status.health_check_duration > 0:
                    hc_status = "PASS" if status.health_check_passed else "FAIL"
                    report_lines.append(
                        f"    Health Check: {hc_status} ({status.health_check_duration:.2f}s)"
                    )
                    if status.health_check_error:
                        report_lines.append(
                            f"    Health Error: {status.health_check_error}"
                        )

                if status.mitigation_applied:
                    report_lines.append("    Mitigation: APPLIED")

                if status.session_duration is not None:
                    session_status = "SUCCESS" if status.session_created else "FAILED"
                    report_lines.append(
                        f"    Session: {session_status} ({status.session_duration:.2f}s)"
                    )
                    if status.recovery_attempts > 0:
                        report_lines.append(
                            f"    Recovery Attempts: {status.recovery_attempts}"
                        )
                    if status.session_error:
                        report_lines.append(
                            f"    Session Error: {status.session_error}"
                        )

                report_lines.append("")

        # Summary and recommendations
        report_lines.extend(
            [
                "SUMMARY:",
                f"  Server startup: {'SUCCESS' if healthy_count > 0 else 'FAILED'}",
                f"  Healthy backends: {healthy_count}/{total_count}",
            ]
        )

        if failed_count > 0:
            report_lines.append(
                "  ⚠️  Some backends failed - check logs above for details"
            )

        if skipped_count > 0:
            report_lines.append(
                "  ℹ️  Some backends were skipped due to health check failures"
            )

        # ECS-specific recommendations
        if failed_count > 0 or skipped_count > 0:
            report_lines.extend(
                [
                    "",
                    "ECS DEPLOYMENT RECOMMENDATIONS:",
                    "  1. Check ECS task definition environment variables",
                    "  2. Verify container network connectivity",
                    "  3. Ensure all required dependencies are in the container image",
                    "  4. Check CloudWatch logs for detailed error information",
                    "  5. Consider increasing ECS task startup timeout if needed",
                ]
            )

        report_lines.append("=" * 60)

        return "\n".join(report_lines)

    def log_startup_report(self) -> None:
        """Log the startup report."""
        report = self.generate_startup_report()

        # Log each line separately for better CloudWatch formatting
        for line in report.split("\n"):
            if line.strip():
                logger.info(line)
            else:
                logger.info("")  # Empty line for spacing

    def should_continue_startup(self) -> Tuple[bool, str]:
        """
        Determine if startup should continue based on backend health.

        Returns:
            Tuple of (should_continue, reason)
        """
        healthy_count = sum(
            1 for s in self.backend_statuses.values() if s.final_status == "healthy"
        )
        total_count = len(self.backend_statuses)

        if healthy_count == 0:
            return False, "No backends are healthy - cannot start server"

        if healthy_count == total_count:
            return True, f"All {total_count} backends are healthy"

        # Some backends are healthy
        failed_count = sum(
            1 for s in self.backend_statuses.values() if s.final_status == "failed"
        )
        return (
            True,
            f"{healthy_count}/{total_count} backends are healthy ({failed_count} failed)",
        )


# Global startup monitor instance
_startup_monitor = StartupMonitor()
