#!/usr/bin/env python3
"""Test runner script for MCP Proxy tests."""

import sys
import subprocess
import os
from pathlib import Path
import argparse


def run_tests(test_suite=None, ctrf=False, fail_fast=False):
    """Run the test suite with appropriate configuration."""
    
    # Get the project root directory (parent of tests directory)
    project_root = Path(__file__).parent.parent
    
    # Create CTRF output directory
    ctrf_dir = project_root / "ctrf"
    if ctrf:
        ctrf_dir.mkdir(exist_ok=True)
    
    # Set up environment for testing
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(project_root),
        "GOOGLE_OAUTH": '{"web": {"client_id": "test-client.googleusercontent.com", "client_secret": "test-secret"}}',
        "MCP_SERVERS_CONFIG_PATH": "/tmp/test_config.json",
        "SA_EMAIL": "test-service-account@test-project.iam.gserviceaccount.com",
        "GCP_SECRET_ARN": '{"type": "external_account", "audience": "//iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/test-pool/providers/test-provider", "subject_token_type": "urn:ietf:params:oauth:token-type:aws4_request", "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test-service-account@test-project.iam.gserviceaccount.com:generateAccessToken", "credential_source": {"environment_id": "aws1", "region_url": "http://169.254.169.254/latest/meta-data/placement/availability-zone", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials", "format": {"type": "json", "subject_token_field_name": "access_token"}}}'
    })
    
    # If running a specific test suite, run it directly
    if test_suite:
        return run_test_suite(test_suite, ctrf, fail_fast, env, ctrf_dir, project_root)
    
    # If running all tests, run each suite separately for better CTRF grouping
    print("Running all test suites separately for better reporting...")
    
    # Run OAuth tests
    oauth_result = run_test_suite("oauth", ctrf, fail_fast, env, ctrf_dir, project_root)
    if oauth_result != 0:
        return oauth_result
    
    # Run proxy tests
    proxy_result = run_test_suite("proxy", ctrf, fail_fast, env, ctrf_dir, project_root)
    
    return proxy_result


def run_test_suite(suite_name, ctrf_enabled, fail_fast, env, ctrf_dir, project_root):
    """Run a specific test suite and generate CTRF report."""
    
    # Determine test path based on suite name
    if suite_name == "oauth":
        test_path = project_root / "tests" / "oauth"
        ctrf_filename = "oauth-server-tests.json"
    elif suite_name == "proxy":
        test_path = project_root / "tests" / "proxy"
        ctrf_filename = "mcp-proxy-app-tests.json"
    else:
        # For unknown suite names, assume it's a path
        test_path = project_root / "tests" / suite_name
        ctrf_filename = f"{suite_name}-tests.json"
    
    # Build pytest command
    cmd = [
        sys.executable, "-m", "pytest", "-v", "--tb=short", "--strict-markers",
        "--strict-config", str(test_path), "--color=yes"
    ]
    
    # Add CTRF flag if enabled
    ctrf_path = None
    if ctrf_enabled:
        ctrf_path = ctrf_dir / ctrf_filename
        cmd.append(f"--ctrf={ctrf_path}")
    
    # Add fail-fast flag if enabled
    if fail_fast:
        cmd.append("-x")
    
    print(f"Running {suite_name.upper()} tests with command: {' '.join(cmd)}")
    print(f"Environment: PYTHONPATH={env.get('PYTHONPATH', 'Not set')}")
    if ctrf_enabled:
        print(f"CTRF reports will be saved to: {ctrf_dir}")
    print("-" * 60)
    
    # Run the tests
    result = subprocess.run(cmd, env=env, capture_output=False)
    
    # Add suite information to the CTRF report if it was generated
    if ctrf_enabled and ctrf_path and ctrf_path.exists():
        try:
            add_suites_script = Path(__file__).parent / "add_suites_to_ctrf.py"
            suite_result = subprocess.run([sys.executable, str(add_suites_script), str(ctrf_path)], 
                          env=env, capture_output=True, text=True)
            if suite_result.returncode == 0:
                print(f"Added suite information to {ctrf_path}")
                if suite_result.stdout:
                    print(suite_result.stdout.strip())
            else:
                print(f"Warning: Failed to add suite information: {suite_result.stderr}")
        except Exception as e:
            print(f"Warning: Failed to process CTRF report: {e}")
    
    return result.returncode


def print_help():
    """Print help message."""
    print("""
MCP Proxy Test Runner

Usage: python run_tests.py [OPTIONS]

Options:
    --oauth      Run only OAuth server tests
    --proxy      Run only MCP proxy application tests (config, lifecycle, etc.)
    --ctrf       Generate CTRF test reports
    --fast       Run tests in fail-fast mode with minimal output
    --help       Show this help message

Examples:
    python run_tests.py                     # Run all tests
    python run_tests.py --oauth             # Run only OAuth tests
    python run_tests.py --proxy             # Run only MCP proxy tests
    python run_tests.py --ctrf              # Run all tests with CTRF reports
    python run_tests.py --oauth --ctrf      # Run OAuth tests with CTRF reports
    python run_tests.py --fast              # Run all tests in fail-fast mode

Note: Make sure to install test dependencies first:
    uv sync --group test
    # or
    pip install -e ".[test]"

CDK tests are handled separately via TypeScript compilation and synthesis in CI/CD.
""")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run MCP Proxy test suites",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=print_help.__doc__
    )
    
    # Test suite selection (mutually exclusive)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--oauth", action="store_true", help="Run OAuth server tests only")
    group.add_argument("--proxy", action="store_true", help="Run MCP proxy application tests only")
    
    # Test options
    parser.add_argument("--ctrf", action="store_true", help="Generate CTRF test reports")
    parser.add_argument("--fast", action="store_true", help="Fail fast on first error")
    
    args = parser.parse_args()
    
    # Determine test suite
    test_suite = None
    if args.oauth:
        test_suite = "oauth"
    elif args.proxy:
        test_suite = "proxy"
    
    return run_tests(test_suite=test_suite, ctrf=args.ctrf, fail_fast=args.fast)


if __name__ == "__main__":
    sys.exit(main())