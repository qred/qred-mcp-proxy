#!/usr/bin/env python3
"""
Post-process CTRF reports to add suite information extracted from test names.
This helps the GitHub Actions CTRF reporter group tests properly.
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, Any


def extract_suite_from_test_name(test_name: str) -> str:
    """
    Extract suite name from pytest test name.

    Examples:
    - "tests/oauth/test_oauth_endpoints.py::TestOAuthEndpoints::test_health_endpoint"
      -> "OAuth Endpoints"
    - "tests/proxy/test_config_loading_unit.py::TestConfigLoadingUnit::test_oauth_config_loading_logic_success"
      -> "Config Loading"
    """
    # Pattern to match pytest class-based test names, only strip "Unit" suffix
    match = re.search(r"::Test([A-Z][a-zA-Z]+?)(?:Unit)?::", test_name)
    if match:
        class_name = match.group(1)

        # Convert CamelCase to space-separated words first
        suite_name = re.sub(
            r"([A-Z])([A-Z][a-z])", r"\1 \2", class_name
        )  # Handle sequences like "MCPProxy"
        suite_name = re.sub(
            r"([a-z])([A-Z])", r"\1 \2", suite_name
        )  # Handle normal CamelCase
        suite_name = suite_name.strip()

        # Clean up specific patterns after the split
        suite_name = suite_name.replace(
            "O Auth", "OAuth"
        )  # Fix split OAuth back to OAuth
        suite_name = suite_name.replace("M C P", "MCP")  # Fix split MCP back to MCP

        return suite_name

    # Fallback to file-based grouping
    file_match = re.search(r"tests/([^/]+)/test_([^/]+)\.py", test_name)
    if file_match:
        category = file_match.group(1).replace("_", " ").title()
        test_type = file_match.group(2).replace("_", " ").title()
        return f"{category} {test_type}"

    return "Ungrouped"


def add_suite_information(ctrf_report: Dict[str, Any]) -> Dict[str, Any]:
    """Add suite information to each test in the CTRF report."""

    if "results" not in ctrf_report or "tests" not in ctrf_report["results"]:
        return ctrf_report

    # Add suite information to each test
    for test in ctrf_report["results"]["tests"]:
        if "name" in test and not test.get("suite"):
            test["suite"] = extract_suite_from_test_name(test["name"])

    return ctrf_report


def main():
    """Process CTRF files to add suite information."""
    if len(sys.argv) != 2:
        print("Usage: python add_suites_to_ctrf.py <ctrf_file_path>")
        sys.exit(1)

    ctrf_file_path = Path(sys.argv[1])

    if not ctrf_file_path.exists():
        print(f"Error: CTRF file not found: {ctrf_file_path}")
        sys.exit(1)

    try:
        # Read the CTRF report
        with open(ctrf_file_path, "r") as f:
            ctrf_report = json.load(f)

        # Add suite information
        updated_report = add_suite_information(ctrf_report)

        # Write back the updated report
        with open(ctrf_file_path, "w") as f:
            json.dump(updated_report, f, indent=2)

        print(f"Successfully added suite information to {ctrf_file_path}")

        # Print summary of suites found
        suites = set()
        for test in updated_report["results"]["tests"]:
            if "suite" in test:
                suites.add(test["suite"])

        print(f"Found {len(suites)} suites: {', '.join(sorted(suites))}")

    except Exception as e:
        print(f"Error processing CTRF file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
