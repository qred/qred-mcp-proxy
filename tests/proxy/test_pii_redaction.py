"""
Unit tests for EET-1302 MCP proxy PII redaction middleware.

Tests are pure-Python and require no running proxy server — they test the
pii_redaction module directly. All assertions use the public API:
  redact_text()           → single string
  redact_value()          → recursive dict/list/string
  redact_tool_arguments() → tool call args dict
  redact_tool_result()    → types.CallToolResult
"""

import sys
from pathlib import Path

import pytest
from mcp import types

# Make mcp_proxy importable from tests/
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "docker" / "mcp_proxy"))

from mcp_proxy.middleware.pii_redaction import (
    redact_text,
    redact_tool_arguments,
    redact_tool_result,
    redact_value,
)


# ── redact_text ───────────────────────────────────────────────────────────────


class TestRedactText:
    """Unit tests for the core string scanner."""

    def test_swedish_ssn_long_form(self):
        text, found = redact_text("personnummer: 19901231-1234")
        assert "19901231-1234" not in text
        assert "[SSN_SE]" in text
        assert "SSN_SE" in found

    def test_swedish_ssn_short_form(self):
        text, found = redact_text("ssn: 901231-1234")
        assert "901231-1234" not in text
        assert found  # should match SSN_SE

    def test_danish_cpr(self):
        text, found = redact_text("CPR: 010190-1234")
        assert "010190-1234" not in text
        assert "SSN_DK" in found

    def test_norwegian_ssn(self):
        text, found = redact_text("fødselsnummer: 01019012345")
        assert "01019012345" not in text
        assert "SSN_NO" in found

    def test_finnish_ssn(self):
        text, found = redact_text("hetu: 010190-123A")
        assert "010190-123A" not in text
        assert "SSN_FI" in found

    def test_belgian_national_number(self):
        text, found = redact_text("rrn: 90.02.01-123.45")
        assert "90.02.01-123.45" not in text
        assert "SSN_BE" in found

    def test_nordic_iban(self):
        text, found = redact_text("IBAN: SE3550000000054910000003")
        assert "SE3550000000054910000003" not in text
        assert "[IBAN_NORDIC]" in text
        assert "IBAN_NORDIC" in found

    def test_email(self):
        text, found = redact_text("email: user@qred.com")
        assert "user@qred.com" not in text
        assert "EMAIL" in found

    def test_openai_key(self):
        # Constructed at runtime to avoid triggering GitHub push protection on literals
        key = "sk-proj-" + "a" * 24
        text, found = redact_text(f"OPENAI_KEY={key}")
        assert key not in text
        assert "OPENAI_KEY" in found

    def test_github_token(self):
        # Constructed at runtime to avoid triggering GitHub push protection on literals
        key = "ghp_" + "A" * 36
        text, found = redact_text(f"token: {key}")
        assert key not in text
        assert "GITHUB_TOKEN" in found

    def test_stripe_key(self):
        # Constructed at runtime to avoid triggering GitHub push protection on literals
        key = "sk_live_" + "a" * 20
        text, found = redact_text(key)
        assert key not in text
        assert "STRIPE_KEY" in found

    def test_clean_text_passes_unchanged(self):
        original = "SELECT count(*) FROM loans WHERE status = 'active'"
        text, found = redact_text(original)
        assert text == original
        assert found == []

    def test_empty_string(self):
        text, found = redact_text("")
        assert text == ""
        assert found == []

    def test_binary_content_skipped(self):
        binary = "before\x00\x01\x02after"
        text, found = redact_text(binary)
        assert text == binary  # unchanged
        assert found == []

    def test_large_content_scans_first_50kb(self):
        # PII beyond 50KB must not be detected
        large = "x" * 60_000 + " user@qred.com"
        text, found = redact_text(large)
        assert found == []

    def test_multiple_pii_types_in_one_string(self):
        row = "id=1 | ssn=19901231-1234 | email=user@qred.com | iban=SE3550000000054910000003"
        text, found = redact_text(row)
        assert "19901231-1234" not in text
        assert "user@qred.com" not in text
        assert "SE3550000000054910000003" not in text
        assert len(found) >= 3


# ── redact_value ──────────────────────────────────────────────────────────────


class TestRedactValue:
    """Recursive scanning of dict/list/str structures."""

    def test_dict_string_values(self):
        value, found = redact_value({"query": "WHERE ssn = '19901231-1234'"})
        assert "19901231-1234" not in value["query"]
        assert found

    def test_nested_dict(self):
        value, found = redact_value({
            "outer": {
                "inner": {"email": "deep@qred.com", "ssn": "19850615-4321"}
            }
        })
        assert "deep@qred.com" not in str(value)
        assert "19850615-4321" not in str(value)

    def test_list_of_strings(self):
        value, found = redact_value(["clean", "ssn: 19901231-1234", "also clean"])
        assert "19901231-1234" not in value[1]
        assert found

    def test_non_string_values_passed_through(self):
        value, found = redact_value({"count": 42, "active": True, "ratio": 3.14})
        assert value == {"count": 42, "active": True, "ratio": 3.14}
        assert found == []

    def test_depth_limit_prevents_stack_overflow(self):
        # Build 15-level deep dict (limit is 10)
        deep: dict = {"k": "ssn: 19901231-1234"}
        for _ in range(15):
            deep = {"nested": deep}
        # Must not raise; deepest level is not scanned
        value, _ = redact_value(deep)
        assert value is not None


# ── redact_tool_arguments ─────────────────────────────────────────────────────


class TestRedactToolArguments:
    """PII in tool arguments must be redacted before backend receives them."""

    def test_sql_query_with_ssn(self):
        args = {"query": "SELECT * FROM customers WHERE ssn = '19901231-1234'"}
        redacted, found = redact_tool_arguments(args, "execute_query", "postgres")
        assert "19901231-1234" not in redacted["query"]
        assert found

    def test_clean_arguments_unchanged(self):
        args = {"query": "SELECT count(*) FROM loans", "limit": 100}
        redacted, found = redact_tool_arguments(args, "query", "postgres")
        assert redacted == args
        assert found == []

    def test_multiple_pii_in_arguments(self):
        args = {
            "query": "SELECT * FROM users WHERE email = 'a@qred.com'",
            "comment": "report for ssn 19901231-1234",
        }
        redacted, found = redact_tool_arguments(args, "execute_query", "postgres")
        assert "a@qred.com" not in str(redacted)
        assert "19901231-1234" not in str(redacted)

    def test_exception_fails_open(self, monkeypatch):
        """If scanning raises, original arguments are returned unchanged."""
        import mcp_proxy.middleware.pii_redaction as mod

        def boom(v: object, depth: int = 0) -> object:
            raise RuntimeError("scan error")

        monkeypatch.setattr(mod, "redact_value", boom)
        args = {"query": "SELECT 1"}
        redacted, found = redact_tool_arguments(args, "query", "postgres")
        assert redacted == args
        assert found == []


# ── redact_tool_result ────────────────────────────────────────────────────────


class TestRedactToolResult:
    """PII in tool results must be redacted before returning to Claude Code."""

    def _make_result(self, *texts: str, is_error: bool = False) -> types.CallToolResult:
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=t) for t in texts],
            isError=is_error,
        )

    def test_ssn_in_result_text(self):
        result = self._make_result("Row 1: ssn=19901231-1234, name=Erik")
        redacted, found = redact_tool_result(result, "execute_query", "postgres")
        assert "19901231-1234" not in redacted.content[0].text  # type: ignore[union-attr]
        assert "SSN_SE" in found

    def test_email_in_result_text(self):
        result = self._make_result("contact: admin@qred.com")
        redacted, found = redact_tool_result(result, "query", "postgres")
        assert "admin@qred.com" not in redacted.content[0].text  # type: ignore[union-attr]
        assert "EMAIL" in found

    def test_iban_in_result_text(self):
        result = self._make_result("IBAN: SE9912000000012345678901")
        redacted, found = redact_tool_result(result, "query", "postgres")
        assert "SE9912000000012345678901" not in str(redacted.content)
        assert "IBAN_NORDIC" in found

    def test_multiple_text_blocks_all_scanned(self):
        result = self._make_result(
            "email: a@qred.com",
            "ssn: 19901231-1234",
            "clean row",
        )
        redacted, found = redact_tool_result(result, "query", "postgres")
        texts = [item.text for item in redacted.content if isinstance(item, types.TextContent)]  # type: ignore[union-attr]
        assert "a@qred.com" not in texts[0]
        assert "19901231-1234" not in texts[1]
        assert texts[2] == "clean row"
        assert len(found) >= 2

    def test_clean_result_returned_unchanged(self):
        result = self._make_result("42 rows returned")
        redacted, found = redact_tool_result(result, "query", "postgres")
        assert redacted is result  # exact same object — no copy made
        assert found == []

    def test_is_error_preserved(self):
        result = self._make_result("error: user@qred.com not found", is_error=True)
        redacted, found = redact_tool_result(result, "query", "postgres")
        assert redacted.isError is True
        assert found

    def test_exception_fails_open(self, monkeypatch):
        """If scanning raises, original result is returned unchanged."""
        import mcp_proxy.middleware.pii_redaction as mod

        def boom(text: str) -> object:
            raise RuntimeError("scan error")

        monkeypatch.setattr(mod, "redact_text", boom)
        result = self._make_result("ssn: 19901231-1234")
        redacted, found = redact_tool_result(result, "query", "postgres")
        assert redacted is result
        assert found == []
