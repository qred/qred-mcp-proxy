"""
Qred MCP Proxy — PII Redaction middleware (EET-1302).

Intercepts at the MCP protocol level inside _call_tool():
  Inbound : scans and redacts tool call arguments before forwarding to backend.
  Outbound: scans and redacts tool call results before returning to Claude Code.

Together with the device-level hooks (pii-filter.py / pii-filter-post.py in
itsupport-automations), this forms the full defence-in-depth PII stack:

  Layer                  Protects
  ─────────────────────  ──────────────────────────────────────────────────
  Device PreToolUse hook  Local tool inputs (Write/Edit content, Bash cmds)
  Device PostToolUse hook Context injection warning for local tool outputs
  This module (proxy)     MCP tool arguments AND results (postgres, grafana…)

Design decisions:
  - Zero new runtime dependencies: regex-only patterns, no external libs.
    The proxy handles structured MCP tool calls (SQL, API args, JSON rows),
    not raw source files — so detect-secrets' credential detectors add little
    over the targeted API-key regexes included here.
  - Fail-open: any exception returns the original unredacted value and logs
    a warning so Claude is never silently blocked.
  - 50 KB scan limit per string: prevents hook latency on large payloads
    (e.g. a Postgres result returning a large JSONB column).
  - Pattern order is significant — see comments below.
"""

import logging
import re
from typing import Any

from mcp import types

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MAX_SCAN_BYTES = 50_000
MAX_DEPTH = 10

# ── Regex patterns ────────────────────────────────────────────────────────────
# Order matters to prevent overlap between Nordic SSN formats:
#   SSN_DK before SSN_SE — both match DDMMYY-NNNN; DK is day/month-constrained
#   SSN_SE before SSN_FI — trailing digit in SE matches FI checksum superset
#   See pii_scanner.py in itsupport-automations for the full rationale.

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("SSN_DK",      re.compile(r"\b(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{2}-\d{4}\b")),
    ("SSN_BE",      re.compile(r"\b\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}\b")),
    ("SSN_SE",      re.compile(r"\b(19|20)?\d{6}[-+]\d{4}\b")),
    ("SSN_FI",      re.compile(r"\b\d{6}[-A]\d{3}[0-9A-Y]\b")),
    ("SSN_NO",      re.compile(r"\b[0-3]\d[0-1]\d{3}\d{5}\b")),
    ("IBAN_NORDIC", re.compile(r"\b(SE|NO|FI|DK|NL|BE)\d{2}[A-Z0-9]{4,30}\b")),
    ("EMAIL",       re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    # API credentials — common formats that can appear in tool results
    ("GITHUB_TOKEN", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("OPENAI_KEY",   re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("STRIPE_KEY",   re.compile(r"\b[sp]k_(?:live|test)_[A-Za-z0-9]{20,}\b")),
]


# ── Core scanning functions ───────────────────────────────────────────────────


def redact_text(text: str) -> tuple[str, list[str]]:
    """
    Scan a single string for PII and return the redacted version plus found types.

    Skips binary content (null bytes in first 512 bytes).
    Scans only the first MAX_SCAN_BYTES — remainder is appended untouched.
    """
    if not text:
        return text, []

    # Skip binary content — avoids false positives on base64/binary data
    if "\x00" in text[:512]:
        return text, []

    scannable = text[:MAX_SCAN_BYTES]
    remainder = text[MAX_SCAN_BYTES:]
    found_types: list[str] = []

    for name, pattern in _PATTERNS:
        if pattern.search(scannable):
            scannable = pattern.sub(f"[{name}]", scannable)
            found_types.append(name)

    if not found_types:
        return text, []

    return scannable + remainder, found_types


def redact_value(value: Any, depth: int = 0) -> tuple[Any, list[str]]:
    """
    Recursively redact PII from dicts, lists, and strings.

    Mirrors scan_value() in pii_scanner.py (itsupport-automations) so both
    layers apply identical patterns to their respective data paths.
    """
    if depth > MAX_DEPTH:
        return value, []

    all_found: list[str] = []

    if isinstance(value, str):
        redacted, found = redact_text(value)
        return redacted, found

    elif isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            new_v, found = redact_value(v, depth + 1)
            out[k] = new_v
            all_found.extend(found)
        return out, all_found

    elif isinstance(value, list):
        out_list: list[Any] = []
        for item in value:
            new_item, found = redact_value(item, depth + 1)
            out_list.append(new_item)
            all_found.extend(found)
        return out_list, all_found

    return value, []


# ── Public API ────────────────────────────────────────────────────────────────


def redact_tool_arguments(
    arguments: dict[str, Any],
    tool_name: str,
    backend_name: str,
) -> tuple[dict[str, Any], list[str]]:
    """
    Scan and redact PII from tool call arguments before forwarding to backend.

    Called by _call_tool() in aggregated_proxy_server.py and proxy_server.py
    immediately after the arguments dict is extracted from the request.

    Returns (redacted_arguments, list_of_found_pii_types).
    Empty found list → caller should pass arguments through unchanged.
    """
    try:
        redacted, found = redact_value(arguments)
        if found:
            logger.warning(
                "EET-1302 PII redacted from tool arguments | tool=%s backend=%s types=%s",
                tool_name,
                backend_name,
                found,
            )
        return redacted, found  # type: ignore[return-value]
    except Exception:
        logger.exception(
            "EET-1302 PII scan failed for tool arguments — passing through unchanged | tool=%s",
            tool_name,
        )
        return arguments, []  # fail-open


def redact_tool_result(
    result: types.CallToolResult,
    tool_name: str,
    backend_name: str,
) -> tuple[types.CallToolResult, list[str]]:
    """
    Scan and redact PII from a CallToolResult before returning to Claude Code.

    Only TextContent items are scanned — ImageContent, AudioContent, and
    EmbeddedResource contain binary/structured data with no PII text risk.

    Returns (redacted_result, list_of_found_pii_types).
    If no PII found, the original result object is returned unchanged.
    """
    try:
        all_found: list[str] = []
        new_content: list[types.ContentBlock] = []
        changed = False

        for item in result.content:
            if isinstance(item, types.TextContent):
                redacted_text, found = redact_text(item.text)
                all_found.extend(found)
                if found:
                    new_content.append(types.TextContent(type="text", text=redacted_text))
                    changed = True
                else:
                    new_content.append(item)
            else:
                # ImageContent, AudioContent, EmbeddedResource, ResourceLink
                new_content.append(item)

        if not all_found:
            return result, []

        if changed:
            logger.warning(
                "EET-1302 PII redacted from tool result | tool=%s backend=%s types=%s",
                tool_name,
                backend_name,
                all_found,
            )

        return types.CallToolResult(content=new_content, isError=result.isError), all_found

    except Exception:
        logger.exception(
            "EET-1302 PII scan failed for tool result — returning original | tool=%s",
            tool_name,
        )
        return result, []  # fail-open
