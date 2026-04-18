# MCP Proxy PII Redaction Middleware — EET-1302

## Overview

`pii_redaction.py` implements the **MCP protocol layer** of Qred's defence-in-depth
PII protection stack.  It intercepts every tool call passing through the proxy and
scrubs PII from both the inbound arguments and the outbound result.

---

## Where it fits

```
Claude Code
    │
    │  MCP tool call (e.g. postgres query, slack message)
    ▼
mcp-proxy.tools.qred.com
    ├─ [redact_tool_arguments()]  ← scrubs before backend sees the query
    │
    ▼
Backend MCP service (Postgres / Slack / Grafana …)
    │
    │  Tool result (rows, API response)
    ▼
mcp-proxy.tools.qred.com
    ├─ [redact_tool_result()]     ← scrubs before Claude Code sees the result
    │
    ▼
Claude Code
```

This is Layer 2 of three:

| Layer | Repo | Protects |
|-------|------|---------|
| 1. Device hooks | itsupport-automations | Tool inputs before local execution |
| **2. MCP middleware** | **qred-mcp-proxy** (this) | **MCP tool arguments and results** |
| 3. API proxy (EET-1352) | mcp-config | LLM conversation stream |

---

## Integration points

`redact_tool_arguments()` and `redact_tool_result()` are called in:

- `mcp_proxy/server/aggregated_proxy_server.py` — multi-backend proxy
- `mcp_proxy/server/proxy_server.py` — single-backend proxy

Both call the functions immediately before/after forwarding to the backend,
ensuring every MCP tool call is covered regardless of proxy type.

---

## Detection patterns (regex, zero dependencies)

Same ordered pattern set as `pii_scanner.py` in itsupport-automations:

| Type | Regex anchor | Replacement |
|------|-------------|-------------|
| SSN_DK | Day/month-constrained DDMMYY-NNNN | `[SSN_DK]` |
| SSN_BE | DD.MM.YY-NNN.CC | `[SSN_BE]` |
| SSN_SE | YYYYMMDD-NNNN / YYMMDD[-+]NNNN | `[SSN_SE]` |
| SSN_FI | DDMMYY[-A]NNNC | `[SSN_FI]` |
| SSN_NO | 11 digits | `[SSN_NO]` |
| IBAN_NORDIC | SE/NO/FI/DK/NL/BE + check + account | `[IBAN_NORDIC]` |
| EMAIL | RFC 5321 local@domain | `[EMAIL]` |
| GITHUB_TOKEN | ghp_ + 36 alphanum | `[GITHUB_TOKEN]` |
| OPENAI_KEY | sk[-proj]-… ≥20 chars | `[OPENAI_KEY]` |
| STRIPE_KEY | pk_/sk_ live/test | `[STRIPE_KEY]` |

### Why regex-only (no detect-secrets dependency)?

The proxy handles structured MCP tool calls (SQL query strings, API parameters, JSON rows).
Regex patterns cover the credential types most likely to appear in these payloads with
near-zero false-positive risk and no additional runtime dependencies.

---

## Design constraints

- **Fail-open**: exceptions in `redact_tool_arguments()` / `redact_tool_result()` log a
  warning and return the original value — Claude is never silently blocked.
- **50 KB limit**: only the first 50 KB of each string is scanned to bound latency on
  large Postgres result sets.
- **Binary skip**: strings containing null bytes in the first 512 bytes are passed through
  unchanged (avoids false positives on base64 data).
- **Depth limit**: recursive dict/list scanning capped at depth 10.
- **TextContent only**: in `redact_tool_result()` only `TextContent` items are scanned;
  `ImageContent`, `AudioContent`, and `EmbeddedResource` are never touched.

---

## Running tests

```bash
# From repo root
/opt/homebrew/bin/python3.13 -m pytest tests/proxy/test_pii_redaction.py -v
# 32 passed
```
