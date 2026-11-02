# MCP Integration, CI/CD Code-Review Gate & PostgreSQL Telemetry Sandbox (Synthetic Demo)

> **Important Disclosure:** This repository is a **synthetic Python demonstration** created specifically to illustrate MCP tool-call policy guards, GitHub Actions PR security/coverage gates, and PostgreSQL run-telemetry logging for an Upwork proposal (`2117031896738273450`). It uses synthetic in-memory fixtures only and is **not** a prior commercial client project.

## What This Synthetic Sandbox Demonstrates

1. **MCP Tool Policy & Secret/SQL Guard (`validate_mcp_tool_call`)**: Enforces tool allowlists, blocks accidental credential/token exposure (`ghp_*`, `sk-*`, AWS keys, Postgres DSNs), and prevents destructive SQL statements (`DROP TABLE`, `TRUNCATE`, broad `DELETE`) before MCP tool execution.
2. **Automated GitHub Actions PR Review Gate (`evaluate_pr_ci_gate`)**: Evaluates PR diffs for secret patterns, unsafe migrations, unit-test pass/fail counts, and minimum test coverage thresholds, producing a structured PostgreSQL telemetry row (`PASS` vs. `BLOCKED`).

## Run Unit Tests

```bash
pytest -v
```
