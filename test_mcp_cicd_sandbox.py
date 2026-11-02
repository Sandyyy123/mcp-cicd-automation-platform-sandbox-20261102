"""Unit tests for the synthetic MCP + CI/CD automation platform sandbox."""
from __future__ import annotations

import pytest
from mcp_cicd_sandbox import MCPToolCall, evaluate_pr_ci_gate, validate_mcp_tool_call


ALLOWED = {"github_pr_comment", "postgres_readonly_query", "run_pytest_shard"}


def test_validate_mcp_tool_call_allows_clean_invocation():
    call = MCPToolCall("postgres_readonly_query", {"sql": "SELECT count(*) FROMworkflow_runs WHERE status = 'PASS';"})
    res = validate_mcp_tool_call(call, ALLOWED)
    assert res["allowed"] is True
    assert len(res["payload_sha256"]) == 64


def test_validate_mcp_tool_call_blocks_unlisted_tool():
    call = MCPToolCall("shell_exec_root", {"cmd": "rm -rf /"})
    res = validate_mcp_tool_call(call, ALLOWED)
    assert res["allowed"] is False
    assert "not in allowed_tools" in res["reason"]


def test_validate_mcp_tool_call_blocks_secret_in_arguments():
    call = MCPToolCall("github_pr_comment", {"body": "Token is ghp_1234567890abcdefghijklmnop"})
    res = validate_mcp_tool_call(call, ALLOWED)
    assert res["allowed"] is False
    assert "credential/secret" in res["reason"]


def test_validate_mcp_tool_call_blocks_destructive_sql():
    call = MCPToolCall("postgres_readonly_query", {"sql": "DROP TABLE production_events;"})
    res = validate_mcp_tool_call(call, ALLOWED)
    assert res["allowed"] is False
    assert "Destructive SQL" in res["reason"]


def test_evaluate_pr_ci_gate_passes_clean_diff_and_high_coverage():
    dec = evaluate_pr_ci_gate(
        pr_number=42,
        commit_sha="a1b2c3d4",
        diff_text="+ def add(a: int, b: int) -> int:\n+     return a + b",
        tests_passed=38,
        tests_failed=0,
        coverage_pct=91.5,
    )
    assert dec.approved_for_merge is True
    assert dec.blocking_reasons == []
    assert dec.telemetry_row["status"] == "PASS"


def test_evaluate_pr_ci_gate_blocks_leaked_dsn_secret():
    dec = evaluate_pr_ci_gate(
        pr_number=43,
        commit_sha="b2c3d4e5",
        diff_text="+ DB_URL = 'postgresql://admin:supersecret@db.internal:5432/prod'",
        tests_passed=20,
        tests_failed=0,
        coverage_pct=88.0,
    )
    assert dec.approved_for_merge is False
    assert any("credential/secret" in r for r in dec.blocking_reasons)


def test_evaluate_pr_ci_gate_blocks_low_coverage_and_failed_tests():
    dec = evaluate_pr_ci_gate(
        pr_number=44,
        commit_sha="c3d4e5f6",
        diff_text="+ x = 1",
        tests_passed=10,
        tests_failed=2,
        coverage_pct=65.0,
    )
    assert dec.approved_for_merge is False
    assert len(dec.blocking_reasons) == 2


def test_evaluate_pr_ci_gate_rejects_invalid_pr_number():
    with pytest.raises(ValueError, match="pr_number and commit_sha"):
        evaluate_pr_ci_gate(0, "", "", 1, 0, 90.0)
