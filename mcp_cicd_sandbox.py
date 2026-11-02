"""Synthetic MCP Tool Policy Guard, GitHub Actions PR Security Gate & Postgres Telemetry Sandbox.

IMPORTANT DISCLOSURE:
This module is a synthetic demonstration created specifically for an Upwork proposal (2117031896738273450).
It operates on in-memory synthetic fixtures only and is NOT a prior commercial client project.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"postgres(?:ql)?://[^\s:@]+:[^\s@]+@", re.I),
]

DESTRUCTIVE_SQL_PATTERN = re.compile(r"\b(?:DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM\s+\w+\s*;)\b", re.I)


@dataclass(frozen=True)
class MCPToolCall:
    tool_name: str
    arguments: dict[str, Any]
    caller_role: str = "ci_worker"


@dataclass
class PRGateDecision:
    pr_number: int
    commit_sha: str
    approved_for_merge: bool
    risk_score: float
    blocking_reasons: list[str] = field(default_factory=list)
    telemetry_row: dict[str, Any] = field(default_factory=dict)


def validate_mcp_tool_call(call: MCPToolCall, allowed_tools: set[str]) -> dict[str, Any]:
    """Enforce allowlist, secret-redaction, and destructive-SQL policy on MCP tool invocations."""
    if call.tool_name not in allowed_tools:
        return {"allowed": False, "reason": f"Tool '{call.tool_name}' is not in allowed_tools"}

    serialized = str(call.arguments)
    for pat in SECRET_PATTERNS:
        if pat.search(serialized):
            return {"allowed": False, "reason": "Potential credential/secret leaked in MCP tool arguments"}

    if DESTRUCTIVE_SQL_PATTERN.search(serialized):
        return {"allowed": False, "reason": "Destructive SQL statement blocked by MCP policy guard"}

    payload_hash = hashlib.sha256(f"{call.tool_name}|{serialized}".encode("utf-8")).hexdigest()
    return {"allowed": True, "reason": "ok", "payload_sha256": payload_hash}


def evaluate_pr_ci_gate(
    pr_number: int,
    commit_sha: str,
    diff_text: str,
    tests_passed: int,
    tests_failed: int,
    coverage_pct: float,
    min_coverage_pct: float = 80.0,
) -> PRGateDecision:
    """Evaluate a GitHub Actions PR diff for leaked secrets, dangerous migrations, test failures,
    and minimum test coverage, returning a structured PostgreSQL telemetry payload.
    """
    if pr_number <= 0 or not commit_sha:
        raise ValueError("pr_number and commit_sha are required")

    reasons: list[str] = []
    risk = 0.05

    for pat in SECRET_PATTERNS:
        if pat.search(diff_text or ""):
            reasons.append("Leaked credential/secret pattern detected in PR diff")
            risk += 0.60
            break

    if DESTRUCTIVE_SQL_PATTERN.search(diff_text or ""):
        reasons.append("Unprotected DROP/TRUNCATE/broad DELETE migration in PR diff")
        risk += 0.45

    if tests_failed > 0 or tests_passed <= 0:
        reasons.append(f"CI test suite failed (passed={tests_passed}, failed={tests_failed})")
        risk += 0.50

    if coverage_pct < min_coverage_pct:
        reasons.append(f"Coverage {coverage_pct:.1f}% below threshold {min_coverage_pct:.1f}%")
        risk += 0.25

    risk = round(min(1.0, risk), 2)
    approved = len(reasons) == 0
    telemetry = {
        "pr_number": pr_number,
        "commit_sha": commit_sha,
        "status": "PASS" if approved else "BLOCKED",
        "risk_score": risk,
        "tests_passed": tests_passed,
        "tests_failed": tests_failed,
        "coverage_pct": round(coverage_pct, 2),
        "blocking_count": len(reasons),
    }
    return PRGateDecision(
        pr_number=pr_number,
        commit_sha=commit_sha,
        approved_for_merge=approved,
        risk_score=risk,
        blocking_reasons=reasons,
        telemetry_row=telemetry,
    )
