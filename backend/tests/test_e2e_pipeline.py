"""
End-to-End Pipeline Tests for TeamCode AI.
Tests the full review pipeline with live Groq + Hindsight services.
Run with: pytest tests/test_e2e_pipeline.py -v -s
"""
import pytest
from app.models import CodeReviewRequest
from app.services.review_agent import review_agent
from app.services.deterministic_scanner import deterministic_scanner
from app.services.llm_service import llm_service
from app.services.hindsight_service import hindsight_service


VULNERABLE_SQL_CODE = (
    "def get_user(db, username):\n"
    "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
    "    cursor = db.cursor()\n"
    "    cursor.execute(query)\n"
    "    return cursor.fetchone()\n"
)

SAFE_SQL_CODE = (
    "def get_user(db, username):\n"
    "    cursor = db.cursor()\n"
    "    query = \"SELECT * FROM users WHERE username = %s\"\n"
    "    cursor.execute(query, (username,))\n"
    "    return cursor.fetchone()\n"
)

NORMAL_CODE = (
    "def calculate_discount(price: float, discount_percent: float) -> float:\n"
    "    if discount_percent < 0 or discount_percent > 100:\n"
    "        raise ValueError('Invalid discount percentage')\n"
    "    return price * (1.0 - discount_percent / 100.0)\n"
)


# ─────────────────────────────────────────────────────────────────────────────
# Section 1: Pure deterministic scanner (no network required)
# ─────────────────────────────────────────────────────────────────────────────

class TestDeterministicScanner:
    def test_vulnerable_sql_detects_sql001(self):
        """Vulnerable f-string SQL must trigger SQL001."""
        findings = deterministic_scanner.scan(VULNERABLE_SQL_CODE, "python")
        sql001 = [f for f in findings if f.rule_id == "SQL001"]
        assert len(sql001) >= 1, f"Expected SQL001, got: {[f.rule_id for f in findings]}"
        assert sql001[0].severity == "high"
        assert sql001[0].line_start == 2
        assert "username" in (sql001[0].evidence or "")

    def test_safe_sql_no_sql001(self):
        """Parameterized SQL must NOT trigger SQL001."""
        findings = deterministic_scanner.scan(SAFE_SQL_CODE, "python")
        sql001 = [f for f in findings if f.rule_id == "SQL001"]
        assert len(sql001) == 0, f"False positive SQL001 on safe code: {[f.evidence for f in sql001]}"

    def test_normal_code_no_findings(self):
        """Normal business logic code must produce zero findings."""
        findings = deterministic_scanner.scan(NORMAL_CODE, "python")
        assert len(findings) == 0, f"Unexpected findings on clean code: {[f.rule_id for f in findings]}"

    def test_multiple_runs_deterministic(self):
        """Same code must produce identical results every time (determinism)."""
        results = [deterministic_scanner.scan(VULNERABLE_SQL_CODE, "python") for _ in range(5)]
        rule_sets = [tuple(sorted(f.rule_id for f in r)) for r in results]
        assert len(set(rule_sets)) == 1, "Scanner produced non-deterministic results!"


# ─────────────────────────────────────────────────────────────────────────────
# Section 2: Full review pipeline (requires live API keys)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(
    not llm_service.is_available()[0],
    reason="Groq LLM not configured - skipping live pipeline tests"
)
class TestLivePipeline:
    def test_vulnerable_sql_full_review(self):
        """Full pipeline: vulnerable SQL must produce SQL001 and an auto-fix."""
        req = CodeReviewRequest(code=VULNERABLE_SQL_CODE, language="python")
        result = review_agent.review_code(req)

        assert result.status == "FINDINGS", f"Expected FINDINGS, got {result.status}"
        assert result.overall_severity in ("high", "critical"), (
            f"Expected high/critical severity, got {result.overall_severity}"
        )

        sql001_findings = [f for f in result.findings if f.rule_id == "SQL001"]
        assert len(sql001_findings) >= 1, (
            f"SQL001 not found in pipeline result. Findings: {[f.rule_id for f in result.findings]}"
        )

        assert result.auto_fix is not None, "Auto-fix result must be present"
        assert result.auto_fix.fixed_code is not None, "Fixed code must be present"
        assert len(result.auto_fix.fixed_code.strip()) > 0, "Fixed code must not be empty"
        assert result.auto_fix.differs_from_original is True, (
            "Fixed code must differ from original vulnerable code"
        )

        fixed = result.auto_fix.fixed_code
        assert 'f"SELECT' not in fixed and "f'SELECT" not in fixed, (
            "Fixed code still contains f-string SQL construction!"
        )

        print(f"\n[PASS] SQL001 findings: {len(sql001_findings)}")
        print(f"       Severity: {result.overall_severity}")
        print(f"       Validation: {result.auto_fix.validation_status}")
        print(f"       Fixed code:\n{result.auto_fix.fixed_code[:300]}")

    def test_safe_sql_full_review_no_sql001(self):
        """Full pipeline: safe parameterized SQL must NOT produce SQL001."""
        req = CodeReviewRequest(code=SAFE_SQL_CODE, language="python")
        result = review_agent.review_code(req)

        sql001_findings = [f for f in result.findings if f.rule_id == "SQL001"]
        assert len(sql001_findings) == 0, (
            f"False positive SQL001 on safe parameterized query: "
            f"{[f.evidence for f in sql001_findings]}"
        )

        if result.status == "PASS":
            assert result.auto_fix is None or result.auto_fix.fixed_code is None, (
                "Should not generate fixed code for clean code"
            )

        print(f"\n[PASS] Safe SQL review: no SQL001 detected. Status: {result.status}")

    def test_normal_code_no_security_findings(self):
        """Full pipeline: clean business logic should not trigger security findings."""
        req = CodeReviewRequest(code=NORMAL_CODE, language="python")
        result = review_agent.review_code(req)

        security_findings = [f for f in result.findings if f.category == "security"]
        assert len(security_findings) == 0, (
            f"Unexpected security findings on clean code: "
            f"{[(f.rule_id, f.title) for f in security_findings]}"
        )
        print(f"\n[PASS] Clean code review: {result.status} | {len(result.findings)} total findings")

    def test_deterministic_findings_survive_llm_override(self):
        """
        CORE DEFENSIVE TEST: Even if LLM says PASS, SQL001 from the deterministic
        scanner must appear in the final result. LLM cannot override a confirmed
        security finding.
        """
        req = CodeReviewRequest(code=VULNERABLE_SQL_CODE, language="python")
        result = review_agent.review_code(req)

        any_sql001 = [f for f in result.findings if f.rule_id == "SQL001"]
        assert len(any_sql001) >= 1, (
            f"CRITICAL: Deterministic SQL001 was dropped from final result! "
            f"review_state={result.review_state}, findings={[f.rule_id for f in result.findings]}"
        )
        print(f"\n[PASS] Deterministic findings survived LLM: {len(any_sql001)} SQL001(s)")

    def test_hindsight_memory_status_valid(self):
        """Hindsight memory retrieval must return a valid status (not error)."""
        if not hindsight_service.is_available()[0]:
            pytest.skip("Hindsight not configured")

        req = CodeReviewRequest(code=VULNERABLE_SQL_CODE, language="python")
        result = review_agent.review_code(req)

        assert result.memory_status in ("recalled", "none_found"), (
            f"Unexpected memory status: {result.memory_status} | {result.memory_message}"
        )
        print(f"\n[PASS] Hindsight status: {result.memory_status} | {result.memory_message}")

    def test_review_again_consistent_results(self):
        """Running review twice on same code must produce consistent SQL001 detection."""
        req = CodeReviewRequest(code=VULNERABLE_SQL_CODE, language="python")

        result1 = review_agent.review_code(req)
        result2 = review_agent.review_code(req)

        count1 = len([f for f in result1.findings if f.rule_id == "SQL001"])
        count2 = len([f for f in result2.findings if f.rule_id == "SQL001"])

        assert count1 >= 1, "First run: SQL001 missing"
        assert count2 >= 1, "Second run: SQL001 missing (inconsistent!)"
        print(f"\n[PASS] Consistent results: run1={count1} SQL001, run2={count2} SQL001")
