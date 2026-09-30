"""
AI Review Accuracy, Fallback & Fix Validation Tests.
Validates:
- Graceful degradation when LLM service is unavailable/fails
- Rigorous AutoFix validation (cannot mark VERIFIED if vulnerability persists)
- Multi-issue and syntax-error handling
"""
import pytest
from unittest.mock import patch
from app.models import CodeReviewRequest, FindingItem
from app.services.review_agent import review_agent
from app.services.deterministic_scanner import deterministic_scanner


def test_llm_failure_graceful_degradation(monkeypatch):
    """When LLM throws an exception, review does not crash and preserves deterministic findings."""
    from app.services.llm_service import llm_service

    vulnerable_sql = (
        "def get_user(db, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    cursor = db.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchone()\n"
    )

    # Force LLM service to simulate an outage / rate limit
    monkeypatch.setattr(
        llm_service,
        "execute_review",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("Groq 429 Rate limit exceeded"))
    )

    req = CodeReviewRequest(code=vulnerable_sql, language="python")
    res = review_agent.review_code(req)

    assert res.review_state == "AI_PARTIAL_FAILURE"
    assert res.status == "FINDINGS"
    # Deterministic findings must survive!
    sql_findings = [f for f in res.findings if f.rule_id == "SQL001"]
    assert len(sql_findings) >= 1
    assert sql_findings[0].severity == "high"


def test_fix_validator_rejects_unresolved_vulnerability(monkeypatch):
    """CRITICAL: If the generated fix still contains the vulnerability, validation MUST FAIL."""
    from app.services.llm_service import llm_service

    vulnerable_sql = (
        "def get_user(db, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    cursor = db.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchone()\n"
    )

    # Simulate an LLM that generated a bad fix still using string concatenation in SQL
    bad_fix = {
        "fixed_code": (
            "def get_user(db, username):\n"
            "    query = 'SELECT * FROM users WHERE username = \\'' + username + '\\''\n"
            "    cursor = db.cursor()\n"
            "    cursor.execute(query)\n"
            "    return cursor.fetchone()\n"
        ),
        "changes_made": ["Attempted fix using concatenation"],
        "remaining_risks": [],
    }

    monkeypatch.setattr(llm_service, "execute_auto_fix", lambda *args, **kwargs: bad_fix)

    req = CodeReviewRequest(code=vulnerable_sql, language="python")
    res = review_agent.review_code(req)

    assert res.auto_fix is not None
    assert res.auto_fix.validation_status == "VALIDATION_FAILED"
    assert res.auto_fix.is_validated is False
    assert res.auto_fix.vulnerabilities_resolved is False


def test_fix_validator_rejects_identical_code(monkeypatch):
    """If fixed code is identical to original, validation MUST FAIL."""
    from app.services.llm_service import llm_service

    code = (
        "def get_user(db, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    cursor = db.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchone()\n"
    )

    identical_fix = {
        "fixed_code": code,
        "changes_made": [],
        "remaining_risks": [],
    }

    monkeypatch.setattr(llm_service, "execute_auto_fix", lambda *args, **kwargs: identical_fix)

    req = CodeReviewRequest(code=code, language="python")
    res = review_agent.review_code(req)

    assert res.auto_fix is not None
    assert res.auto_fix.validation_status == "VALIDATION_FAILED"
    assert res.auto_fix.differs_from_original is False
    assert res.auto_fix.is_validated is False


def test_fix_validator_rejects_syntax_error_code(monkeypatch):
    """If generated fix introduces Python syntax errors, validation MUST FAIL."""
    from app.services.llm_service import llm_service

    code = (
        "def get_user(db, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    cursor = db.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchone()\n"
    )

    syntax_broken_fix = {
        "fixed_code": "def get_user(db, username):\n    query = (syntax error invalid python!!",
        "changes_made": ["Broken fix"],
        "remaining_risks": [],
    }

    monkeypatch.setattr(llm_service, "execute_auto_fix", lambda *args, **kwargs: syntax_broken_fix)

    req = CodeReviewRequest(code=code, language="python")
    res = review_agent.review_code(req)

    assert res.auto_fix is not None
    assert res.auto_fix.validation_status == "VALIDATION_FAILED"
    assert res.auto_fix.is_validated is False


def test_multi_issue_code_detection():
    """Detects multiple distinct vulnerabilities across functions."""
    code = (
        "import os\n"
        "API_KEY = 'mock_scanner_token_key_abcdef987654321'\n"
        "\n"
        "def run_sql(db, val):\n"
        "    query = f'SELECT * FROM t WHERE v = {val}'\n"
        "    db.execute(query)\n"
        "\n"
        "def run_cmd(arg):\n"
        "    os.system('ls ' + arg)\n"
    )
    findings = deterministic_scanner.scan(code, "python")
    rule_ids = set(f.rule_id for f in findings)
    assert "SQL001" in rule_ids
    assert "SEC001" in rule_ids
    assert "CMD001" in rule_ids


def test_syntax_error_in_submitted_code_does_not_crash_scanner():
    """Scanner must handle code with syntax errors safely without raising exceptions."""
    broken_code = "def foo(::\n   broken syntax !!! %%%"
    findings = deterministic_scanner.scan(broken_code, "python")
    assert isinstance(findings, list)


def test_review_agent_handles_string_findings_gracefully(monkeypatch):
    """Review agent must handle LLM returning strings instead of dicts in findings without crashing."""
    from app.services.llm_service import llm_service

    code = "def add(a, b):\n    return a + b\n"
    # Simulate LLM returning finding strings instead of dictionaries or a raw string for findings
    raw_llm_response = {
        "status": "FINDINGS",
        "summary": "Review completed with plain text finding strings",
        "overall_severity": "low",
        "confidence": 0.85,
        "findings": [
            "Variable naming could be more descriptive",
            "Missing type annotations and docstrings",
        ],
        "explanation": "Suggestions provided as string items."
    }

    monkeypatch.setattr(llm_service, "execute_review", lambda *args, **kwargs: raw_llm_response)
    monkeypatch.setattr(
        llm_service,
        "execute_auto_fix",
        lambda *args, **kwargs: {
            "fixed_code": code,
            "changes_made": ["No change"],
            "remaining_risks": [],
        },
    )

    req = CodeReviewRequest(code=code, language="python")
    res = review_agent.review_code(req)

    assert res.status == "FINDINGS"
    assert len(res.findings) == 2
    for finding in res.findings:
        assert isinstance(finding.title, str)
        assert isinstance(finding.explanation, str)
        assert finding.severity in ("info", "low", "medium", "high", "critical")

