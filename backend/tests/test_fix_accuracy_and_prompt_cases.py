"""
Section 22 Comprehensive Fix Validation & Accuracy Test Suite.
Tests:
- TEST 1: SQL Injection detection & verified parameterized fix
- TEST 2: Correct parameterized SQL (no false positive, no unnecessary fix)
- TEST 3: Hardcoded password with undefined database (externalized, but NOT VERIFIED -> VALIDATION_LIMITED)
- TEST 4: Environment variable usage (no false positive secret finding)
- TEST 5: Invalid Python syntax in generated fix (VALIDATION_FAILED)
- TEST 6: Missing required import (os.getenv without import os -> VALIDATION_FAILED)
- TEST 7: Clean code (0 findings, no fix generated)
- TEST 8: Multiple distinct issues reported together
- Edge cases: Invented library rejection, function signature preservation
"""
import pytest
from app.models import CodeReviewRequest
from app.services.review_agent import review_agent
from app.services.deterministic_scanner import deterministic_scanner
from app.services.fix_validator import fix_validator
from app.services.llm_service import llm_service


def test_section22_test1_sql_injection_verified_fix(monkeypatch):
    """
    TEST 1 — SQL injection
    Input:
    def get_user(db, username):
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor = db.cursor()
        cursor.execute(query)
        return cursor.fetchone()
    Expected:
    SQL injection finding = YES, Severity = HIGH, Fixed code generated = YES,
    Parameterized query = YES, Fixed code validation = PASS (VERIFIED)
    """
    vulnerable_sql = (
        "def get_user(db, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    cursor = db.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchone()\n"
    )

    valid_fixed_code = (
        "def get_user(db, username):\n"
        "    query = \"SELECT * FROM users WHERE username = %s\"\n"
        "    cursor = db.cursor()\n"
        "    cursor.execute(query, (username,))\n"
        "    return cursor.fetchone()\n"
    )

    monkeypatch.setattr(
        llm_service,
        "execute_auto_fix",
        lambda *args, **kwargs: {
            "fixed_code": valid_fixed_code,
            "changes_made": ["Used parameterized SQL query with placeholder tuple"],
            "remaining_risks": [],
        },
    )

    req = CodeReviewRequest(code=vulnerable_sql, language="python")
    res = review_agent.review_code(req)

    assert res.status == "FINDINGS"
    sql_findings = [f for f in res.findings if f.rule_id == "SQL001"]
    assert len(sql_findings) >= 1
    assert sql_findings[0].severity == "high"

    assert res.auto_fix is not None
    assert res.auto_fix.validation_status == "VERIFIED"
    assert res.auto_fix.is_validated is True
    assert res.auto_fix.vulnerabilities_resolved is True
    assert "%s" in res.auto_fix.fixed_code or "?" in res.auto_fix.fixed_code


def test_section22_test2_correct_parameterized_sql():
    """
    TEST 2 — Correct parameterized SQL
    Input:
    def get_user(db, username):
        cursor = db.cursor()
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        return cursor.fetchone()
    Expected:
    SQL injection finding = NO, No unnecessary fixed-code box.
    """
    clean_sql = (
        "def get_user(db, username):\n"
        "    cursor = db.cursor()\n"
        "    query = \"SELECT * FROM users WHERE username = %s\"\n"
        "    cursor.execute(query, (username,))\n"
        "    return cursor.fetchone()\n"
    )

    req = CodeReviewRequest(code=clean_sql, language="python")
    res = review_agent.review_code(req)

    sql_findings = [f for f in res.findings if f.rule_id == "SQL001"]
    assert len(sql_findings) == 0


def test_section22_test3_hardcoded_password_undefined_database(monkeypatch):
    """
    TEST 3 — Hardcoded password with undefined database
    Input:
    def connect():
        password = "MySuperSecret123"
        return database.connect(
            host="localhost",
            user="admin",
            password=password
        )
    Expected:
    Hardcoded secret finding = YES
    Fix should externalize the password.
    But the fix must NOT be VERIFIED if `database` is an invented/undefined dependency.
    The validator must recognize that limitation (VALIDATION_LIMITED, is_validated = False).
    """
    secret_code = (
        "def connect():\n"
        "    password = \"MySuperSecret123\"\n"
        "    return database.connect(\n"
        "        host=\"localhost\",\n"
        "        user=\"admin\",\n"
        "        password=password\n"
        "    )\n"
    )

    externalized_fix = (
        "import os\n\n"
        "def connect():\n"
        "    password = os.getenv(\"DB_PASSWORD\")\n"
        "    if not password:\n"
        "        raise RuntimeError(\"Database password not set in environment\")\n"
        "    return database.connect(\n"
        "        host=\"localhost\",\n"
        "        user=\"admin\",\n"
        "        password=password\n"
        "    )\n"
    )

    monkeypatch.setattr(
        llm_service,
        "execute_auto_fix",
        lambda *args, **kwargs: {
            "fixed_code": externalized_fix,
            "changes_made": ["Externalized DB_PASSWORD to environment variable"],
            "remaining_risks": [],
        },
    )

    req = CodeReviewRequest(code=secret_code, language="python")
    res = review_agent.review_code(req)

    # 1. Hardcoded secret finding = YES
    secret_findings = [f for f in res.findings if f.rule_id == "SEC001"]
    assert len(secret_findings) >= 1

    # 2. Fix generated
    assert res.auto_fix is not None
    assert "os.getenv" in res.auto_fix.fixed_code

    # 3. But NOT marked VERIFIED because `database` is an unresolved external dependency!
    assert res.auto_fix.validation_status == "VALIDATION_LIMITED"
    assert res.auto_fix.is_validated is False
    assert "database" in res.auto_fix.validation_message


def test_section22_test4_environment_variable_no_false_positive():
    """
    TEST 4 — Environment variable
    Input:
    import os

    def connect():
        password = os.getenv("DB_PASSWORD")
        return create_connection(password)
    Expected:
    No hardcoded password finding.
    """
    code = (
        "import os\n\n"
        "def connect():\n"
        "    password = os.getenv(\"DB_PASSWORD\")\n"
        "    return create_connection(password)\n"
    )
    findings = deterministic_scanner.scan(code, "python")
    secret_findings = [f for f in findings if f.rule_id == "SEC001"]
    assert len(secret_findings) == 0


def test_section22_test5_invalid_generated_fix(monkeypatch):
    """
    TEST 5 — Invalid generated fix
    Create a test where the model returns invalid Python.
    Example:
    def get_user(db, username)
        return db.get(username)
    Expected:
    Validation = FAIL, VERIFIED = FALSE
    """
    vulnerable_sql = (
        "def get_user(db, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    cursor = db.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchone()\n"
    )

    broken_syntax_fix = (
        "def get_user(db, username)\n"
        "    return db.get(username)\n"
    )

    monkeypatch.setattr(
        llm_service,
        "execute_auto_fix",
        lambda *args, **kwargs: {
            "fixed_code": broken_syntax_fix,
            "changes_made": ["Broken fix syntax"],
            "remaining_risks": [],
        },
    )

    req = CodeReviewRequest(code=vulnerable_sql, language="python")
    res = review_agent.review_code(req)

    assert res.auto_fix is not None
    assert res.auto_fix.validation_status == "VALIDATION_FAILED"
    assert res.auto_fix.is_validated is False
    assert "Syntax error" in res.auto_fix.validation_message


def test_section22_test6_missing_import(monkeypatch):
    """
    TEST 6 — Missing import
    Generated fix:
    def connect():
        password = os.getenv("DB_PASSWORD")
        return database.connect(password=password)
    Expected:
    If `os` is not imported, validation must detect the issue and prevent VERIFIED status.
    """
    secret_code = (
        "def connect():\n"
        "    password = \"MySuperSecret123\"\n"
        "    return database.connect(password=password)\n"
    )

    missing_import_fix = (
        "def connect():\n"
        "    password = os.getenv(\"DB_PASSWORD\")\n"
        "    return database.connect(password=password)\n"
    )

    monkeypatch.setattr(
        llm_service,
        "execute_auto_fix",
        lambda *args, **kwargs: {
            "fixed_code": missing_import_fix,
            "changes_made": ["Externalized to os.getenv without importing os"],
            "remaining_risks": [],
        },
    )

    req = CodeReviewRequest(code=secret_code, language="python")
    res = review_agent.review_code(req)

    assert res.auto_fix is not None
    assert res.auto_fix.validation_status == "VALIDATION_FAILED"
    assert res.auto_fix.is_validated is False
    assert "import os" in res.auto_fix.validation_message


def test_section22_test7_clean_code():
    """
    TEST 7 — Clean code
    Input:
    def add(a, b):
        return a + b
    Expected:
    Findings = 0, No fix generated.
    """
    clean_code = "def add(a, b):\n    return a + b\n"
    req = CodeReviewRequest(code=clean_code, language="python")
    res = review_agent.review_code(req)

    assert res.status == "PASS"
    assert len(res.findings) == 0
    assert res.auto_fix is None


def test_section22_test8_multiple_issues():
    """
    TEST 8 — Multiple issues
    Input containing:
    - hardcoded secret
    - SQL injection
    - unsafe file operation
    Expected:
    All applicable findings should be reported.
    """
    multi_code = (
        "import os\n"
        "password = \"MySuperSecret123\"\n"
        "\n"
        "def get_user(db, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    return db.execute(query)\n"
        "\n"
        "def read_file(user_path):\n"
        "    f = open('data/' + user_path)\n"
        "    return f.read()\n"
    )

    findings = deterministic_scanner.scan(multi_code, "python")
    rule_ids = set(f.rule_id for f in findings)
    assert "SEC001" in rule_ids
    assert "SQL001" in rule_ids
    assert "PATH001" in rule_ids


def test_invented_library_rejection():
    """Validator rejects fix that introduces non-existent external library."""
    orig = (
        "def get_user(db, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    return db.query(query)\n"
    )
    fixed = (
        "def get_user(db, username):\n"
        "    clean = invented_sanitizer.sanitize(username)\n"
        "    return db.query(\"SELECT * FROM users WHERE username = %s\", (clean,))\n"
    )
    orig_f = deterministic_scanner.scan(orig, "python")
    outcome = fix_validator.validate_fix(orig, fixed, "python", orig_f)
    assert outcome.validation_status == "VALIDATION_FAILED"
    assert outcome.is_validated is False
    assert "invented_sanitizer" in outcome.validation_message


def test_altered_function_signature_rejection():
    """Validator rejects fix that renames function or alters parameters."""
    orig = (
        "def get_user(db, username):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    cursor = db.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchone()\n"
    )
    fixed = (
        "def fetch_user_data(db):\n"
        "    query = \"SELECT * FROM users\"\n"
        "    cursor = db.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n"
    )
    orig_f = deterministic_scanner.scan(orig, "python")
    outcome = fix_validator.validate_fix(orig, fixed, "python", orig_f)
    assert outcome.validation_status == "VALIDATION_FAILED"
    assert outcome.is_validated is False
    assert "renamed or omitted" in outcome.validation_message
