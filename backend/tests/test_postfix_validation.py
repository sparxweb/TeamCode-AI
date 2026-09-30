"""
Comprehensive Post-Fix Validation and False-Positive Regression Test Suite.
Tests Section 15 requirements across 20 distinct categories:
1. Python SQL injection
2. Python command injection (including ping_server)
3. Python hardcoded secret
4. Python insecure deserialization
5. Python path traversal
6. Python weak crypto / password hashing
7. JavaScript XSS
8. JavaScript hardcoded secret
9. Java SQL injection
10. Java insecure credentials / auth
11. C buffer overflow (gets)
12. C++ unsafe memory (strcpy)
13. Go SQL injection
14. PHP SQL injection
15. TypeScript XSS
16. Logic bug (self comparison)
17. Null/None handling bug
18. Performance issue (N+1 query)
19. Syntax error detection and resolution
20. Clean secure code (zero false positives)
21. End-to-end "Review Fixed Code" flow with resolution summary
"""
import pytest
from app.models import CodeReviewRequest, FindingItem
from app.services.deterministic_scanner import deterministic_scanner
from app.services.fix_validator import fix_validator
from app.services.review_agent import review_agent


# 1. Python SQL Injection
def test_category_01_python_sql_injection():
    original = 'def get_user(db, u):\n    query = f"SELECT * FROM users WHERE username = \'{u}\'"\n    return db.execute(query).fetchall()'
    fixed = 'def get_user(db, u):\n    query = "SELECT * FROM users WHERE username = %s"\n    return db.execute(query, (u,)).fetchall()'

    orig_findings = deterministic_scanner.scan(original, "python")
    assert any(f.rule_id == "SQL001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "python", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "SQL001" and f.status == "RESOLVED" for f in outcome.resolved_findings)
    assert len(outcome.new_findings) == 0


# 2. Python Command Injection (ping_server)
def test_category_02_python_command_injection_ping_server():
    original = (
        "import subprocess\n\n"
        "def ping_server(host):\n"
        '    command = "ping -c 1 " + host\n'
        "    result = subprocess.run(command, shell=True, capture_output=True, text=True)\n"
        "    return result.stdout\n"
    )
    fixed = (
        "import subprocess\n"
        "import re\n\n"
        "def ping_server(host: str) -> str:\n"
        '    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):\n'
        '        raise ValueError("Invalid host")\n\n'
        "    result = subprocess.run(\n"
        '        ["ping", "-c", "1", host],\n'
        "        capture_output=True,\n"
        "        text=True,\n"
        "        timeout=5,\n"
        "    )\n"
        "    result.check_returncode()\n"
        "    return result.stdout\n"
    )

    orig_findings = deterministic_scanner.scan(original, "python")
    assert any(f.rule_id == "CMD001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "python", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "CMD001" and f.status == "RESOLVED" for f in outcome.resolved_findings)
    assert len(outcome.new_findings) == 0
    # Portability note should be present as informational, not a security vulnerability
    assert len(outcome.portability_notes) > 0


# 3. Python Hardcoded Secret
def test_category_03_python_hardcoded_secret():
    original = 'import os\nDATABASE_PASSWORD = "super_secret_db_pass_123456789"\ndef connect(db):\n    return db.connect(password=DATABASE_PASSWORD)'
    fixed = 'import os\nDATABASE_PASSWORD = os.getenv("DB_PASSWORD", "")\ndef connect(db):\n    return db.connect(password=DATABASE_PASSWORD)'

    orig_findings = deterministic_scanner.scan(original, "python")
    assert any(f.rule_id == "SEC001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "python", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "SEC001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 4. Python Insecure Deserialization
def test_category_04_python_insecure_deserialization():
    original = 'import pickle\ndef load_data(payload):\n    return pickle.loads(payload)'
    fixed = 'import json\ndef load_data(payload):\n    return json.loads(payload)'

    orig_findings = deterministic_scanner.scan(original, "python")
    assert any(f.rule_id == "DES001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "python", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "DES001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 5. Python Path Traversal
def test_category_05_python_path_traversal():
    original = 'def read_user_file(filename):\n    with open("/data/files/" + filename, "r") as f:\n        return f.read()'
    fixed = 'import os\ndef read_user_file(filename):\n    safe_name = os.path.basename(filename)\n    with open("/data/files/" + safe_name, "r") as f:\n        return f.read()'

    orig_findings = deterministic_scanner.scan(original, "python")
    assert any(f.rule_id == "PATH001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "python", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "PATH001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 6. Python Weak Password Hashing / Crypto
def test_category_06_python_weak_crypto():
    original = 'import hashlib\ndef hash_password(p):\n    return hashlib.md5(p.encode()).hexdigest()'
    fixed = 'import hashlib\ndef hash_password(p):\n    return hashlib.sha256(p.encode()).hexdigest()'

    orig_findings = deterministic_scanner.scan(original, "python")
    assert any(f.rule_id == "SEC_CRYPTO" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "python", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "SEC_CRYPTO" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 7. JavaScript XSS
def test_category_07_javascript_xss():
    original = 'function displayUser(input) {\n  document.getElementById("output").innerHTML = "<div>" + input + "</div>";\n}'
    fixed = 'function displayUser(input) {\n  const el = document.getElementById("output");\n  el.textContent = input;\n}'

    orig_findings = deterministic_scanner.scan(original, "javascript")
    assert any(f.rule_id == "SEC_XSS" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "javascript", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "SEC_XSS" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 8. JavaScript Hardcoded Secret
def test_category_08_javascript_hardcoded_secret():
    original = 'const API_KEY = "sk_live_99887766554433221100";\nfunction callApi() { return fetch("/api", { headers: { Authorization: API_KEY } }); }'
    fixed = 'const API_KEY = process.env.API_KEY || "";\nfunction callApi() { return fetch("/api", { headers: { Authorization: API_KEY } }); }'

    orig_findings = deterministic_scanner.scan(original, "javascript")
    assert any(f.rule_id == "SEC001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "javascript", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "SEC001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 9. Java SQL Injection
def test_category_09_java_sql_injection():
    original = 'public User findUser(String name) {\n    String sql = "SELECT * FROM users WHERE username = \'" + name + "\'";\n    return db.query(sql);\n}'
    fixed = 'public User findUser(String name) {\n    String sql = "SELECT * FROM users WHERE username = ?";\n    return db.query(sql, name);\n}'

    orig_findings = deterministic_scanner.scan(original, "java")
    assert any(f.rule_id == "SQL001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "java", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert any(f.rule_id == "SQL001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 10. Java Insecure Authentication / Secret
def test_category_10_java_insecure_auth():
    original = 'public class Config {\n    public static final String API_SECRET = "jwt_super_secret_99887766";\n}'
    fixed = 'public class Config {\n    public static final String API_SECRET = System.getenv("API_SECRET");\n}'

    orig_findings = deterministic_scanner.scan(original, "java")
    assert any(f.rule_id == "SEC001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "java", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert any(f.rule_id == "SEC001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 11. C Buffer Overflow (gets)
def test_category_11_c_buffer_overflow():
    original = '#include <stdio.h>\nint main() {\n    char buf[64];\n    gets(buf);\n    return 0;\n}'
    fixed = '#include <stdio.h>\nint main() {\n    char buf[64];\n    fgets(buf, sizeof(buf), stdin);\n    return 0;\n}'

    orig_findings = deterministic_scanner.scan(original, "c")
    assert any(f.rule_id == "MEM001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "c", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert any(f.rule_id == "MEM001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 12. C++ Unsafe Memory Handling (strcpy)
def test_category_12_cpp_unsafe_memory():
    original = '#include <cstring>\nvoid copyData(const char* src) {\n    char dst[32];\n    strcpy(dst, src);\n}'
    fixed = '#include <string>\nvoid copyData(const char* src) {\n    std::string dst = src;\n}'

    orig_findings = deterministic_scanner.scan(original, "cpp")
    assert any(f.rule_id == "MEM001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "cpp", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert any(f.rule_id == "MEM001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 13. Go SQL Injection
def test_category_13_go_sql_injection():
    original = 'func GetUser(db *sql.DB, id string) {\n    query := "SELECT * FROM users WHERE id = \'" + id + "\'"\n    db.Query(query)\n}'
    fixed = 'func GetUser(db *sql.DB, id string) {\n    query := "SELECT * FROM users WHERE id = ?"\n    db.Query(query, id)\n}'

    orig_findings = deterministic_scanner.scan(original, "go")
    assert any(f.rule_id == "SQL001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "go", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert any(f.rule_id == "SQL001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 14. PHP SQL Injection
def test_category_14_php_sql_injection():
    original = '<?php\n$id = $_GET["id"];\n$sql = "SELECT * FROM users WHERE id = " . $id;\n$db->query($sql);\n?>'
    fixed = '<?php\n$id = $_GET["id"];\n$stmt = $db->prepare("SELECT * FROM users WHERE id = :id");\n$stmt->execute(["id" => $id]);\n?>'

    orig_findings = deterministic_scanner.scan(original, "php")
    assert any(f.rule_id == "SQL001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "php", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert any(f.rule_id == "SQL001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 15. TypeScript XSS
def test_category_15_typescript_xss():
    original = 'export function renderAlert(msg: string): void {\n  document.getElementById("alert")!.innerHTML = "<span>" + msg + "</span>";\n}'
    fixed = 'export function renderAlert(msg: string): void {\n  const el = document.getElementById("alert");\n  if (el) el.textContent = msg;\n}'

    orig_findings = deterministic_scanner.scan(original, "typescript")
    assert any(f.rule_id == "SEC_XSS" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "typescript", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "SEC_XSS" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 16. Logic Bug (self comparison)
def test_category_16_logic_bug_self_comparison():
    original = 'def validate(x, y):\n    if x == x:\n        return True\n    return False'
    fixed = 'def validate(x, y):\n    if x == y:\n        return True\n    return False'

    orig_findings = deterministic_scanner.scan(original, "python")
    assert any(f.rule_id == "LOG001" for f in orig_findings)

    outcome = fix_validator.validate_fix(original, fixed, "python", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "LOG001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 17. Null / None Handling Bug
def test_category_17_null_handling_bug():
    original = 'def get_user_len(user):\n    return len(user["name"])'
    fixed = 'def get_user_len(user):\n    if not user or "name" not in user or user["name"] is None:\n        return 0\n    return len(user["name"])'

    # Simulated finding for null handling
    orig_findings = [
        FindingItem(
            rule_id="BUG001",
            title="Unchecked Null/None Pointer Dereference",
            category="bug",
            severity="medium",
            line_start=2,
            line_end=2,
            explanation="user or user['name'] could be None, raising a TypeError.",
            recommended_fix="Add guard check for user and user['name']",
            requires_fix=True,
            evidence='return len(user["name"])',
            validated_by_scanner=False,
        )
    ]

    outcome = fix_validator.validate_fix(original, fixed, "python", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "BUG001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 18. Performance Issue (N+1 Query)
def test_category_18_performance_issue():
    original = 'def load_orders(users):\n    for u in users:\n        db.execute(f"SELECT * FROM orders WHERE user_id = {u.id}")'
    fixed = 'def load_orders(users):\n    user_ids = [u.id for u in users]\n    return db.execute("SELECT * FROM orders WHERE user_id = ANY(%s)", (user_ids,))'

    orig_findings = [
        FindingItem(
            rule_id="PERF001",
            title="N+1 Query In Loop",
            category="performance",
            severity="medium",
            line_start=2,
            line_end=3,
            explanation="Executing database query inside loop causes N+1 performance bottleneck.",
            recommended_fix="Batch fetch orders with single query using IN / ANY",
            requires_fix=True,
            evidence='db.execute(...)',
            validated_by_scanner=False,
        )
    ]

    outcome = fix_validator.validate_fix(original, fixed, "python", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert any(f.rule_id == "PERF001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 19. Syntax Error Detection & Resolution
def test_category_19_syntax_error():
    broken = "def calculate_total(prices\n    return sum(prices)"
    fixed = "def calculate_total(prices):\n    return sum(prices)"

    orig_findings = deterministic_scanner.scan(broken, "python")
    assert any(f.rule_id == "SYN001" for f in orig_findings)

    outcome = fix_validator.validate_fix(broken, fixed, "python", orig_findings)
    assert outcome.vulnerabilities_resolved is True
    assert outcome.validation_status == "VERIFIED"
    assert any(f.rule_id == "SYN001" and f.status == "RESOLVED" for f in outcome.resolved_findings)


# 20. Clean Secure Code (Zero False Positives)
def test_category_20_clean_secure_code_zero_false_positives():
    clean_code = (
        "import os\n"
        "import re\n"
        "import subprocess\n"
        "from typing import Optional\n\n"
        "def safe_ping(host: str, timeout: int = 5) -> str:\n"
        '    """Safely execute ping without shell injection vulnerability."""\n'
        '    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):\n'
        '        raise ValueError("Invalid hostname format")\n\n'
        "    result = subprocess.run(\n"
        '        ["ping", "-c", "1", host],\n'
        "        capture_output=True,\n"
        "        text=True,\n"
        "        timeout=timeout,\n"
        "    )\n"
        "    result.check_returncode()\n"
        "    return result.stdout\n"
    )

    findings = deterministic_scanner.scan(clean_code, "python")
    # Clean code must have 0 high/critical findings
    critical_or_high = [f for f in findings if f.severity in ("high", "critical")]
    assert len(critical_or_high) == 0, f"Expected 0 false positive security findings, found: {critical_or_high}"


# 21. End-to-End "Review Fixed Code" Flow
def test_review_fixed_code_flow_resolves_all_issues():
    original_code = (
        "import subprocess\n\n"
        "def ping_server(host):\n"
        '    command = "ping -c 1 " + host\n'
        "    result = subprocess.run(command, shell=True, capture_output=True, text=True)\n"
        "    return result.stdout\n"
    )
    fixed_code = (
        "import subprocess\n"
        "import re\n\n"
        "def ping_server(host: str) -> str:\n"
        '    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):\n'
        '        raise ValueError("Invalid host")\n\n'
        "    result = subprocess.run(\n"
        '        ["ping", "-c", "1", host],\n'
        "        capture_output=True,\n"
        "        text=True,\n"
        "        timeout=5,\n"
        "    )\n"
        "    result.check_returncode()\n"
        "    return result.stdout\n"
    )

    orig_findings = deterministic_scanner.scan(original_code, "python")
    assert any(f.rule_id == "CMD001" for f in orig_findings)

    # Submit fixed code with is_fixed_code_review=True
    req = CodeReviewRequest(
        code=fixed_code,
        language="python",
        original_code=original_code,
        original_findings=orig_findings,
        is_fixed_code_review=True,
    )
    res = review_agent.review_code(req)

    assert res.status == "PASS"
    assert res.review_state in ("NO_FINDINGS", "AI_REVIEW_SUCCESS")
    assert len(res.findings) == 0
    assert len(res.resolved_findings) >= 1
    assert any(f.rule_id == "CMD001" and f.status == "RESOLVED" for f in res.resolved_findings)
    assert len(res.new_findings) == 0
    assert "Original issue(s) successfully RESOLVED" in res.summary
    assert "0 new issues introduced" in res.summary
    assert "Validation: PASSED" in res.summary
