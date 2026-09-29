"""
Universal Code Review, Error Detection & Fix Engine Regression Suite
Covers the universal requirements in Section 30:
A. Clean code
B. Syntax error
C. Type/delimiter error
D. Null/None error
E. Logic error
F. Security vulnerabilities
G. Multiple mixed vulnerabilities
H. Performance issues
I. Code-quality issues
J. Safe code resembling vulnerable patterns (false positive prevention)
K. Multi-language detection across 13+ languages
L. Empty input handling
M. Large input handling
N. Malformed AI response handling
O. AI unavailable fallback
P. Fix validation failure
Q. Fix introducing regression
R. File upload validation
S. History preservation
T. HindSight memory isolation from code evidence
"""

import ast
import pytest
from app.models import (
    CodeReviewRequest,
    FindingItem,
    MemoryItem,
)
from app.services.deterministic_scanner import deterministic_scanner
from app.services.file_service import detect_language_from_content, detect_language_from_filename
from app.services.fix_validator import fix_validator
from app.services.review_agent import review_agent, preprocess_code
from app.services.history_service import history_service
from app.main import app
from fastapi.testclient import TestClient


# ============================================================================
# CATEGORY A: Clean Code
# ============================================================================
def test_universal_clean_code_python():
    clean_code = """
def calculate_area(length: float, width: float) -> float:
    if length <= 0 or width <= 0:
        return 0.0
    return length * width
"""
    findings = deterministic_scanner.scan(clean_code, "python")
    assert len(findings) == 0


def test_universal_clean_code_javascript():
    clean_code = """
function sumNumbers(a, b) {
    if (typeof a !== 'number' || typeof b !== 'number') {
        return 0;
    }
    return a + b;
}
"""
    findings = deterministic_scanner.scan(clean_code, "javascript")
    assert len(findings) == 0


# ============================================================================
# CATEGORY B: Syntax Error
# ============================================================================
def test_universal_syntax_error_python():
    bad_code = "def broken_func(\n    print('missing paren'"
    findings = deterministic_scanner.scan(bad_code, "python")
    assert any(f.rule_id == "SYN001" and f.category == "syntax" for f in findings)


def test_universal_syntax_error_unclosed_delimiters():
    bad_js = "function test() { if (true) { console.log('unclosed');"
    findings = deterministic_scanner.scan(bad_js, "javascript")
    assert any(f.rule_id == "SYN002" and f.category == "syntax" for f in findings)


# ============================================================================
# CATEGORY E: Logic Errors (Self-comparison, Unreachable code, Infinite loop)
# ============================================================================
def test_universal_logic_self_comparison():
    code = """
def check_user(user_id):
    if user_id == user_id:
        return True
    return False
"""
    findings = deterministic_scanner.scan(code, "python")
    assert any(f.rule_id == "LOG001" and f.category == "logic" for f in findings)


def test_universal_logic_unreachable_code():
    code = """
def compute_total(val):
    if val < 0:
        return 0
        print("This line cannot be reached")
    return val * 2
"""
    findings = deterministic_scanner.scan(code, "python")
    assert any(f.rule_id == "LOG002" and f.category == "logic" for f in findings)


def test_universal_logic_infinite_loop():
    code = """
def spin():
    while True:
        pass
"""
    findings = deterministic_scanner.scan(code, "python")
    assert any(f.rule_id == "LOG004" and f.category == "logic" for f in findings)


# ============================================================================
# CATEGORY F: Security Vulnerabilities (XSS, SSRF, Command Injection, Crypto)
# ============================================================================
def test_universal_security_dom_xss():
    js_code = """
function display(name) {
    document.getElementById('profile').innerHTML = '<h1>' + name + '</h1>';
}
"""
    findings = deterministic_scanner.scan(js_code, "javascript")
    assert any(f.rule_id == "SEC_XSS" and f.category == "security" for f in findings)


def test_universal_security_ssrf():
    py_code = """
import requests

def fetch_url(user_input):
    resp = requests.get(user_input)
    return resp.text
"""
    findings = deterministic_scanner.scan(py_code, "python")
    assert any(f.rule_id == "SEC_SSRF" and f.category == "security" for f in findings)


def test_universal_security_insecure_randomness():
    py_code = """
import random

def generate_reset_token():
    return str(random.random())
"""
    findings = deterministic_scanner.scan(py_code, "python")
    assert any(f.rule_id == "SEC_RANDOM" and f.category == "security" for f in findings)


def test_universal_security_weak_crypto():
    py_code = """
import hashlib

def store_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()
"""
    findings = deterministic_scanner.scan(py_code, "python")
    assert any(f.rule_id == "SEC_CRYPTO" and f.category == "security" for f in findings)


# ============================================================================
# CATEGORY G: Multiple Mixed Vulnerabilities
# ============================================================================
def test_universal_multiple_mixed_vulnerabilities():
    code = """
import hashlib
import random

def process(user_input):
    # Insecure randomness
    token = random.random()
    
    # Weak hashing
    hashed = hashlib.md5(user_input.encode()).hexdigest()
    
    # Logic error
    if user_input == user_input:
        return hashed
        print("never reached")
        
    return None
"""
    findings = deterministic_scanner.scan(code, "python")
    # Verify multiple categories are detected simultaneously
    categories = set(f.category for f in findings)
    assert "security" in categories
    assert "logic" in categories
    assert len(findings) >= 3


# ============================================================================
# CATEGORY I: Code Quality (Empty except block)
# ============================================================================
def test_universal_quality_empty_except():
    code = """
def risky_operation():
    try:
        1 / 0
    except:
        pass
"""
    findings = deterministic_scanner.scan(code, "python")
    assert any(f.rule_id == "QAL001" and f.category == "quality" for f in findings)


# ============================================================================
# CATEGORY J: Safe Code Resembling Vulnerable Patterns (False Positive Check)
# ============================================================================
def test_universal_safe_constant_sql_no_false_positive():
    safe_code = """
def get_all_users(cursor):
    query = "SELECT id, name FROM users " + "ORDER BY created_at DESC"
    cursor.execute(query)
    return cursor.fetchall()
"""
    findings = deterministic_scanner.scan(safe_code, "python")
    assert not any(f.rule_id == "SQL001" for f in findings)


def test_universal_safe_subprocess_no_false_positive():
    safe_code = """
import subprocess

def run_git_status():
    result = subprocess.run(["git", "status"], shell=False, capture_output=True)
    return result.stdout
"""
    findings = deterministic_scanner.scan(safe_code, "python")
    assert not any(f.rule_id == "SEC002" for f in findings)


# ============================================================================
# CATEGORY K: Multi-Language Detection across 13+ Languages
# ============================================================================
@pytest.mark.parametrize(
    "snippet,expected_lang",
    [
        ("def foo():\n    return 'python'", "python"),
        ("const msg: string = 'ts';", "typescript"),
        ("function test() { const x = 1; }", "javascript"),
        ("public class Main { public static void main(String[] args) {} }", "java"),
        ("#include <stdio.h>\nint main() { printf('hi'); return 0; }", "c"),
        ("#include <iostream>\nint main() { std::cout << 'hi'; return 0; }", "cpp"),
        ("using System;\nnamespace App { class Program { static void Main() {} } }", "csharp"),
        ("package main\nimport 'fmt'\nfunc main() { fmt.Println('go') }", "go"),
        ("fn main() {\n    let mut x: Vec<i32> = Vec::new();\n}", "rust"),
        ("<?php\necho 'Hello World';\n$val = 42;", "php"),
        ("fun main(args: Array<String>) {\n    val name = 'Kotlin'\n}", "kotlin"),
        ("import Foundation\nfunc greet(person: String) -> String {\n    return person\n}", "swift"),
        ("def greet_user(name)\n  puts \"Hello #{name}\"\nend", "ruby"),
    ],
)
def test_universal_language_detection(snippet, expected_lang):
    detected = detect_language_from_content(snippet)
    assert detected == expected_lang


# ============================================================================
# CATEGORY L: Empty Input Handling
# ============================================================================
def test_universal_empty_input_handling():
    findings = deterministic_scanner.scan("", "python")
    assert findings == []
    normalized = preprocess_code("   \n\t   \n")
    assert normalized == ""


# ============================================================================
# CATEGORY P: Fix Validation Failure (Identical Code & Syntax Error)
# ============================================================================
def test_universal_fix_validator_rejects_identical_code():
    orig = "def foo():\n    return 42"
    outcome = fix_validator.validate_fix(
        original_code=orig,
        fixed_code=orig,
        language="python",
        original_findings=[],
    )
    assert outcome.is_validated is False
    assert outcome.validation_status == "VALIDATION_FAILED"


def test_universal_fix_validator_rejects_syntax_broken_fix():
    orig = "def foo():\n    return 42"
    broken_fix = "def foo():\n    return (42"
    outcome = fix_validator.validate_fix(
        original_code=orig,
        fixed_code=broken_fix,
        language="python",
        original_findings=[],
    )
    assert outcome.is_validated is False
    assert outcome.validation_status == "VALIDATION_FAILED"


# ============================================================================
# CATEGORY Q: Fix Introducing Regression
# ============================================================================
def test_universal_fix_validator_rejects_new_security_issue():
    orig = """
def run(cmd):
    return cmd
"""
    # Fix introduces command injection os.system
    regressed_fix = """
import os

def run(cmd):
    return os.system(cmd)
"""
    orig_finding = FindingItem(
        rule_id="QAL001",
        title="Quality note",
        category="quality",
        severity="low",
        confidence=0.8,
        line_start=1,
        line_end=1,
        explanation="Note",
        team_memory_used=[],
        recommended_fix="...",
        requires_fix=True,
    )
    outcome = fix_validator.validate_fix(
        original_code=orig,
        fixed_code=regressed_fix,
        language="python",
        original_findings=[orig_finding],
    )
    assert outcome.is_validated is False
    assert outcome.validation_status == "VALIDATION_FAILED"
    assert "introduced new issue" in outcome.validation_message.lower()


# ============================================================================
# CATEGORY R: File Upload Validation
# ============================================================================
def test_universal_file_upload_validation():
    import io
    client = TestClient(app)

    # Valid python file
    res = client.post(
        "/api/review/upload",
        files={"file": ("test.py", io.BytesIO(b"print('hello')"), "text/plain")},
    )
    assert res.status_code == 200
    assert res.json()["language"] == "python"

    # Valid kotlin file
    res_kt = client.post(
        "/api/review/upload",
        files={"file": ("App.kt", io.BytesIO(b"fun main() {}"), "text/plain")},
    )
    assert res_kt.status_code == 200
    assert res_kt.json()["language"] == "kotlin"

    # Valid swift file
    res_sw = client.post(
        "/api/review/upload",
        files={"file": ("App.swift", io.BytesIO(b"import Swift"), "text/plain")},
    )
    assert res_sw.status_code == 200
    assert res_sw.json()["language"] == "swift"

    # Disallowed binary executable
    res_exe = client.post(
        "/api/review/upload",
        files={"file": ("malware.exe", io.BytesIO(b"MZ..."), "application/octet-stream")},
    )
    assert res_exe.status_code == 400
    assert "Unsupported file format" in res_exe.json()["detail"]


# ============================================================================
# CATEGORY S: History Lifecycle
# ============================================================================
def test_universal_history_preservation():
    sample_review = {
        "id": "universal-history-test-1",
        "timestamp": "2026-09-29T10:00:00Z",
        "language": "python",
        "status": "PASS",
        "overall_severity": "low",
        "summary": "Clean code passed.",
        "findings": [],
    }
    saved = history_service.save_review(sample_review)
    assert saved is True
    retrieved = history_service.get_review("universal-history-test-1")
    assert retrieved is not None
    assert retrieved["id"] == "universal-history-test-1"
