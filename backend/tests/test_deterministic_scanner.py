from app.services.deterministic_scanner import deterministic_scanner


def test_1_fstring_sql():
    """TEST 1: f-string SQL -> Expected: HIGH SQL injection."""
    code = '''def get_user(db, username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchone()
'''
    findings = deterministic_scanner.scan(code, "python")
    assert len(findings) >= 1
    sql_findings = [f for f in findings if f.rule_id == "SQL001"]
    assert len(sql_findings) >= 1
    assert sql_findings[0].severity == "high"
    assert sql_findings[0].line_start == 2
    assert "username" in (sql_findings[0].evidence or "")


def test_2_sql_string_concatenation():
    """TEST 2: SQL string concatenation -> Expected: HIGH SQL injection."""
    code = '''def get_user(db, username):
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchone()
'''
    findings = deterministic_scanner.scan(code, "python")
    assert len(findings) >= 1
    sql_findings = [f for f in findings if f.rule_id == "SQL001"]
    assert len(sql_findings) >= 1
    assert sql_findings[0].severity == "high"


def test_3_parameterized_sql():
    """TEST 3: Parameterized SQL -> Expected: 0 SQL injection."""
    code = '''def get_user(db, username):
    cursor = db.cursor()
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()
'''
    findings = deterministic_scanner.scan(code, "python")
    sql_findings = [f for f in findings if f.rule_id == "SQL001"]
    assert len(sql_findings) == 0


def test_4_normal_python_function_no_sql():
    """TEST 4: Normal Python function with no SQL -> Expected: no SQL injection."""
    code = '''def calculate_discount(price: float, discount_percent: float) -> float:
    if discount_percent < 0 or discount_percent > 100:
        raise ValueError("Invalid discount percentage")
    return price * (1.0 - discount_percent / 100.0)
'''
    findings = deterministic_scanner.scan(code, "python")
    assert len(findings) == 0


def test_5_hardcoded_api_key():
    """TEST 5: Hardcoded API key -> Expected: secret/security finding."""
    code = '''def get_payment_client():
    api_key = "mock_scanner_token_key_abcdef987654321"
    return PaymentClient(api_key=api_key)
'''
    findings = deterministic_scanner.scan(code, "python")
    sec_findings = [f for f in findings if f.rule_id == "SEC001"]
    assert len(sec_findings) >= 1
    assert sec_findings[0].severity in ("high", "critical")


def test_6_eval_user_input():
    """TEST 6: eval(user_input) -> Expected: security finding."""
    code = '''def evaluate_expression(user_input):
    result = eval(user_input)
    return result
'''
    findings = deterministic_scanner.scan(code, "python")
    eval_findings = [f for f in findings if f.rule_id == "SEC_EVAL"]
    assert len(eval_findings) >= 1
    assert eval_findings[0].severity == "critical"
    assert "eval" in eval_findings[0].title.lower() or "eval" in eval_findings[0].explanation.lower()


def test_7_safe_parameterized_query_styles():
    """TEST 7: Safe parameterized query -> Expected: no SQL injection across placeholder styles."""
    # Style 1: ? placeholder (SQLite)
    code_qmark = '''def query_sqlite(db, user_id):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM items WHERE id = ?", (user_id,))
    return cursor.fetchall()
'''
    findings_q = deterministic_scanner.scan(code_qmark, "python")
    assert len([f for f in findings_q if f.rule_id == "SQL001"]) == 0

    # Style 2: :name placeholder (SQLAlchemy/Oracle)
    code_named = '''def query_named(session, user_id):
    query = "SELECT * FROM items WHERE id = :user_id"
    return session.execute(query, {"user_id": user_id}).fetchall()
'''
    findings_n = deterministic_scanner.scan(code_named, "python")
    assert len([f for f in findings_n if f.rule_id == "SQL001"]) == 0

    # Style 3: $1 placeholder (PostgreSQL)
    code_pg = '''def query_pg(conn, user_id):
    query = "SELECT * FROM items WHERE id = $1"
    return conn.fetch(query, user_id)
'''
    findings_pg = deterministic_scanner.scan(code_pg, "python")
    assert len([f for f in findings_pg if f.rule_id == "SQL001"]) == 0


def test_8_exact_same_vulnerable_sql_repeated():
    """TEST 8: Run the exact same vulnerable SQL code multiple times -> Expected: same security finding every time."""
    code = '''def get_user(db, username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchone()
'''
    runs = 5
    for i in range(runs):
        findings = deterministic_scanner.scan(code, "python")
        sql_findings = [f for f in findings if f.rule_id == "SQL001"]
        assert len(sql_findings) == 1, f"Run {i+1} failed: expected 1 finding, got {len(sql_findings)}"
        assert sql_findings[0].line_start == 2
        assert sql_findings[0].severity == "high"


def test_9_sql_modulo_formatting():
    """TEST 9: SQL query constructed with % formatting -> Expected: SQL001 detected."""
    code = '''def get_user(db, username):
    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchone()
'''
    findings = deterministic_scanner.scan(code, "python")
    sql_findings = [f for f in findings if f.rule_id == "SQL001"]
    assert len(sql_findings) >= 1
    assert sql_findings[0].severity == "high"


def test_10_sql_format_method():
    """TEST 10: SQL query constructed with .format() -> Expected: SQL001 detected."""
    code = '''def get_user(db, username):
    query = "SELECT * FROM users WHERE username = '{}'".format(username)
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchone()
'''
    findings = deterministic_scanner.scan(code, "python")
    sql_findings = [f for f in findings if f.rule_id == "SQL001"]
    assert len(sql_findings) >= 1
    assert sql_findings[0].severity == "high"


def test_11_normal_non_sql_fstring():
    """TEST 11: Normal non-SQL f-string -> Expected: NO SQL001 (no false positives)."""
    code = '''def greet_user(username: str) -> str:
    message = f"Hello {username}, welcome back!"
    return message
'''
    findings = deterministic_scanner.scan(code, "python")
    sql_findings = [f for f in findings if f.rule_id == "SQL001"]
    assert len(sql_findings) == 0


def test_12_constant_sql_string_concatenation():
    """TEST 12: Constant string concatenation without variables -> Expected: NO SQL001."""
    code = '''def get_all_active_users(db):
    query = "SELECT id, username FROM users " + "WHERE is_active = 1"
    cursor = db.cursor()
    cursor.execute(query)
    return cursor.fetchall()
'''
    findings = deterministic_scanner.scan(code, "python")
    sql_findings = [f for f in findings if f.rule_id == "SQL001"]
    assert len(sql_findings) == 0


def test_13_inline_execute_format():
    """TEST 13: Direct .format() inside cursor.execute() -> Expected: SQL001 detected."""
    code = '''def find_user(db, username):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '{}'".format(username))
    return cursor.fetchone()
'''
    findings = deterministic_scanner.scan(code, "python")
    sql_findings = [f for f in findings if f.rule_id == "SQL001"]
    assert len(sql_findings) >= 1
    assert sql_findings[0].severity == "high"


def test_14_inline_execute_concatenation():
    """TEST 14: Direct concatenation inside cursor.execute() -> Expected: SQL001 detected."""
    code = '''def find_user(db, username):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
    return cursor.fetchone()
'''
    findings = deterministic_scanner.scan(code, "python")
    sql_findings = [f for f in findings if f.rule_id == "SQL001"]
    assert len(sql_findings) >= 1
    assert sql_findings[0].severity == "high"


def test_15_command_injection_os_system():
    """TEST 15: Command injection via os.system -> Expected: CMD001 detected."""
    code = '''import os
def ping_host(host):
    os.system("ping -c 1 " + host)
'''
    findings = deterministic_scanner.scan(code, "python")
    cmd_findings = [f for f in findings if f.rule_id == "CMD001"]
    assert len(cmd_findings) >= 1
    assert cmd_findings[0].severity == "critical"


def test_16_safe_subprocess_no_shell():
    """TEST 16: Safe command execution with argument list -> Expected: NO CMD001."""
    code = '''import subprocess
def ping_host(host):
    subprocess.run(["ping", "-c", "1", host], check=True)
'''
    findings = deterministic_scanner.scan(code, "python")
    cmd_findings = [f for f in findings if f.rule_id == "CMD001"]
    assert len(cmd_findings) == 0


def test_17_path_traversal_open():
    """TEST 17: Dynamic path construction in open() -> Expected: PATH001 detected."""
    code = '''def read_user_file(user_file):
    with open(f"/var/data/{user_file}", "r") as f:
        return f.read()
'''
    findings = deterministic_scanner.scan(code, "python")
    path_findings = [f for f in findings if f.rule_id == "PATH001"]
    assert len(path_findings) >= 1
    assert path_findings[0].severity == "high"


def test_18_safe_static_open():
    """TEST 18: Safe static file open -> Expected: NO PATH001."""
    code = '''def read_config():
    with open("/etc/app/config.json", "r") as f:
        return f.read()
'''
    findings = deterministic_scanner.scan(code, "python")
    path_findings = [f for f in findings if f.rule_id == "PATH001"]
    assert len(path_findings) == 0


def test_19_unsafe_deserialization_pickle():
    """TEST 19: pickle.loads on dynamic input -> Expected: DES001 detected."""
    code = '''import pickle
def load_session(payload):
    return pickle.loads(payload)
'''
    findings = deterministic_scanner.scan(code, "python")
    des_findings = [f for f in findings if f.rule_id == "DES001"]
    assert len(des_findings) >= 1
    assert des_findings[0].severity == "critical"


def test_20_hardcoded_aws_key_masked():
    """TEST 20: Hardcoded AWS access key ID -> Expected: SEC001 and masked evidence."""
    code = '''def get_aws_credentials():
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    return aws_key
'''
    findings = deterministic_scanner.scan(code, "python")
    sec_findings = [f for f in findings if f.rule_id == "SEC001"]
    assert len(sec_findings) >= 1
    assert "AKIAIOSFODNN7EXAMPLE" not in (sec_findings[0].evidence or "")
    assert "****" in (sec_findings[0].evidence or "")


