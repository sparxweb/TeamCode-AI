"""Quick end-to-end test of the review pipeline."""
import json
import sys
from app.models import CodeReviewRequest
from app.services.review_agent import review_agent

VULN_CODE = (
    "import sqlite3\n"
    "def get_user(username):\n"
    "    conn = sqlite3.connect('users.db')\n"
    "    cursor = conn.cursor()\n"
    "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
    "    cursor.execute(query)\n"
    "    user = cursor.fetchone()\n"
    "    conn.close()\n"
    "    return user\n"
)

SAFE_CODE = (
    "import sqlite3\n"
    "def get_user(username):\n"
    "    conn = sqlite3.connect('users.db')\n"
    "    cursor = conn.cursor()\n"
    "    query = 'SELECT * FROM users WHERE username = ?'\n"
    "    cursor.execute(query, (username,))\n"
    "    user = cursor.fetchone()\n"
    "    conn.close()\n"
    "    return user\n"
)

def run_test(name, code, expect_finding):
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print(f"{'='*60}")
    req = CodeReviewRequest(code=code, language="python")
    try:
        result = review_agent.review_code(req)
        print(f"  status: {result.status}")
        print(f"  review_mode: {result.review_mode}")
        print(f"  fallback_used: {result.fallback_used}")
        print(f"  findings: {len(result.findings)}")
        print(f"  overall_severity: {result.overall_severity}")
        print(f"  summary: {result.summary[:100]}")
        sql_findings = [f for f in result.findings if "SQL" in f.rule_id or "sql" in f.title.lower()]
        print(f"  SQL findings: {len(sql_findings)}")
        if result.auto_fix:
            print(f"  auto_fix.validation_status: {result.auto_fix.validation_status}")
            print(f"  auto_fix.fixed_code present: {bool(result.auto_fix.fixed_code)}")
        
        # Serialize to JSON to verify it works
        j = result.model_dump()
        s = json.dumps(j)
        print(f"  JSON serialization: OK ({len(s)} bytes)")
        
        if expect_finding and len(result.findings) == 0:
            print("  WARN: Expected findings but got none!")
        elif not expect_finding and len(sql_findings) > 0:
            print("  WARN: False positive - found SQL issue in safe code!")
        else:
            print("  RESULT: PASS")
    except Exception as e:
        print(f"  ERROR: {type(e).__name__}: {str(e)[:300]}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    run_test("Vulnerable SQL injection code", VULN_CODE, expect_finding=True)
    run_test("Safe parameterized SQL code", SAFE_CODE, expect_finding=False)
    print("\nDone.")
