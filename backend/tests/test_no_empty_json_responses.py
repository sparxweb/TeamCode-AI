"""
Tests that reproduce and prevent "Unexpected end of JSON input":

Verifies that every API endpoint returns valid JSON for:
1. Normal review (SQL injection)
2. Safe code (no false positive)
3. Empty code → 400 (not empty body)
4. LLM unavailable → deterministic fallback still returns valid JSON
5. Upload endpoint with invalid extension → 400 JSON
6. 500 errors → still return JSON {detail: "..."}
7. Health endpoint always returns JSON
"""
import json
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from app.main import app

client = TestClient(app, raise_server_exceptions=False)

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


def assert_valid_json_response(response, expected_status=200):
    """Assert that the response is a valid non-empty JSON response."""
    assert response.status_code == expected_status, (
        f"Expected HTTP {expected_status}, got {response.status_code}. Body: {response.text[:300]}"
    )
    # Must NOT be empty
    assert response.text.strip(), f"Response body is empty (HTTP {response.status_code})"
    # Must NOT be HTML
    assert not response.text.strip().startswith('<'), (
        f"Response is HTML, not JSON: {response.text[:200]}"
    )
    # Must be valid JSON
    try:
        data = response.json()
    except json.JSONDecodeError as e:
        pytest.fail(f"Response is not valid JSON: {e}. Body: {response.text[:300]}")
    return data


class TestNoEmptyJsonResponses:
    """
    Ensures the backend NEVER returns an empty or non-JSON body.
    This is the root cause of 'Unexpected end of JSON input' on the frontend.
    """

    def test_health_endpoint_returns_valid_json(self):
        res = client.get("/api/health")
        data = assert_valid_json_response(res, 200)
        assert "status" in data
        assert "groq_configured" in data

    def test_review_sql_injection_returns_valid_json(self):
        """Vulnerable code must return valid JSON with findings."""
        res = client.post("/api/review", json={"code": VULN_CODE, "language": "python"})
        data = assert_valid_json_response(res, 200)
        assert "findings" in data
        assert "status" in data
        assert isinstance(data["findings"], list)
        sql_findings = [f for f in data["findings"] if "SQL" in f.get("rule_id", "")]
        assert len(sql_findings) >= 1, "Expected SQL injection finding"

    def test_review_safe_code_no_false_positive(self):
        """Safe parameterized code must NOT report SQL injection."""
        res = client.post("/api/review", json={"code": SAFE_CODE, "language": "python"})
        data = assert_valid_json_response(res, 200)
        sql_findings = [
            f for f in data["findings"]
            if "SQL" in f.get("rule_id", "") or "sql injection" in f.get("title", "").lower()
        ]
        assert len(sql_findings) == 0, f"False positive SQL finding on safe code: {sql_findings}"

    def test_review_empty_code_returns_json_400_or_422(self):
        """Empty code must return 400 or 422 JSON, never empty body."""
        res = client.post("/api/review", json={"code": "", "language": "python"})
        # Must be either 400 or 422 (validation), never 200 with garbage or empty 500
        assert res.status_code in (400, 422), f"Expected 400/422, got {res.status_code}"
        assert_valid_json_response(res, res.status_code)

    def test_review_missing_code_field_returns_json_422(self):
        """Missing required field must return 422 JSON (FastAPI validation)."""
        res = client.post("/api/review", json={"language": "python"})
        data = assert_valid_json_response(res, 422)
        assert "detail" in data

    def test_review_with_llm_unavailable_still_returns_valid_json(self):
        """
        When Groq/LLM raises an exception, the review agent must still return
        valid JSON using the deterministic fallback. This is the key guard
        against the 'Unexpected end of JSON input' error.
        """
        def mock_execute_review(*args, **kwargs):
            raise ValueError("Simulated Groq API timeout")

        from app.services.llm_service import llm_service as svc
        with patch.object(svc, "execute_review", mock_execute_review):
            res = client.post("/api/review", json={"code": VULN_CODE, "language": "python"})
        data = assert_valid_json_response(res, 200)
        # Should still have findings from deterministic scanner
        assert "findings" in data
        assert "review_mode" in data
        # Must show fallback was used
        assert data.get("fallback_used") is True or data.get("review_mode") == "deterministic"

    def test_review_with_llm_unavailable_safe_code_still_returns_valid_json(self):
        """Even on safe code with LLM down, we get valid JSON PASS."""
        def mock_execute_review(*args, **kwargs):
            raise ConnectionError("Simulated Groq connection refused")

        from app.services.llm_service import llm_service as svc
        with patch.object(svc, "execute_review", mock_execute_review):
            res = client.post("/api/review", json={"code": SAFE_CODE, "language": "python"})
        data = assert_valid_json_response(res, 200)
        assert "findings" in data

    def test_upload_invalid_extension_returns_json_400(self):
        """File upload with bad extension must return JSON 400, not empty/HTML."""
        import io
        fake_file = io.BytesIO(b"some content")
        res = client.post(
            "/api/review/upload",
            files={"file": ("malware.exe", fake_file, "application/octet-stream")},
        )
        # Should be 400 with JSON error
        assert res.status_code in (400, 422)
        assert_valid_json_response(res, res.status_code)

    def test_history_endpoint_returns_valid_json(self):
        """History endpoint must always return valid JSON."""
        res = client.get("/api/history")
        data = assert_valid_json_response(res, 200)
        assert isinstance(data, list)

    def test_unknown_endpoint_returns_json_404(self):
        """Unknown route returns JSON 404, not HTML."""
        res = client.get("/api/nonexistent")
        assert res.status_code == 404
        # FastAPI returns JSON 404 by default
        assert_valid_json_response(res, 404)

    def test_review_response_json_is_fully_serializable(self):
        """
        The complete review response must be serializable to JSON without errors.
        This prevents NaN/Infinity/None values from breaking frontend JSON.parse().
        """
        res = client.post("/api/review", json={"code": VULN_CODE, "language": "python"})
        data = assert_valid_json_response(res, 200)
        # Re-serialize to catch any non-JSON-safe values
        try:
            round_trip = json.dumps(data)
            assert len(round_trip) > 100
        except (TypeError, ValueError) as e:
            pytest.fail(f"Response contains non-JSON-serializable value: {e}")

    def test_deterministic_scanner_works_independently(self):
        """
        Deterministic scanner must detect SQL injection regardless of LLM.
        """
        def mock_is_available(*args, **kwargs):
            return False, "LLM not configured"

        from app.services.llm_service import llm_service as svc
        with patch.object(svc, "is_available", mock_is_available):
            res = client.post("/api/review", json={"code": VULN_CODE, "language": "python"})
        data = assert_valid_json_response(res, 200)
        assert len(data["findings"]) >= 1, "Deterministic scanner must find SQL injection independently"
        assert data.get("fallback_used") is True
