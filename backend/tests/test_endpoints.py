import pytest
import io

from fastapi.testclient import TestClient
from app.main import app
from app.models import MemoryItem
from app.services.hindsight_service import hindsight_service
from app.services.llm_service import llm_service
from app.services.history_service import history_service

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "groq_configured" in data
    assert "hindsight_configured" in data
    assert "hindsight_bank_id" in data


def test_file_upload_validation_rejected_extension():
    # Unsupported extension (.exe)
    file_bytes = b"fake binary content"
    files = {"file": ("malicious.exe", io.BytesIO(file_bytes), "application/octet-stream")}
    res = client.post("/api/review/upload", files=files)
    assert res.status_code == 400
    assert "Unsupported file format" in res.json()["detail"]


def test_file_upload_validation_binary():
    # Attempt to upload binary in allowed extension
    file_bytes = b"\x00\x01\x02\xff\xfe\x00"
    files = {"file": ("corrupt.py", io.BytesIO(file_bytes), "application/octet-stream")}
    # Should reject binary safely with 400
    res = client.post("/api/review/upload", files=files)
    assert res.status_code == 400
    assert "Binary files are not supported" in res.json()["detail"]


def test_file_upload_validation_empty():
    # Empty file upload must be rejected cleanly
    file_bytes = b""
    files = {"file": ("empty.py", io.BytesIO(file_bytes), "text/plain")}
    res = client.post("/api/review/upload", files=files)
    assert res.status_code == 400
    assert "empty" in res.json()["detail"].lower()


def test_file_upload_path_traversal_sanitized():
    # Path traversal in filename must be stripped safely
    import pytest
    file_bytes = b"def add(a, b):\n    return a + b\n"
    files = {"file": ("../../etc/passwd.py", io.BytesIO(file_bytes), "text/plain")}
    res = client.post("/api/review/upload", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["filename"] == "passwd.py"


def test_history_lifecycle():
    history_service.clear_history()
    assert len(history_service.get_history()) == 0

    dummy_review = {
        "id": "test-review-123",
        "timestamp": "2026-09-28T12:00:00Z",
        "language": "python",
        "summary": "Test summary",
        "overall_severity": "high",
        "issues": [{"title": "SQL Injection", "severity": "high", "category": "security", "explanation": "raw sql", "recommendation": "use params"}],
        "memories_used": [{"id": "m1", "text": "All queries must be parameterized", "tags": ["sql"]}],
        "memory_status": "recalled",
    }
    history_service.save_review(dummy_review)

    hist = history_service.get_history()
    assert len(hist) == 1
    assert hist[0]["id"] == "test-review-123"
    assert hist[0]["memories_count"] == 1

    fetched = history_service.get_review_by_id("test-review-123")
    assert fetched is not None
    assert fetched["id"] == "test-review-123"

    history_service.clear_history()
    assert len(history_service.get_history()) == 0


def test_derive_recall_query():
    from app.services.review_agent import derive_focused_recall_query
    
    code = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
    query = derive_focused_recall_query(code, "python")
    assert "database queries SQL parameterized" in query
    assert "python" in query


def test_hindsight_unavailable_visible_reporting(monkeypatch):
    # When Hindsight is not configured or fails, it MUST return "unavailable" status visibly
    # and MUST NOT invent fake memories.
    monkeypatch.setattr(hindsight_service, "is_available", lambda force=False: (False, "Simulated network timeout"))
    status, memories, msg = hindsight_service.recall("test query")
    assert status == "unavailable"
    assert len(memories) == 0
    assert "unavailable" in msg.lower()
