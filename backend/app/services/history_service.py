import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger("teamcode.history")

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
HISTORY_FILE = DATA_DIR / "history.json"


class HistoryService:
    def __init__(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if not HISTORY_FILE.exists():
            try:
                HISTORY_FILE.write_text("[]", encoding="utf-8")
            except Exception as e:
                logger.error("Could not initialize history file: %s", str(e))

    def _read_all(self) -> List[Dict[str, Any]]:
        if not HISTORY_FILE.exists():
            return []
        try:
            content = HISTORY_FILE.read_text(encoding="utf-8")
            return json.loads(content) if content.strip() else []
        except Exception as e:
            logger.error("Error reading history: %s", str(e))
            return []

    def _write_all(self, items: List[Dict[str, Any]]):
        try:
            HISTORY_FILE.write_text(json.dumps(items, indent=2), encoding="utf-8")
        except Exception as e:
            logger.error("Error writing history: %s", str(e))

    def save_review(self, review_data: Dict[str, Any]):
        """Saves a record of a review including code hash, findings, auto_fix, and validation status."""
        items = self._read_all()
        # Sanitize data to ensure no API keys or secrets are stored
        sanitized_review = {k: v for k, v in review_data.items() if "key" not in k.lower() and "secret" not in k.lower()}
        
        auto_fix = review_data.get("auto_fix") or {}
        summary_record = {
            "id": review_data.get("id"),
            "code_hash": review_data.get("code_hash"),
            "timestamp": review_data.get("timestamp"),
            "language": review_data.get("language"),
            "status": review_data.get("status", "FINDINGS"),
            "summary": review_data.get("summary"),
            "overall_severity": review_data.get("overall_severity"),
            "findings_count": len(review_data.get("findings", [])),
            "issues_count": len(review_data.get("issues", [])),
            "memories_count": len(review_data.get("memories_used", [])),
            "memory_status": review_data.get("memory_status"),
            "has_fixed_code": bool(auto_fix.get("fixed_code")),
            "is_fix_validated": auto_fix.get("is_validated", False),
            "full_review": sanitized_review,
        }
        items.insert(0, summary_record)
        items = items[:50]
        self._write_all(items)
        return True

    def get_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        items = self._read_all()
        # Return summary without full_review for list view
        result = []
        for item in items[:limit]:
            result.append({
                "id": item.get("id"),
                "timestamp": item.get("timestamp"),
                "language": item.get("language"),
                "summary": item.get("summary"),
                "overall_severity": item.get("overall_severity"),
                "issues_count": item.get("issues_count", 0),
                "memories_count": item.get("memories_count", 0),
                "memory_status": item.get("memory_status"),
            })
        return result

    def get_review_by_id(self, review_id: str) -> Optional[Dict[str, Any]]:
        items = self._read_all()
        for item in items:
            if item.get("id") == review_id:
                return item.get("full_review")
        return None

    get_review = get_review_by_id

    def clear_history(self):
        self._write_all([])


history_service = HistoryService()
