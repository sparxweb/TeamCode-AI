from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException
from app.services.history_service import history_service

router = APIRouter(prefix="/api/history", tags=["Review History"])


@router.get("", response_model=List[Dict[str, Any]])
def get_recent_history(limit: int = 20):
    """
    Returns lightweight review history metadata.
    """
    return history_service.get_history(limit=limit)


@router.get("/{review_id}")
def get_single_review(review_id: str):
    """
    Returns full review data for a specific historical review.
    """
    review = history_service.get_review_by_id(review_id)
    if not review:
        raise HTTPException(status_code=404, detail="Review not found in history.")
    return review


@router.delete("")
def clear_all_history():
    """
    Clears local prototype review history.
    """
    history_service.clear_history()
    return {"message": "Local review history cleared."}
