from fastapi import APIRouter, HTTPException
from app.config import settings
from app.models import (
    RetainMemoryRequest,
    RetainMemoryResponse,
    RecallQueryRequest,
    RecallQueryResponse,
)
from app.services.hindsight_service import hindsight_service

router = APIRouter(prefix="/api/memory", tags=["Hindsight Memory"])


@router.post("/retain", response_model=RetainMemoryResponse)
def retain_team_memory(request: RetainMemoryRequest):
    """
    Persists a team rule, architecture preference, or review feedback into Hindsight.
    """
    success, result_dict, error_msg = hindsight_service.retain(
        content=request.content,
        context=request.context,
        tags=request.tags,
        memory_type=request.memory_type,
    )

    if not success:
        raise HTTPException(
            status_code=502 if "unavailable" in (error_msg or "").lower() else 400,
            detail=error_msg or "Failed to retain memory in Hindsight.",
        )

    return RetainMemoryResponse(
        success=True,
        message="Team knowledge saved to Hindsight.",
        bank_id=result_dict.get("bank_id", settings.HINDSIGHT_BANK_ID),
        operation_id=result_dict.get("operation_id"),
        retained_memory={
            "content": request.content,
            "type": request.memory_type,
            "context": request.context,
            "tags": request.tags,
        },
    )


@router.post("/recall", response_model=RecallQueryResponse)
def test_recall_memory(request: RecallQueryRequest):
    """
    Tests Hindsight RECALL with a custom query to verify memory retrieval.
    """
    status, memories, message = hindsight_service.recall(
        query=request.query,
        max_tokens=request.max_tokens or 2048,
    )

    return RecallQueryResponse(
        query=request.query,
        status=status,
        count=len(memories),
        memories=memories,
        message=message,
    )
