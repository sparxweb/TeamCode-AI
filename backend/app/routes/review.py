import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form
from app.models import CodeReviewRequest, CodeReviewResponse
from app.services.review_agent import review_agent
from app.services.file_service import validate_and_read_uploaded_file

logger = logging.getLogger("teamcode.routes.review")
router = APIRouter(prefix="/api/review", tags=["Code Review"])


@router.post("", response_model=CodeReviewResponse)
def review_code_endpoint(request: CodeReviewRequest):
    """
    Submits code for review.
    1. Recalls relevant memories from Hindsight.
    2. Builds LLM prompt with memories and code.
    3. Runs review through Groq.
    4. Returns structured results with explicit memory references.
    """
    try:
        response = review_agent.review_code(request)
        return response
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception:
        logger.exception("Unexpected error during code review")
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred during review. Please try again later."
        )


@router.post("/upload", response_model=CodeReviewResponse)
async def review_file_upload_endpoint(
    file: UploadFile = File(...),
    context_hint: Optional[str] = Form(None),
):
    """
    Accepts an uploaded source file, validates it, and runs the memory-powered code review.
    """
    content, detected_lang, filename = await validate_and_read_uploaded_file(file)

    request = CodeReviewRequest(
        code=content,
        language=detected_lang,
        filename=filename,
        context_hint=context_hint,
    )

    try:
        response = review_agent.review_code(request)
        return response
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception:
        logger.exception("Unexpected error during file review")
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred during file review. Please try again later."
        )
