from fastapi import APIRouter
from app.config import settings
from app.models import ServiceHealthResponse
from app.services.hindsight_service import hindsight_service
from app.services.llm_service import llm_service

router = APIRouter(prefix="/api/health", tags=["Health"])


@router.get("", response_model=ServiceHealthResponse)
def get_health():
    groq_ok, groq_msg = llm_service.is_available_live()
    hindsight_ok, hindsight_msg = hindsight_service.is_available()

    status = "healthy" if (groq_ok and hindsight_ok) else "degraded"
    note_parts = []
    if not groq_ok:
        note_parts.append(f"Groq: {groq_msg}")
    else:
        note_parts.append(f"Groq model: {settings.GROQ_MODEL}")

    if not hindsight_ok:
        note_parts.append(f"Hindsight: {hindsight_msg}")
    else:
        note_parts.append(f"Hindsight connected to bank '{settings.HINDSIGHT_BANK_ID}'")

    return ServiceHealthResponse(
        status=status,
        groq_configured=groq_ok,
        groq_model=settings.GROQ_MODEL,
        hindsight_configured=hindsight_ok,
        hindsight_bank_id=settings.HINDSIGHT_BANK_ID,
        hindsight_base_url=settings.HINDSIGHT_BASE_URL,
        note=" | ".join(note_parts),
    )
