import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.routes import health, review, memory, history

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("teamcode")

app = FastAPI(
    title="TeamCode AI API",
    description="AI Code Review Agent with Hindsight Long-Term Team Memory",
    version="1.0.0",
)

# CORS configuration for Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global safe error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error processing %s: %s", request.url.path, str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Please try again later."},
    )

# Include routers
app.include_router(health.router)
app.include_router(review.router)
app.include_router(memory.router)
app.include_router(history.router)


@app.get("/")
def root():
    return {
        "service": "TeamCode AI Backend",
        "version": "1.0.0",
        "status": "online",
        "groq_configured": settings.is_groq_configured,
        "hindsight_configured": settings.is_hindsight_configured,
        "endpoints": {
            "health": "/api/health",
            "review": "/api/review",
            "retain_memory": "/api/memory/retain",
            "recall_memory": "/api/memory/recall",
            "history": "/api/history",
        },
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
