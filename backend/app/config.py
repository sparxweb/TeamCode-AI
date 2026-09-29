import os
from pathlib import Path
from pydantic import BaseModel
from dotenv import load_dotenv

# Search for .env in current folder, parent, or project root
current_dir = Path(__file__).resolve().parent
candidates = [
    current_dir.parent.parent / ".env",
    current_dir.parent / ".env",
    current_dir / ".env",
    Path.cwd() / ".env",
]
for candidate in candidates:
    if candidate.exists():
        load_dotenv(dotenv_path=candidate, override=True)
        break


class Settings(BaseModel):
    # LLM Settings (Groq)
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    GROQ_FALLBACK_MODELS: list[str] = [
        "openai/gpt-oss-120b",
        "openai/gpt-oss-20b",
        "qwen/qwen3.8-27b",
    ]

    # Hindsight Settings
    HINDSIGHT_API_KEY: str = os.getenv("HINDSIGHT_API_KEY", "")
    HINDSIGHT_BASE_URL: str = os.getenv("HINDSIGHT_BASE_URL", "https://api.hindsight.vectorize.io")
    HINDSIGHT_BANK_ID: str = os.getenv("HINDSIGHT_BANK_ID", "teamcode-ai")

    # Security & Limits
    MAX_UPLOAD_SIZE_BYTES: int = 512 * 1024  # 512 KB
    ALLOWED_EXTENSIONS: set[str] = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs",
        ".cpp", ".c", ".h", ".hpp", ".cs", ".php", ".rb", ".sql",
        ".html", ".css", ".json", ".yaml", ".yml", ".sh",
        ".kt", ".kts", ".swift"
    }

    @property
    def is_groq_configured(self) -> bool:
        return bool(self.GROQ_API_KEY and self.GROQ_API_KEY.strip())

    @property
    def is_hindsight_configured(self) -> bool:
        return bool(self.HINDSIGHT_API_KEY and self.HINDSIGHT_API_KEY.strip())


settings = Settings()
