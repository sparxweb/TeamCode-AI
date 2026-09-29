from pathlib import Path
from typing import Tuple
from fastapi import UploadFile, HTTPException
from app.config import settings

LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".cpp": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".swift": "swift",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".sh": "bash",
}


def detect_language_from_filename(filename: str) -> str:
    ext = Path(filename).suffix.lower()
    return LANGUAGE_EXTENSIONS.get(ext, "text")


def detect_language_from_content(code: str) -> str:
    snippet = code[:1500]
    snippet_lines = snippet.splitlines()

    # PHP
    if "<?php" in snippet or "$_GET" in snippet or "$_POST" in snippet or "<?=" in snippet:
        return "php"

    # Python
    if any(line.strip().startswith(("def ", "class ", "import ", "from ", "async def ")) and ":" in line for line in snippet_lines) or "print(" in snippet:
        return "python"

    # Go
    if "package " in snippet and ("func " in snippet or "import (" in snippet):
        return "go"

    # Rust
    if ("fn " in snippet or "pub fn " in snippet) and ("let mut " in snippet or "impl " in snippet or "println!" in snippet):
        return "rust"

    # Kotlin
    if "fun " in snippet and ("val " in snippet or "var " in snippet or "package " in snippet):
        return "kotlin"

    # Swift
    if ("func " in snippet or "var " in snippet) and ("import Foundation" in snippet or "import UIKit" in snippet or "guard let" in snippet):
        return "swift"

    # Ruby
    if ("def " in snippet and "end" in snippet) or "require '" in snippet or "require_relative" in snippet:
        return "ruby"

    # C#
    if "using System" in snippet or "namespace " in snippet or "Console.WriteLine" in snippet:
        return "csharp"

    # Java
    if "public class " in snippet or "System.out.println" in snippet or "public static void main" in snippet:
        return "java"

    # C++
    if "#include <iostream>" in snippet or "std::cout" in snippet or "std::vector" in snippet:
        return "cpp"

    # C
    if "#include <stdio.h>" in snippet or "#include <stdlib.h>" in snippet or "printf(" in snippet:
        return "c"

    # TypeScript / JavaScript
    if any(kw in snippet for kw in ["import React", "export default", "export const", "interface ", ": string", ": number", ": boolean"]):
        return "typescript"
    if any(kw in snippet for kw in ["const ", "let ", "var ", "function ", "console.log("]):
        return "javascript"

    # SQL
    if any(kw in snippet.upper() for kw in ["SELECT ", "INSERT INTO", "CREATE TABLE", "UPDATE ", "DELETE FROM"]):
        return "sql"

    return "text"


async def validate_and_read_uploaded_file(file: UploadFile) -> Tuple[str, str, str]:
    """
    Validates uploaded file size and extension, securely reading content as untrusted text.
    Never executes or runs shell commands on code.
    Returns: (content_str, language, safe_filename)
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file missing filename.")

    # Sanitize filename against path traversal (e.g., ../../malicious.py -> malicious.py)
    safe_filename = Path(file.filename).name
    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename.")

    ext = Path(safe_filename).suffix.lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Allowed extensions: {', '.join(sorted(settings.ALLOWED_EXTENSIONS))}"
        )

    # Read bytes with size limit
    content_bytes = await file.read()
    if not content_bytes or not content_bytes.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    if len(content_bytes) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES // 1024} KB."
        )

    if b"\x00" in content_bytes:
        raise HTTPException(
            status_code=400,
            detail="File content could not be decoded as text. Binary files are not supported."
        )

    # Decode as UTF-8 / text
    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = content_bytes.decode("latin-1")
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="File content could not be decoded as text. Binary files are not supported."
            )

    if not content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file contains no readable source code.")

    detected_lang = detect_language_from_filename(safe_filename)
    return content, detected_lang, safe_filename
