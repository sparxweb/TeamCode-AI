import json
import logging
from typing import Dict, Any, List, Optional
import groq
from app.config import settings
from app.models import MemoryItem, FindingItem

logger = logging.getLogger("teamcode.llm")


REVIEW_SYSTEM_PROMPT = """You are TeamCode AI, an advanced, general-purpose code review, error detection, and remediation engine for engineering teams.
You review developer code across diverse languages (Python, JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, PHP, Kotlin, Swift, Ruby, SQL, etc.).

CRITICAL GENERAL-PURPOSE REVIEW MANDATE:
1. NEVER assume the error type. Do NOT assume SQL injection, XSS, or hardcoded passwords. The code may have syntax errors, compilation/type issues, logic bugs, performance problems, resource leaks, architecture violations, security vulnerabilities, or be completely clean.
2. Evaluate what is ACTUALLY present in the submitted code.
3. Every finding MUST cite exact evidence lines directly from the submitted code. Never fabricate evidence or cite external rules as code evidence.
4. Separate SEVERITY (critical | high | medium | low | info) from CONFIDENCE (0.0 to 1.0 float).
   - Critical: Severe exploitable vulnerabilities (RCE, unauthenticated access) or fatal runtime crashes.
   - High: Exploitable security defects, unhandled null dereferences in core paths, severe data corruption.
   - Medium: Logic bugs, unhandled exceptions, race conditions, significant performance bottlenecks.
   - Low: Minor quality defects, unused variables, minor inefficiencies.
   - Info: Style suggestions, documentation notes, architectural observations.

CRITICAL INSTRUCTIONS REGARDING TEAM MEMORY:
You are provided with relevant team memories from the team's Hindsight memory bank, categorized into:
- Team Rules & Standards
- Architecture Preferences
- Previous Review Feedback
- General Guidelines

1. You MUST evaluate whether the code complies with or violates any retrieved team memory.
2. If the code violates a team memory, explicitly flag it, list the exact rule in team_memory_used, and cite it in explanation and recommended_fix.
3. TEAM MEMORY IS NOT CODE EVIDENCE. Clearly distinguish between current code evidence and team standards.
4. If NO team memories are provided, review according to standard secure engineering best practices.

OUTPUT SCHEMA (You MUST respond strictly with a valid JSON object matching this schema):
{
  "status": "PASS | FINDINGS",
  "summary": "Executive summary of review findings and standards compliance",
  "overall_severity": "info | low | medium | high | critical",
  "confidence": 0.95,
  "findings": [
    {
      "rule_id": "Short rule ID e.g. SYN001, LOG001, SEC001, SQL001, PERF001, QAL001, ARCH001",
      "title": "Short descriptive title of the finding",
      "category": "security | quality | architecture | performance | syntax | logic",
      "severity": "info | low | medium | high | critical",
      "confidence": 0.95,
      "line_start": 1,
      "line_end": 1,
      "evidence": "Exact snippet of code from submitted input at these lines",
      "explanation": "Clear, detailed explanation of WHAT is wrong, WHERE, and WHY",
      "impact": "Concrete impact on security, correctness, or performance",
      "team_memory_used": ["Exact cited team memory / standard if applicable"],
      "recommended_fix": "Precise recommended fix or safe code pattern",
      "requires_fix": true
    }
  ],
  "suggestions": [
    "General actionable suggestion 1",
    "General actionable suggestion 2"
  ],
  "explanation": "Synthesis of review decisions and how standards guided the outcome"
}

If the code is clean and has no issues, set "status": "PASS", "overall_severity": "info", "confidence": 0.95, "findings": [].
"""

AUTO_FIX_SYSTEM_PROMPT = """You are TeamCode AI's Universal Auto-Fix Agent.
Your task is to take developer code and a list of verified review findings, and generate a clean, secure, production-ready corrected version of the code that resolves every issue while preserving the intended business logic and programming style.

FIX PRINCIPLES:
1. Preserve original intent and business logic. Change only the minimum necessary code.
2. Resolve the detected issues according to their category:
   - Syntax/Compilation: Fix syntax errors, unmatched delimiters, type mismatches, or malformed statements.
   - Logic: Correct loop bounds, fix conditional comparisons, add missing null/None handling, ensure proper return values.
   - Performance: Release unclosed resources, replace obvious O(n^2) redundant computations, eliminate repeated database queries.
   - Security: Parameterize SQL queries, sanitize HTML/DOM outputs, use safe subprocess arguments (shell=False), extract hardcoded secrets to environment variables, use strong cryptography (e.g. SHA-256/bcrypt).
   - Code Quality: Clean up empty exception handlers (log or handle), remove redundant code.
3. PRESERVE ORIGINAL CONTEXT, LIBRARIES, AND IMPORTS:
   - NEVER invent new libraries, modules, or fake APIs that are not already imported or defined.
   - PRESERVE all existing imports, framework usage, and function signatures.
   - DO NOT alter function names, parameter lists, or return structures.
   - If using standard library functions (e.g., `os.getenv()`, `subprocess.run()`, `ast.literal_eval()`), you MUST include the corresponding standard library import if not already present.
4. Provide the COMPLETE, RUNNABLE corrected source code — do not omit code with comments like '... rest of code unchanged ...'.
5. Maintain existing formatting and naming conventions.

You MUST respond strictly with a valid JSON object matching this schema:
{
  "fixed_code": "The complete corrected source code string",
  "changes_made": [
    "Specific change 1 applied",
    "Specific change 2 applied"
  ],
  "remaining_risks": [
    "Any residual trade-offs or notes (or empty if none)"
  ]
}
"""


def format_memories_as_team_context(memories: List[MemoryItem]) -> str:
    """Categorizes and formats recalled Hindsight memories into distinct contextual groups."""
    if not memories:
        return "=== TEAM CONTEXT (FROM HINDSIGHT) ===\nNo relevant team memory retrieved for this review. Evaluating against industry best practices.\n"

    rules: List[MemoryItem] = []
    arch: List[MemoryItem] = []
    feedback: List[MemoryItem] = []
    general: List[MemoryItem] = []

    for m in memories:
        text_lower = m.text.lower()
        m_type = (m.type or "").lower()
        if "must" in text_lower or "never" in text_lower or "rule" in m_type or "standard" in m_type:
            rules.append(m)
        elif "arch" in m_type or "pattern" in text_lower or "layer" in text_lower:
            arch.append(m)
        elif "review" in m_type or "previous" in text_lower or "feedback" in text_lower:
            feedback.append(m)
        else:
            general.append(m)

    sections = ["=== TEAM CONTEXT (FROM HINDSIGHT MEMORY BANK: teamcode-ai) ==="]

    if rules:
        sections.append("\n-- TEAM RULES & CODING STANDARDS --")
        for i, m in enumerate(rules, 1):
            sections.append(f"[{i}] {m.text}")
            if m.context:
                sections.append(f"    Intent: {m.context}")

    if arch:
        sections.append("\n-- ARCHITECTURE PREFERENCES --")
        for i, m in enumerate(arch, 1):
            sections.append(f"[{i}] {m.text}")

    if feedback:
        sections.append("\n-- PREVIOUS REVIEW DECISIONS & FEEDBACK --")
        for i, m in enumerate(feedback, 1):
            sections.append(f"[{i}] {m.text}")

    if general:
        sections.append("\n-- GENERAL ENGINEERING GUIDELINES --")
        for i, m in enumerate(general, 1):
            sections.append(f"[{i}] {m.text}")

    return "\n".join(sections) + "\n"


class LLMService:
    def __init__(self):
        self._client: Optional[groq.Groq] = None
        self._setup_client()

    def _setup_client(self):
        if settings.is_groq_configured:
            try:
                self._client = groq.Groq(api_key=settings.GROQ_API_KEY)
            except Exception as e:
                logger.error("Failed to initialize Groq client: %s", str(e))
                self._client = None
        else:
            self._client = None

    def is_available(self) -> tuple[bool, str]:
        if not settings.is_groq_configured:
            return False, "GROQ_API_KEY is not configured in .env."
        if not self._client:
            return False, "Groq client is not initialized."
        try:
            self._client.models.list()
            return True, f"Groq LLM service is ready ({settings.GROQ_MODEL})."
        except Exception as e:
            logger.warning("Groq live connectivity check failed: %s", str(e))
            return False, f"Groq authentication or connectivity failed: {str(e)}"

    def execute_review(
        self,
        code: str,
        language: str,
        memories: List[MemoryItem],
        context_hint: Optional[str] = None,
        deterministic_findings: Optional[List[FindingItem]] = None,
    ) -> Dict[str, Any]:
        """
        Sends code and categorized team context to Groq and parses structured review findings.
        """
        available, reason = self.is_available()
        if not available:
            raise ValueError(f"Groq service unavailable: {reason}")

        # Build prompt sections
        memory_section = format_memories_as_team_context(memories)

        det_section = ""
        if deterministic_findings:
            det_section = "\n=== PRE-SCANNER FINDINGS (High Confidence) ===\n"
            for df in deterministic_findings:
                det_section += f"- [{df.rule_id}] Line {df.line_start}: {df.title} (Evidence: {df.evidence})\n"

        user_content = f"""Programming Language: {language}
{f'Developer Context: {context_hint}' if context_hint else ''}

{memory_section}
{det_section}
=== CODE TO REVIEW ===
```{language}
{code}
```

Perform a rigorous, structured code review. Adhere strictly to the requested JSON schema."""

        # Try configured model, then fallbacks
        models_to_try = [settings.GROQ_MODEL] + [
            m for m in settings.GROQ_FALLBACK_MODELS if m != settings.GROQ_MODEL
        ]

        last_error = None
        for model_name in models_to_try:
            try:
                logger.info("Calling Groq LLM with model: %s", model_name)
                completion = self._client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": REVIEW_SYSTEM_PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                )

                content = completion.choices[0].message.content
                if not content:
                    raise ValueError("Groq returned empty response.")

                data = json.loads(content)
                logger.info("Successfully received structured review from Groq (%s)", model_name)
                return data

            except groq.APIConnectionError as e:
                raise ValueError(f"Could not connect to Groq API: {str(e)}")
            except groq.AuthenticationError as e:
                raise ValueError(f"Groq Authentication failed. Check your GROQ_API_KEY: {str(e)}")
            except groq.BadRequestError as e:
                last_error = e
                logger.warning("Groq model %s error: %s. Trying fallback...", model_name, str(e))
                continue
            except json.JSONDecodeError as e:
                raise ValueError(f"Failed to parse LLM structured output as JSON: {str(e)}")
            except Exception as e:
                last_error = e
                logger.error("Groq review error with model %s: %s", model_name, str(e))
                continue

        raise ValueError(f"Groq review failed across attempted models: {str(last_error)}")

    def execute_auto_fix(
        self,
        original_code: str,
        language: str,
        findings: List[FindingItem],
        memories: List[MemoryItem],
    ) -> Dict[str, Any]:
        """
        Invokes Groq to generate a corrected version of the code that resolves the findings.
        """
        available, reason = self.is_available()
        if not available:
            raise ValueError(f"Groq service unavailable for auto-fix: {reason}")

        findings_text = ""
        for i, f in enumerate(findings, 1):
            findings_text += f"{i}. [{f.rule_id}] Line {f.line_start}-{f.line_end}: {f.title}\n"
            findings_text += f"   Issue: {f.explanation}\n"
            findings_text += f"   Recommended Fix: {f.recommended_fix}\n"
            if f.team_memory_used:
                findings_text += f"   Team Rule Violated: {', '.join(f.team_memory_used)}\n"

        user_content = f"""Programming Language: {language}

=== VALIDATED REVIEW FINDINGS TO RESOLVE ===
{findings_text}

=== ORIGINAL CODE TO FIX ===
```{language}
{original_code}
```

Generate the complete fixed code resolving every issue above. Adhere strictly to the requested JSON schema."""

        models_to_try = [settings.GROQ_MODEL] + [
            m for m in settings.GROQ_FALLBACK_MODELS if m != settings.GROQ_MODEL
        ]

        last_error = None
        for model_name in models_to_try:
            try:
                logger.info("Calling Auto-Fix Agent with model: %s", model_name)
                completion = self._client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": AUTO_FIX_SYSTEM_PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                )

                content = completion.choices[0].message.content
                if not content:
                    raise ValueError("Groq returned empty auto-fix response.")

                data = json.loads(content)
                logger.info("Successfully received auto-fix from Groq (%s)", model_name)
                return data

            except Exception as e:
                last_error = e
                logger.error("Auto-Fix error with model %s: %s", model_name, str(e))
                continue

        raise ValueError(f"Auto-Fix generation failed across attempted models: {str(last_error)}")


llm_service = LLMService()
