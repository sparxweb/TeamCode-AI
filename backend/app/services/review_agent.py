import uuid
import datetime
import hashlib
import logging
import ast
from typing import List, Optional
from app.models import (
    CodeReviewRequest,
    CodeReviewResponse,
    FindingItem,
    IssueItem,
    AutoFixResult,
    MemoryItem,
)
from app.services.deterministic_scanner import deterministic_scanner
from app.services.hindsight_service import hindsight_service
from app.services.llm_service import llm_service
from app.services.file_service import detect_language_from_content
from app.services.history_service import history_service
from app.services.fix_validator import fix_validator

logger = logging.getLogger("teamcode.agent")


def preprocess_code(raw_code: str) -> str:
    """
    Normalizes submitted code:
    - Normalizes line endings (\r\n -> \n)
    - Strips trailing whitespace while preserving lines and indentation
    - Never executes untrusted user code
    """
    if not raw_code:
        return ""
    normalized = raw_code.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in normalized.split("\n")]
    return "\n".join(lines).strip("\n")


def derive_focused_recall_query(code: str, language: str, context_hint: Optional[str] = None) -> str:
    """
    Derives a targeted Hindsight recall query based on the code's semantic domain,
    syntax elements, libraries used, and developer context.
    """
    code_lower = code.lower()
    detected_topics = []

    # Check for common engineering domains
    if any(k in code_lower for k in ["select", "insert", "update", "delete", "from", "cursor.execute", "session.query", "db.", "sql"]):
        detected_topics.append("database queries SQL parameterized ORM")
    if any(k in code_lower for k in ["password", "token", "auth", "secret", "bearer", "api_key", "jwt", "crypto"]):
        detected_topics.append("authentication security credentials tokens")
    if any(k in code_lower for k in ["try", "except", "catch", "throw", "raise", "error", "exception"]):
        detected_topics.append("error handling exceptions")
    if any(k in code_lower for k in ["logger", "logging", "log.", "console.log", "print("]):
        detected_topics.append("logging monitoring observability")
    if any(k in code_lower for k in ["http", "request", "axios", "fetch", "endpoint", "api", "route", "fastapi"]):
        detected_topics.append("api endpoints HTTP client communication")
    if any(k in code_lower for k in ["class ", "interface ", "abstract ", "extends ", "implements ", "service"]):
        detected_topics.append("architecture design patterns layering")

    query_parts = [f"Language: {language}"]
    if detected_topics:
        query_parts.append("Topics: " + ", ".join(detected_topics))
    if context_hint:
        query_parts.append(f"Context: {context_hint}")

    if len(query_parts) == 1:
        query_parts.append("team coding standards architecture best practices security rules")

    return " | ".join(query_parts)


class ReviewAgent:
    """
    Multi-stage review agent:
    1. Code Preprocessing & Normalization
    2. Deterministic Security Checks (lightweight rule engine)
    3. Hindsight Memory Retrieval (categorized team standards)
    4. Groq Review Engine (structured output)
    5. Review Validation & Finding Merging
    6. Auto-Fix Agent
    7. Fix Validator
    """

    def review_code(self, request: CodeReviewRequest) -> CodeReviewResponse:
        review_id = str(uuid.uuid4())
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. CODE PREPROCESSOR
        normalized_code = preprocess_code(request.code)
        lang = request.language or "auto"
        if lang == "auto":
            lang = detect_language_from_content(normalized_code)
        code_hash = hashlib.sha256(normalized_code.encode("utf-8")).hexdigest()[:16]

        # 2. DETERMINISTIC SECURITY CHECKS
        deterministic_findings = deterministic_scanner.scan(normalized_code, lang)
        logger.info(
            "Deterministic scanner identified %d findings on %s code",
            len(deterministic_findings),
            lang,
        )

        # 3. HINDSIGHT MEMORY RETRIEVAL
        recall_query = derive_focused_recall_query(normalized_code, lang, request.context_hint)
        logger.info("Executing Hindsight RECALL with query: %s", recall_query)

        memory_status, recalled_memories, memory_msg = hindsight_service.recall(
            query=recall_query,
            max_tokens=4096,
        )

        # 4. GROQ REVIEW ENGINE
        llm_raw = {}
        llm_failed = False
        llm_error_msg = ""
        try:
            llm_raw = llm_service.execute_review(
                code=normalized_code,
                language=lang,
                memories=recalled_memories,
                context_hint=request.context_hint,
                deterministic_findings=deterministic_findings,
            )
        except Exception as e:
            llm_failed = True
            llm_error_msg = str(e)
            logger.error("Groq review execution encountered error: %s", str(e))
            if deterministic_findings:
                llm_raw = {
                    "status": "FINDINGS",
                    "summary": f"Deterministic security checks identified {len(deterministic_findings)} vulnerability(ies). (AI review service temporarily unavailable)",
                    "overall_severity": "high",
                    "confidence": 0.95,
                    "findings": [],
                    "explanation": f"Automated deterministic security rules flagged issues. Note: AI review returned an error ({llm_error_msg}).",
                }
            else:
                llm_raw = {
                    "status": "FINDINGS",
                    "summary": f"AI review unavailable ({llm_error_msg}). Deterministic analysis completed.",
                    "overall_severity": "low",
                    "confidence": 0.50,
                    "findings": [],
                    "explanation": f"AI review provider encountered an error ({llm_error_msg}). Because comprehensive AI analysis could not run, this code cannot be certified as clean.",
                }

        # 5. REVIEW VALIDATION & MERGING
        # 5. REVIEW VALIDATION & MERGING
        raw_llm_findings = llm_raw.get("findings", [])
        merged_findings: List[FindingItem] = []
        code_lines = normalized_code.split("\n")

        def extract_evidence_from_code(lstart: int, lend: int) -> Optional[str]:
            if not code_lines or not normalized_code.strip():
                return None
            start_idx = max(0, min(lstart - 1, len(code_lines) - 1))
            end_idx = max(start_idx + 1, min(lend, len(code_lines)))
            snippet = "\n".join(code_lines[start_idx:end_idx]).strip()
            return snippet if snippet else None

        # Track which deterministic findings have been merged
        merged_det_rules = set()

        valid_categories = ("security", "quality", "architecture", "performance", "syntax", "logic", "bug")
        valid_severities = ("info", "low", "medium", "high", "critical")

        for raw in raw_llm_findings:
            raw_rule = str(raw.get("rule_id", "")).upper()
            raw_title = raw.get("title", "Review Finding")
            raw_cat = str(raw.get("category", "quality")).lower()
            if raw_cat not in valid_categories:
                raw_cat = "quality"
            raw_sev = str(raw.get("severity", "medium")).lower()
            if raw_sev not in valid_severities:
                raw_sev = "medium"

            raw_lstart = int(raw.get("line_start", 1) or 1)
            raw_lend = int(raw.get("line_end", raw_lstart) or raw_lstart)

            # Check if this matches a deterministic finding
            matching_det = None
            for df in deterministic_findings:
                if (
                    df.rule_id == raw_rule
                    or (df.category == raw_cat and abs(df.line_start - raw_lstart) <= 2)
                    or (raw_rule and raw_rule in df.rule_id)
                ):
                    matching_det = df
                    merged_det_rules.add(df.rule_id)
                    break

            if matching_det:
                # Merge: use deterministic exact lines, rule_id, evidence + LLM explanation & memory citations
                ev = matching_det.evidence or extract_evidence_from_code(matching_det.line_start, matching_det.line_end)
                merged_findings.append(
                    FindingItem(
                        rule_id=matching_det.rule_id,
                        title=matching_det.title or raw_title,
                        category=matching_det.category,
                        severity=matching_det.severity,
                        confidence=max(matching_det.confidence, float(raw.get("confidence", 0.95))),
                        line_start=matching_det.line_start,
                        line_end=matching_det.line_end,
                        explanation=raw.get("explanation") or matching_det.explanation,
                        impact=raw.get("impact"),
                        team_memory_used=raw.get("team_memory_used") or [],
                        recommended_fix=raw.get("recommended_fix") or matching_det.recommended_fix,
                        requires_fix=True,
                        evidence=ev,
                        validated_by_scanner=True,
                    )
                )
            else:
                ev = raw.get("evidence")
                # Ensure evidence is authentic snippet from user code
                if not ev or ev not in normalized_code:
                    ev = extract_evidence_from_code(raw_lstart, raw_lend)

                merged_findings.append(
                    FindingItem(
                        rule_id=raw_rule or f"QAL{len(merged_findings) + 1:03d}",
                        title=raw_title,
                        category=raw_cat,
                        severity=raw_sev,
                        confidence=float(raw.get("confidence", 0.90)),
                        line_start=raw_lstart,
                        line_end=raw_lend,
                        explanation=raw.get("explanation", ""),
                        impact=raw.get("impact"),
                        team_memory_used=raw.get("team_memory_used") or [],
                        recommended_fix=raw.get("recommended_fix", ""),
                        requires_fix=bool(raw.get("requires_fix", True)),
                        evidence=ev,
                        validated_by_scanner=False,
                    )
                )

        # NEVER DROP DETERMINISTIC HIGH-CONFIDENCE FINDINGS:
        # If the LLM missed any deterministic findings, add them explicitly
        for df in deterministic_findings:
            if df.rule_id not in merged_det_rules:
                # Ensure evidence is populated
                if not df.evidence:
                    df.evidence = extract_evidence_from_code(df.line_start, df.line_end)
                # Check if any memory matches this rule to cite it
                matched_team_mem = []
                if df.rule_id == "SQL001" and recalled_memories:
                    for rm in recalled_memories:
                        if any(k in rm.text.lower() for k in ["parameterized", "sql", "query"]):
                            matched_team_mem.append(rm.text)

                df.team_memory_used = matched_team_mem
                merged_findings.append(df)

        # Deduplicate findings by (rule_id, line_start) or overlapping lines with same category
        unique_findings: List[FindingItem] = []
        seen_keys = set()
        for f in merged_findings:
            # Primary deduplication key
            key = (f.rule_id, f.line_start)
            # Check if there is already an existing finding with same category and same line
            duplicate = False
            for existing in unique_findings:
                if existing.rule_id == f.rule_id and existing.line_start == f.line_start:
                    duplicate = True
                    break
                if existing.category == f.category and abs(existing.line_start - f.line_start) == 0:
                    # Same category, exact same line: merge
                    duplicate = True
                    # If this one has higher confidence or validated_by_scanner, elevate
                    if f.validated_by_scanner and not existing.validated_by_scanner:
                        existing.validated_by_scanner = True
                        existing.rule_id = f.rule_id
                        existing.evidence = f.evidence
                    existing.confidence = max(existing.confidence, f.confidence)
                    break

            if not duplicate and key not in seen_keys:
                unique_findings.append(f)
                seen_keys.add(key)

        # Determine review state, status, and severity
        if llm_failed:
            review_state = "AI_PARTIAL_FAILURE"
            overall_status = "FINDINGS"
            if not unique_findings:
                overall_severity = "low"
                summary = "AI review unavailable. Deterministic analysis completed."
                explanation = (
                    f"AI review encountered an issue ({llm_error_msg}). "
                    "Deterministic analysis found no obvious pattern violations, "
                    "but complete AI validation could not be performed."
                )
            else:
                if any(f.severity == "critical" for f in unique_findings):
                    overall_severity = "critical"
                elif any(f.severity == "high" for f in unique_findings):
                    overall_severity = "high"
                else:
                    overall_severity = "medium"
                summary = f"Deterministic security checks identified {len(unique_findings)} vulnerability(ies). (AI review layer was unavailable)"
                explanation = (
                    f"Automated deterministic safety rules flagged issue(s) requiring remediation. "
                    f"Note: AI review service was unavailable ({llm_error_msg})."
                )
        elif not unique_findings:
            review_state = "NO_FINDINGS"
            overall_status = "PASS"
            overall_severity = "low"
            summary = "No issues detected."
            explanation = "No security, quality, or architecture issues were identified. Code looks good — no fix required."
        else:
            review_state = "FINDINGS_FOUND"
            overall_status = "FINDINGS"
            if any(f.severity == "critical" for f in unique_findings):
                overall_severity = "critical"
            elif any(f.severity == "high" for f in unique_findings):
                overall_severity = "high"
            elif any(f.severity == "medium" for f in unique_findings):
                overall_severity = "medium"
            else:
                overall_severity = "low"
            summary = llm_raw.get(
                "summary",
                f"Code review identified {len(unique_findings)} finding(s) requiring attention.",
            )
            explanation = llm_raw.get("explanation", "")

        # 6. AUTO-FIX AGENT & 7. FIX VALIDATOR
        auto_fix_result: Optional[AutoFixResult] = None
        has_fixable_findings = any(f.requires_fix for f in unique_findings)

        if overall_status == "FINDINGS" and has_fixable_findings:
            try:
                candidate_fixed_code = None
                changes_made = []
                remaining_risks = []

                if not llm_failed:
                    fix_data = llm_service.execute_auto_fix(
                        original_code=normalized_code,
                        language=lang,
                        findings=unique_findings,
                        memories=recalled_memories,
                    )
                    candidate_fixed_code = fix_data.get("fixed_code")
                    changes_made = fix_data.get("changes_made", [])
                    remaining_risks = fix_data.get("remaining_risks", [])

                if candidate_fixed_code and candidate_fixed_code.strip():
                    outcome = fix_validator.validate_fix(
                        original_code=normalized_code,
                        fixed_code=candidate_fixed_code,
                        language=lang,
                        original_findings=unique_findings,
                    )

                    all_risks = list(remaining_risks)
                    for r in outcome.remaining_risks:
                        if r not in all_risks:
                            all_risks.append(r)

                    auto_fix_result = AutoFixResult(
                        original_code=normalized_code,
                        fixed_code=candidate_fixed_code,
                        changes_made=changes_made,
                        remaining_risks=all_risks,
                        is_validated=outcome.is_validated,
                        validation_status=outcome.validation_status,
                        validation_message=outcome.validation_message,
                        differs_from_original=outcome.differs_from_original,
                        vulnerabilities_resolved=outcome.vulnerabilities_resolved,
                    )
            except Exception as e:
                logger.error("Auto-Fix agent error: %s", str(e))
                auto_fix_result = AutoFixResult(
                    original_code=normalized_code,
                    fixed_code=None,
                    changes_made=[],
                    remaining_risks=[f"Auto-fix generation encountered an error: {str(e)}"],
                    is_validated=False,
                    validation_status="VALIDATION_FAILED",
                    validation_message="Fix requires review: fix generator encountered an error.",
                    differs_from_original=False,
                    vulnerabilities_resolved=False,
                )

        # 8. Backward Compatibility: Map FindingItem to IssueItem
        legacy_issues: List[IssueItem] = []
        for f in unique_findings:
            legacy_issues.append(
                IssueItem(
                    title=f.title,
                    severity=f.severity,
                    category=f.category if f.category in ("security", "bug", "quality", "architecture") else "quality",
                    explanation=f.explanation,
                    recommendation=f.recommended_fix,
                    line_reference=f"Line {f.line_start}" if f.line_start == f.line_end else f"Lines {f.line_start}-{f.line_end}",
                    rule_violation=", ".join(f.team_memory_used) if f.team_memory_used else None,
                )
            )

        security_issues = [i for i in legacy_issues if i.category == "security"]
        bugs = [i for i in legacy_issues if i.category == "bug"]
        quality_issues = [i for i in legacy_issues if i.category == "quality"]
        architecture_issues = [i for i in legacy_issues if i.category == "architecture"]

        # Parse suggestions
        suggestions = llm_raw.get("suggestions", [])
        if not isinstance(suggestions, list):
            suggestions = [str(suggestions)]

        response = CodeReviewResponse(
            id=review_id,
            timestamp=now_iso,
            language=lang,
            filename=request.filename,
            code_hash=code_hash,
            review_state=review_state,
            status=overall_status,
            summary=summary,
            overall_severity=overall_severity,
            confidence=float(llm_raw.get("confidence", 0.95)),
            findings=unique_findings,
            auto_fix=auto_fix_result,
            issues=legacy_issues,
            security_issues=security_issues,
            bugs=bugs,
            quality_issues=quality_issues,
            architecture_issues=architecture_issues,
            suggestions=suggestions,
            memory_status=memory_status,
            memory_message=memory_msg,
            memories_used=recalled_memories,
            explanation=llm_raw.get(
                "explanation",
                "Review evaluated against deterministic security rules, team standards, and secure engineering practices.",
            ),
        )

        # 9. Save to history
        try:
            history_service.save_review(response.model_dump())
        except Exception as e:
            logger.error("Failed to save review to history: %s", str(e))

        return response


review_agent = ReviewAgent()
