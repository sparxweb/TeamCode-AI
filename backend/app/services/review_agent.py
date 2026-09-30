import uuid
import datetime
import hashlib
import logging
import ast
from typing import Any, Dict, List, Optional, Literal
from app.models import (
    CodeReviewRequest,
    CodeReviewResponse,
    FindingItem,
    IssueItem,
    AutoFixResult,
    MemoryItem,
    SeverityLevel,
    ReviewState,
    ReviewStatus,
)
from app.services.deterministic_scanner import deterministic_scanner
from app.services.hindsight_service import hindsight_service
from app.services.llm_service import llm_service
from app.services.file_service import detect_language_from_content
from app.services.history_service import history_service
from app.services.fix_validator import fix_validator
from app.services.remediation_engine import remediation_engine

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

def _safe_float(val: Any, default: float = 0.95) -> float:
    """Safely converts an arbitrary value to float with a fallback default."""
    try:
        if isinstance(val, (int, float, str)):
            return float(val)
        return default
    except (ValueError, TypeError):
        return default


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

        if not normalized_code.strip():
            return CodeReviewResponse(
                id=review_id,
                timestamp=now_iso,
                language=lang,
                filename=request.filename,
                code_hash=code_hash,
                review_state="REVIEW_FAILED",
                review_mode="deterministic",
                fallback_used=False,
                status="PASS",
                summary="Review could not be completed: submitted code is empty.",
                overall_severity="info",
                confidence=1.0,
                findings=[],
                auto_fix=None,
                issues=[],
                security_issues=[],
                bugs=[],
                quality_issues=[],
                architecture_issues=[],
                suggestions=["Please provide valid non-empty source code for review."],
                memory_status="none_found",
                memory_message="No code submitted to evaluate.",
                memories_used=[],
                explanation="No source code was provided for review. Please submit valid code.",
            )

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
        llm_raw: Dict[str, Any] = {}
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
        if not isinstance(llm_raw, dict):
            llm_raw = {}
        raw_llm_findings = llm_raw.get("findings", [])
        if not isinstance(raw_llm_findings, list):
            if isinstance(raw_llm_findings, str) and raw_llm_findings.strip():
                raw_llm_findings = [{
                    "title": "Review Finding",
                    "explanation": raw_llm_findings,
                    "severity": "medium",
                    "category": "quality",
                }]
            else:
                raw_llm_findings = []

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

        for idx, raw in enumerate(raw_llm_findings):
            if isinstance(raw, str):
                raw = {
                    "rule_id": f"QAL{idx + 1:03d}",
                    "title": raw.strip()[:60] if raw.strip() else "Review Finding",
                    "explanation": raw.strip(),
                    "category": "quality",
                    "severity": "medium",
                    "line_start": idx + 1,
                    "line_end": idx + 1,
                    "confidence": 0.85,
                }
            elif not isinstance(raw, dict):
                continue

            raw_rule = str(raw.get("rule_id", "")).upper()
            raw_title = str(raw.get("title") or "Review Finding").strip() or "Review Finding"
            raw_cat = str(raw.get("category", "quality")).lower()
            if raw_cat not in valid_categories:
                raw_cat = "quality"
            raw_sev = str(raw.get("severity", "medium")).lower()
            if raw_sev not in valid_severities:
                raw_sev = "medium"

            raw_lstart = int(raw.get("line_start", 1) or 1)
            raw_lend = int(raw.get("line_end", raw_lstart) or raw_lstart)

            # Safely parse team_memory_used to ensure List[str] type compatibility
            raw_mem = raw.get("team_memory_used")
            if isinstance(raw_mem, list):
                team_mem_list: List[str] = [str(m) for m in raw_mem if m is not None]
            elif isinstance(raw_mem, str) and raw_mem.strip():
                team_mem_list: List[str] = [raw_mem.strip()]
            else:
                team_mem_list: List[str] = []

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
                        confidence=max(matching_det.confidence, _safe_float(raw.get("confidence"), 0.95)),
                        line_start=matching_det.line_start,
                        line_end=matching_det.line_end,
                        explanation=str(raw.get("explanation") or matching_det.explanation),
                        impact=str(raw.get("impact")) if raw.get("impact") is not None else None,
                        team_memory_used=team_mem_list,
                        recommended_fix=str(raw.get("recommended_fix") or matching_det.recommended_fix),
                        requires_fix=True,
                        evidence=ev,
                        validated_by_scanner=True,
                    )
                )
            else:
                raw_ev = raw.get("evidence")
                ev = str(raw_ev) if isinstance(raw_ev, str) and raw_ev.strip() else None
                # Ensure evidence is authentic snippet from user code
                if not ev or ev not in normalized_code:
                    ev = extract_evidence_from_code(raw_lstart, raw_lend)

                merged_findings.append(
                    FindingItem(
                        rule_id=raw_rule or f"QAL{len(merged_findings) + 1:03d}",
                        title=raw_title,
                        category=raw_cat,
                        severity=raw_sev,
                        confidence=_safe_float(raw.get("confidence"), 0.90),
                        line_start=raw_lstart,
                        line_end=raw_lend,
                        explanation=str(raw.get("explanation", "")),
                        impact=str(raw.get("impact")) if raw.get("impact") is not None else None,
                        team_memory_used=team_mem_list,
                        recommended_fix=str(raw.get("recommended_fix", "")),
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

        resolved_findings: List[FindingItem] = []
        new_findings: List[FindingItem] = []
        false_positives: List[FindingItem] = []

        review_mode: Literal["ai", "deterministic"] = "deterministic"
        fallback_used: bool = False
        review_state: ReviewState = "DETERMINISTIC_FALLBACK"
        overall_status: ReviewStatus = "FINDINGS"
        overall_severity: SeverityLevel = "medium"
        summary: str = "Code review completed."
        explanation: str = ""

        if request.is_fixed_code_review:
            # 1. Retrieve original code and original findings from request or parent review
            orig_code = request.original_code
            orig_findings = request.original_findings or []

            if request.parent_review_id and (not orig_code or not orig_findings):
                parent_data = history_service.get_review_by_id(request.parent_review_id)
                if parent_data:
                    if not orig_code:
                        parent_fix = parent_data.get("auto_fix") or {}
                        orig_code = parent_fix.get("original_code") or parent_data.get("code")
                    if not orig_findings and parent_data.get("findings"):
                        try:
                            orig_findings = [FindingItem(**f) for f in parent_data["findings"]]
                        except Exception:
                            pass

            if orig_code and orig_findings:
                # Run deterministic post-fix validation
                fix_outcome = fix_validator.validate_fix(
                    original_code=orig_code,
                    fixed_code=normalized_code,
                    language=lang,
                    original_findings=orig_findings,
                )
                resolved_findings = fix_outcome.resolved_findings
                new_findings = fix_outcome.new_findings
                false_positives = fix_outcome.false_positives

                review_mode = "deterministic"
                fallback_used = False

                if fix_outcome.vulnerabilities_resolved and len(fix_outcome.new_findings) == 0:
                    review_state = "AI_REVIEW_SUCCESS" if not llm_failed else "NO_FINDINGS"
                    overall_status = "PASS"
                    overall_severity = "low"
                    summary = f"Original issue(s) successfully RESOLVED ({len(resolved_findings)} resolved). 0 new issues introduced. Validation: PASSED."
                    explanation = (
                        "Independent multi-layer validation confirmed that all original vulnerabilities "
                        "and defects have been successfully remediated, syntax is verified, and no regressions "
                        "or new security issues were introduced."
                    )
                    unique_findings = []
                else:
                    review_state = "FINDINGS_FOUND"
                    overall_status = "FINDINGS"
                    still_present = [f for f in fix_outcome.original_findings if f.status == "STILL_PRESENT"]
                    unique_findings = still_present + fix_outcome.new_findings
                    if any(f.severity in ("critical", "high") for f in unique_findings):
                        overall_severity = "high"
                    else:
                        overall_severity = "medium"
                    summary = f"Re-review of fixed code: {len(resolved_findings)} resolved, {len(unique_findings)} issue(s) still present or newly introduced."
                    explanation = fix_outcome.validation_message

        # Determine review state, status, and severity if not fixed_code_review
        if not request.is_fixed_code_review:
            if llm_failed:
                review_mode = "deterministic"
                fallback_used = True
                review_state = "AI_PARTIAL_FAILURE"
                if not unique_findings:
                    overall_status = "PASS"
                    overall_severity = "low"
                    summary = "AI review unavailable — deterministic security analysis used (0 issues detected)."
                    explanation = (
                        "AI review unavailable — deterministic security analysis used. "
                        "Automated deterministic security rules inspected the code and identified 0 pattern violations."
                    )
                else:
                    overall_status = "FINDINGS"
                    if any(f.severity == "critical" for f in unique_findings):
                        overall_severity = "critical"
                    elif any(f.severity == "high" for f in unique_findings):
                        overall_severity = "high"
                    else:
                        overall_severity = "medium"
                    summary = f"AI review unavailable — deterministic security analysis used. Flagged {len(unique_findings)} issue(s) requiring remediation."
                    explanation = (
                        "AI review unavailable — deterministic security analysis used. "
                        "Automated deterministic safety rules flagged issue(s) requiring remediation."
                    )
            elif not unique_findings:
                review_mode = "ai"
                fallback_used = False
                review_state = "AI_REVIEW_SUCCESS"
                overall_status = "PASS"
                overall_severity = "low"
                summary = "No issues detected."
                explanation = "No security, quality, or architecture issues were identified. Code looks good — no fix required."
            else:
                review_mode = "ai"
                fallback_used = False
                review_state = "AI_REVIEW_SUCCESS"
                overall_status = "FINDINGS"
                if any(f.severity == "critical" for f in unique_findings):
                    overall_severity = "critical"
                elif any(f.severity == "high" for f in unique_findings):
                    overall_severity = "high"
                elif any(f.severity == "medium" for f in unique_findings):
                    overall_severity = "medium"
                else:
                    overall_severity = "low"
                summary = str(
                    llm_raw.get(
                        "summary",
                        f"Code review identified {len(unique_findings)} finding(s) requiring attention.",
                    )
                )
                explanation = str(llm_raw.get("explanation", "") or "")

        # 6. AUTO-FIX AGENT & 7. FIX VALIDATOR
        auto_fix_result: Optional[AutoFixResult] = None
        has_fixable_findings = any(f.requires_fix for f in unique_findings)

        if not request.is_fixed_code_review and overall_status == "FINDINGS" and has_fixable_findings:
            candidate_fixed_code: Optional[str] = None
            changes_made: List[str] = []
            remaining_risks: List[str] = []
            remediation_method: Literal["llm", "deterministic", "none"] = "none"

            # Level 1: Try LLM fix if service is available
            try:
                fix_data = llm_service.execute_auto_fix(
                    original_code=normalized_code,
                    language=lang,
                    findings=unique_findings,
                    memories=recalled_memories,
                )
                code_cand = fix_data.get("fixed_code")
                if code_cand and code_cand.strip():
                    candidate_fixed_code = code_cand.strip()
                    changes_made = fix_data.get("changes_made", [])
                    remaining_risks = fix_data.get("remaining_risks", [])
                    remediation_method = "llm"
            except Exception as e:
                logger.warning("LLM auto-fix failed, falling back to deterministic remediation: %s", str(e))

            # Level 2: Deterministic remediation engine fallback
            if not candidate_fixed_code:
                try:
                    det_fix = remediation_engine.generate_remediation(
                        original_code=normalized_code,
                        language=lang,
                        findings=unique_findings,
                        context_hint=request.context_hint,
                    )
                    if det_fix and det_fix.fixed_code and det_fix.fixed_code.strip() != normalized_code:
                        candidate_fixed_code = det_fix.fixed_code.strip()
                        changes_made = det_fix.changes_made
                        remaining_risks = det_fix.remaining_risks
                        remediation_method = "deterministic"
                except Exception as e:
                    logger.error("Deterministic remediation engine encountered error: %s", str(e))

            # Step: Validate candidate fix if generated
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

                resolved_findings = outcome.resolved_findings
                new_findings = outcome.new_findings
                false_positives = outcome.false_positives

                remediation_status = "verified" if outcome.validation_status == "VERIFIED" else "validation_failed"

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
                    original_findings=outcome.original_findings,
                    fixed_code_findings=outcome.fixed_code_findings,
                    resolved_findings=outcome.resolved_findings,
                    new_findings=outcome.new_findings,
                    false_positives=outcome.false_positives,
                    verification_checks=outcome.verification_checks,
                    portability_notes=outcome.portability_notes,
                    remediation_status=remediation_status,
                    remediation_method=remediation_method,
                )
            else:
                # Level 3: No automatic fix available with sufficient confidence
                auto_fix_result = AutoFixResult(
                    original_code=normalized_code,
                    fixed_code=None,
                    changes_made=[],
                    remaining_risks=["Automatic remediation could not be safely generated with sufficient confidence. Manual fix recommended."],
                    is_validated=False,
                    validation_status="NOT_VALIDATED",
                    validation_message="Automatic fix unavailable: Safe automatic remediation could not be generated.",
                    differs_from_original=False,
                    vulnerabilities_resolved=False,
                    remediation_status="unavailable",
                    remediation_method="none",
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

        if not explanation or not explanation.strip():
            raw_expl = llm_raw.get("explanation")
            if isinstance(raw_expl, str) and raw_expl.strip():
                explanation = raw_expl.strip()
            else:
                explanation = "Review evaluated against deterministic security rules, team standards, and secure engineering practices."

        response = CodeReviewResponse(
            id=review_id,
            timestamp=now_iso,
            language=lang,
            filename=request.filename,
            code_hash=code_hash,
            review_state=review_state,
            review_mode=review_mode,
            fallback_used=fallback_used,
            status=overall_status,
            summary=summary,
            overall_severity=overall_severity,
            confidence=_safe_float(llm_raw.get("confidence"), 0.95),
            findings=unique_findings,
            auto_fix=auto_fix_result,
            resolved_findings=resolved_findings,
            new_findings=new_findings,
            false_positives=false_positives,
            is_fixed_code_review=bool(request.is_fixed_code_review),
            issues=legacy_issues,
            security_issues=security_issues,
            bugs=bugs,
            quality_issues=quality_issues,
            architecture_issues=architecture_issues,
            suggestions=suggestions,
            memory_status=memory_status,
            memory_message=memory_msg,
            memories_used=recalled_memories,
            explanation=explanation,
        )

        # 9. Save to history
        try:
            history_service.save_review(response.model_dump())
        except Exception as e:
            logger.error("Failed to save review to history: %s", str(e))

        return response


review_agent = ReviewAgent()
