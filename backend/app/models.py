from typing import Optional, List, Literal
from pydantic import BaseModel, Field

SeverityLevel = Literal["low", "medium", "high", "critical", "info"]
ReviewState = Literal[
    "AI_REVIEW_SUCCESS", "DETERMINISTIC_FALLBACK", "REVIEW_FAILED",
    "REVIEW_SUCCESS", "FINDINGS_FOUND", "NO_FINDINGS", "AI_PARTIAL_FAILURE", "REVIEW_ERROR", "NO_ISSUES"
]
ReviewStatus = Literal["PASS", "FINDINGS"]


class MemoryItem(BaseModel):
    id: str = Field(..., description="Unique memory ID")
    text: str = Field(..., description="The recalled memory text")
    type: Optional[str] = Field(None, description="Memory type or classification")
    relevance_score: Optional[float] = Field(None, description="Relevance score from recall")
    context: Optional[str] = Field(None, description="Memory context or rationale")
    tags: List[str] = Field(default_factory=list, description="Tags associated with memory")


class FindingItem(BaseModel):
    finding_id: Optional[str] = Field(default=None, description="Stable unique identifier e.g. CMD001_a1b2c3d4")
    rule_id: str = Field(..., description="Unique rule identifier e.g. SQL001, SEC001, SYN001, LOG001, CMD001")
    title: str = Field(..., description="Short descriptive title")
    category: Literal["security", "quality", "architecture", "performance", "syntax", "logic", "bug"] = Field(
        ..., description="Category of finding"
    )
    severity: SeverityLevel = Field(
        ..., description="Severity level"
    )
    confidence: float = Field(default=0.95, ge=0.0, le=1.0, description="Confidence score")
    line_start: int = Field(default=1, description="Starting line number")
    line_end: int = Field(default=1, description="Ending line number")
    explanation: str = Field(..., description="Clear explanation of the problem")
    impact: Optional[str] = Field(default=None, description="Technical impact or risk of finding")
    team_memory_used: List[str] = Field(
        default_factory=list, description="Citations to specific team memories"
    )
    recommended_fix: str = Field(..., description="Recommended fix description or code snippet")
    requires_fix: bool = Field(default=True, description="Whether this finding warrants an auto-fix")
    evidence: Optional[str] = Field(default=None, description="Code snippet or syntactic evidence")
    validated_by_scanner: bool = Field(
        default=False, description="Whether validated by deterministic security checks"
    )
    status: Literal["RESOLVED", "STILL_PRESENT", "NEW_ISSUE", "PRE_EXISTING", "FALSE_POSITIVE", "UNABLE_TO_VERIFY"] = Field(
        default="STILL_PRESENT", description="Lifecycle status: RESOLVED, STILL_PRESENT, NEW_ISSUE, FALSE_POSITIVE, UNABLE_TO_VERIFY"
    )
    resolution_note: Optional[str] = Field(default=None, description="Explanation of how the issue was verified as resolved")
    portability_note: Optional[str] = Field(default=None, description="Portability/compatibility note if applicable")


class IssueItem(BaseModel):
    """Backward-compatible issue model for existing consumers."""
    title: str = Field(..., description="Short title of the issue")
    severity: SeverityLevel = Field(
        ..., description="Severity level"
    )
    category: Literal["security", "bug", "quality", "architecture", "performance", "syntax", "logic"] = Field(
        ..., description="Issue classification"
    )
    explanation: str = Field(..., description="Clear explanation of the problem")
    recommendation: str = Field(..., description="Actionable recommendation and fix")
    line_reference: Optional[str] = Field(
        default=None, description="Affected line number or range, e.g. 'Line 14-16'"
    )
    rule_violation: Optional[str] = Field(
        default=None, description="Name or reference to specific team memory violated, if any"
    )


class AutoFixResult(BaseModel):
    original_code: str = Field(..., description="The original submitted code")
    fixed_code: Optional[str] = Field(default=None, description="The validated corrected code")
    changes_made: List[str] = Field(default_factory=list, description="List of changes applied")
    remaining_risks: List[str] = Field(default_factory=list, description="Residual risks or notes")
    is_validated: bool = Field(
        default=False, description="Whether fix passed deterministic security checks"
    )
    validation_status: Literal["VERIFIED", "VALIDATION_LIMITED", "VALIDATION_FAILED", "NOT_VALIDATED"] = Field(
        default="NOT_VALIDATED", description="Status: VERIFIED, VALIDATION_LIMITED, VALIDATION_FAILED, or NOT_VALIDATED"
    )
    validation_message: str = Field(
        default="", description="Fix validator status e.g. 'Fix verified'"
    )
    differs_from_original: bool = Field(
        default=False, description="Whether the fixed code differs from original code"
    )
    vulnerabilities_resolved: bool = Field(
        default=False, description="Whether deterministic security checks passed on fixed code"
    )
    remediation_status: Literal["verified", "generated", "validation_failed", "unavailable", "unsafe_to_autofix"] = Field(
        default="unavailable", description="Remediation status: verified, generated, validation_failed, unavailable, or unsafe_to_autofix"
    )
    remediation_method: Literal["llm", "deterministic", "none"] = Field(
        default="none", description="Remediation method: llm, deterministic, or none"
    )
    original_findings: List[FindingItem] = Field(
        default_factory=list, description="Original findings detected before fix"
    )
    fixed_code_findings: List[FindingItem] = Field(
        default_factory=list, description="Findings detected on fixed code"
    )
    resolved_findings: List[FindingItem] = Field(
        default_factory=list, description="Original findings confirmed resolved by fix"
    )
    new_findings: List[FindingItem] = Field(
        default_factory=list, description="New findings introduced by fix"
    )
    false_positives: List[FindingItem] = Field(
        default_factory=list, description="Findings classified as false positives / benign"
    )
    verification_checks: List[str] = Field(
        default_factory=list, description="Exact checks performed during validation"
    )
    portability_notes: List[str] = Field(
        default_factory=list, description="Platform portability observations"
    )


class CodeReviewRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=500000, description="Source code to review")
    language: Optional[str] = Field(default="auto", description="Programming language or 'auto'")
    filename: Optional[str] = Field(default=None, description="Optional filename")
    context_hint: Optional[str] = Field(
        default=None, description="Optional developer context or PR description"
    )
    parent_review_id: Optional[str] = Field(default=None, description="Optional ID of parent review being re-reviewed")
    original_code: Optional[str] = Field(default=None, description="Original code before fix if reviewing fixed code")
    original_findings: Optional[List[FindingItem]] = Field(default=None, description="Original findings if reviewing fixed code")
    is_fixed_code_review: Optional[bool] = Field(default=False, description="Whether this request is reviewing fixed code")


class CodeReviewResponse(BaseModel):
    id: str = Field(..., description="Unique review ID")
    timestamp: str = Field(..., description="ISO timestamp")
    language: str = Field(..., description="Detected or specified programming language")
    filename: Optional[str] = Field(default=None, description="Optional filename")
    code_hash: Optional[str] = Field(default=None, description="SHA256 hash of original code")
    is_fixed_code_review: bool = Field(default=False, description="Whether this is a review of fixed code")
    review_mode: Literal["ai", "deterministic"] = Field(
        default="deterministic", description="Review execution mode: ai or deterministic"
    )
    fallback_used: bool = Field(
        default=False, description="Whether deterministic fallback was used"
    )
    
    # Review Pipeline Outcome State
    review_state: ReviewState = Field(
        default="DETERMINISTIC_FALLBACK",
        description="State: AI_REVIEW_SUCCESS, DETERMINISTIC_FALLBACK, REVIEW_FAILED, REVIEW_SUCCESS, FINDINGS_FOUND, NO_FINDINGS, AI_PARTIAL_FAILURE, REVIEW_ERROR, NO_ISSUES",
    )

    # Status and Summary
    status: ReviewStatus = Field(
        default="FINDINGS", description="PASS if clean, FINDINGS if issues identified"
    )
    summary: str = Field(..., description="Executive summary of the review")
    overall_severity: SeverityLevel = Field(
        ..., description="Overall code quality/risk rating"
    )
    confidence: float = Field(default=0.95, ge=0.0, le=1.0, description="Confidence score")

    # Structured Findings (Multi-stage architecture)
    findings: List[FindingItem] = Field(
        default_factory=list, description="Deterministic and LLM validated findings"
    )
    resolved_findings: List[FindingItem] = Field(
        default_factory=list, description="Original findings verified as resolved"
    )
    new_findings: List[FindingItem] = Field(
        default_factory=list, description="New findings introduced"
    )
    false_positives: List[FindingItem] = Field(
        default_factory=list, description="Benign or false positive findings"
    )

    # Auto-Fix
    auto_fix: Optional[AutoFixResult] = Field(
        default=None, description="Auto-fix results when findings require remediation"
    )

    # Backward-compatible categorized issues
    issues: List[IssueItem] = Field(default_factory=list, description="All detected issues")
    security_issues: List[IssueItem] = Field(default_factory=list)
    bugs: List[IssueItem] = Field(default_factory=list)
    quality_issues: List[IssueItem] = Field(default_factory=list)
    architecture_issues: List[IssueItem] = Field(default_factory=list)
    suggestions: List[str] = Field(default_factory=list, description="General suggestions")

    # Hindsight Memory Contribution (Visible to user)
    memory_status: Literal["recalled", "none_found", "unavailable"] = Field(
        ..., description="Hindsight recall status"
    )
    memory_message: str = Field(
        ..., description="User-facing summary of Hindsight memory status"
    )
    memories_used: List[MemoryItem] = Field(
        default_factory=list, description="Specific team memories that influenced this review"
    )
    explanation: str = Field(
        ..., description="Detailed explanation of how team standards were evaluated"
    )


class RetainMemoryRequest(BaseModel):
    memory_type: str = Field(
        default="Team Standard",
        description="Type: Team Standard, Architecture Decision, Security Policy, Exception, Previous Review",
    )
    content: str = Field(..., min_length=5, description="Rule or team memory content to retain")
    context: Optional[str] = Field(
        None, description="Why this rule exists, historical context, or justification"
    )
    tags: List[str] = Field(default_factory=list, description="Keywords / domain tags")


class RetainMemoryResponse(BaseModel):
    success: bool
    message: str
    bank_id: str
    operation_id: Optional[str] = None
    retained_memory: dict = Field(default_factory=dict)


class RecallQueryRequest(BaseModel):
    query: str = Field(..., min_length=2, description="Query string for memory recall")
    max_tokens: Optional[int] = Field(2048, description="Budget for returned tokens")


class RecallQueryResponse(BaseModel):
    query: str
    status: Literal["recalled", "none_found", "unavailable"]
    count: int
    memories: List[MemoryItem]
    message: str


class ServiceHealthResponse(BaseModel):
    status: str
    groq_configured: bool
    groq_model: str
    hindsight_configured: bool
    hindsight_bank_id: str
    hindsight_base_url: str
    active_memory_count: Optional[int] = None
    note: str
