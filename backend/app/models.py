from typing import Optional, List, Literal
from pydantic import BaseModel, Field


class MemoryItem(BaseModel):
    id: str = Field(..., description="Unique memory ID")
    text: str = Field(..., description="The recalled memory text")
    type: Optional[str] = Field(None, description="Memory type or classification")
    relevance_score: Optional[float] = Field(None, description="Relevance score from recall")
    context: Optional[str] = Field(None, description="Memory context or rationale")
    tags: List[str] = Field(default_factory=list, description="Tags associated with memory")


class FindingItem(BaseModel):
    rule_id: str = Field(..., description="Unique rule identifier e.g. SQL001, SEC001, SYN001, LOG001")
    title: str = Field(..., description="Short descriptive title")
    category: Literal["security", "quality", "architecture", "performance", "syntax", "logic", "bug"] = Field(
        ..., description="Category of finding"
    )
    severity: Literal["low", "medium", "high", "critical", "info"] = Field(
        ..., description="Severity level"
    )
    confidence: float = Field(default=0.95, ge=0.0, le=1.0, description="Confidence score")
    line_start: int = Field(default=1, description="Starting line number")
    line_end: int = Field(default=1, description="Ending line number")
    explanation: str = Field(..., description="Clear explanation of the problem")
    impact: Optional[str] = Field(None, description="Technical impact or risk of finding")
    team_memory_used: List[str] = Field(
        default_factory=list, description="Citations to specific team memories"
    )
    recommended_fix: str = Field(..., description="Recommended fix description or code snippet")
    requires_fix: bool = Field(default=True, description="Whether this finding warrants an auto-fix")
    evidence: Optional[str] = Field(None, description="Code snippet or syntactic evidence")
    validated_by_scanner: bool = Field(
        default=False, description="Whether validated by deterministic security checks"
    )


class IssueItem(BaseModel):
    """Backward-compatible issue model for existing consumers."""
    title: str = Field(..., description="Short title of the issue")
    severity: Literal["low", "medium", "high", "critical", "info"] = Field(
        ..., description="Severity level"
    )
    category: Literal["security", "bug", "quality", "architecture", "performance", "syntax", "logic"] = Field(
        ..., description="Issue classification"
    )
    explanation: str = Field(..., description="Clear explanation of the problem")
    recommendation: str = Field(..., description="Actionable recommendation and fix")
    line_reference: Optional[str] = Field(
        None, description="Affected line number or range, e.g. 'Line 14-16'"
    )
    rule_violation: Optional[str] = Field(
        None, description="Name or reference to specific team memory violated, if any"
    )


class AutoFixResult(BaseModel):
    original_code: str = Field(..., description="The original submitted code")
    fixed_code: Optional[str] = Field(None, description="The validated corrected code")
    changes_made: List[str] = Field(default_factory=list, description="List of changes applied")
    remaining_risks: List[str] = Field(default_factory=list, description="Residual risks or notes")
    is_validated: bool = Field(
        default=False, description="Whether fix passed deterministic security checks"
    )
    validation_status: Literal["VERIFIED", "VALIDATION_LIMITED", "VALIDATION_FAILED"] = Field(
        default="VALIDATION_FAILED", description="Status: VERIFIED, VALIDATION_LIMITED, or VALIDATION_FAILED"
    )
    validation_message: str = Field(
        default="", description="Fix validator status e.g. 'Fix verified'"
    )
    differs_from_original: bool = Field(
        default=True, description="Whether the fixed code differs from original code"
    )
    vulnerabilities_resolved: bool = Field(
        default=True, description="Whether deterministic security checks passed on fixed code"
    )


class CodeReviewRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=500000, description="Source code to review")
    language: Optional[str] = Field("auto", description="Programming language or 'auto'")
    filename: Optional[str] = Field(None, description="Optional filename")
    context_hint: Optional[str] = Field(
        None, description="Optional developer context or PR description"
    )


class CodeReviewResponse(BaseModel):
    id: str = Field(..., description="Unique review ID")
    timestamp: str = Field(..., description="ISO timestamp")
    language: str = Field(..., description="Detected or specified programming language")
    filename: Optional[str] = Field(None, description="Optional filename")
    code_hash: Optional[str] = Field(None, description="SHA256 hash of original code")
    
    # Review Pipeline Outcome State
    review_state: Literal[
        "REVIEW_SUCCESS", "FINDINGS_FOUND", "NO_FINDINGS", "AI_PARTIAL_FAILURE", "REVIEW_ERROR", "NO_ISSUES"
    ] = Field(default="FINDINGS_FOUND", description="State: REVIEW_SUCCESS, FINDINGS_FOUND, NO_FINDINGS, AI_PARTIAL_FAILURE, REVIEW_ERROR, NO_ISSUES")

    # Status and Summary
    status: Literal["PASS", "FINDINGS"] = Field(
        default="FINDINGS", description="PASS if clean, FINDINGS if issues identified"
    )
    summary: str = Field(..., description="Executive summary of the review")
    overall_severity: Literal["low", "medium", "high", "critical", "info"] = Field(
        ..., description="Overall code quality/risk rating"
    )
    confidence: float = Field(default=0.95, ge=0.0, le=1.0, description="Confidence score")

    # Structured Findings (New multi-stage architecture)
    findings: List[FindingItem] = Field(
        default_factory=list, description="Deterministic and LLM validated findings"
    )

    # Auto-Fix
    auto_fix: Optional[AutoFixResult] = Field(
        None, description="Auto-fix results when findings require remediation"
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
