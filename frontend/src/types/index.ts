export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type IssueCategory = 'security' | 'bug' | 'quality' | 'architecture';
export type MemoryStatus = 'recalled' | 'none_found' | 'unavailable';

export interface MemoryItem {
  id: string;
  text: string;
  type?: string;
  relevance_score?: number | null;
  context?: string | null;
  tags: string[];
}

export interface IssueItem {
  title: string;
  severity: Severity;
  category: IssueCategory;
  explanation: string;
  recommendation: string;
  line_reference?: string | null;
  rule_violation?: string | null;
}

export interface FindingItem {
  finding_id?: string;
  rule_id: string;
  title: string;
  category: 'security' | 'quality' | 'architecture' | 'performance' | 'syntax' | 'logic' | 'bug';
  severity: Severity;
  confidence: number;
  line_start: number;
  line_end: number;
  explanation: string;
  impact?: string | null;
  team_memory_used: string[];
  recommended_fix: string;
  requires_fix: boolean;
  evidence?: string | null;
  validated_by_scanner?: boolean;
  status?: 'RESOLVED' | 'STILL_PRESENT' | 'NEW_ISSUE' | 'PRE_EXISTING' | 'FALSE_POSITIVE' | 'UNABLE_TO_VERIFY';
  resolution_note?: string | null;
  portability_note?: string | null;
}

export interface AutoFixResult {
  original_code: string;
  fixed_code?: string | null;
  changes_made: string[] | string;
  remaining_risks: string[] | string;
  is_validated: boolean;
  validation_status?: 'VERIFIED' | 'VALIDATION_LIMITED' | 'VALIDATION_FAILED' | 'NOT_VALIDATED';
  remediation_status?: 'verified' | 'generated' | 'validation_failed' | 'unavailable' | 'unsafe_to_autofix';
  remediation_method?: 'llm' | 'deterministic' | 'none';
  validation_message: string;
  differs_from_original?: boolean;
  vulnerabilities_resolved?: boolean;
  original_findings?: FindingItem[];
  fixed_code_findings?: FindingItem[];
  resolved_findings?: FindingItem[];
  new_findings?: FindingItem[];
  false_positives?: FindingItem[];
  verification_checks?: string[];
  portability_notes?: string[];
}

export interface CodeReviewRequest {
  code: string;
  language?: string;
  filename?: string | null;
  context_hint?: string | null;
  parent_review_id?: string;
  original_code?: string;
  original_findings?: FindingItem[];
  is_fixed_code_review?: boolean;
}

export interface CodeReviewResponse {
  id: string;
  timestamp: string;
  language: string;
  filename?: string | null;
  status: 'PASS' | 'FINDINGS';
  success?: boolean;
  review_mode?: 'ai' | 'deterministic';
  fallback_used?: boolean;
  system_reason?: string | null;
  review_state?: 'AI_REVIEW_SUCCESS' | 'DETERMINISTIC_FALLBACK' | 'REVIEW_FAILED' | 'REVIEW_SUCCESS' | 'FINDINGS_FOUND' | 'NO_FINDINGS' | 'NO_ISSUES' | 'AI_PARTIAL_FAILURE' | 'REVIEW_ERROR';
  summary: string;
  overall_severity: Severity;
  confidence: number;
  findings: FindingItem[];
  resolved_findings?: FindingItem[];
  new_findings?: FindingItem[];
  false_positives?: FindingItem[];
  is_fixed_code_review?: boolean;
  auto_fix?: AutoFixResult | null;
  code_hash?: string;
  // Legacy / fallback fields
  issues: IssueItem[];
  security_issues: IssueItem[];
  bugs: IssueItem[];
  quality_issues: IssueItem[];
  architecture_issues: IssueItem[];
  suggestions: string[];
  memory_status: MemoryStatus;
  memory_message: string;
  memories_used: MemoryItem[];
  explanation: string;
}

export interface RetainMemoryRequest {
  memory_type: string;
  content: string;
  context?: string;
  tags?: string[];
}

export interface RetainMemoryResponse {
  success: boolean;
  message: string;
  bank_id: string;
  operation_id?: string;
  retained_memory: {
    content: string;
    type: string;
    context?: string;
    tags?: string[];
  };
}

export interface RecallQueryResponse {
  query: string;
  status: MemoryStatus;
  count: number;
  memories: MemoryItem[];
  message: string;
}

export interface ServiceHealth {
  status: string;
  groq_configured: boolean;
  groq_model: string;
  hindsight_configured: boolean;
  hindsight_bank_id: string;
  hindsight_base_url: string;
  note: string;
}

export interface HistoryItem {
  id: string;
  timestamp: string;
  language: string;
  filename?: string | null;
  summary: string;
  overall_severity: Severity;
  issues_count: number;
  memories_count: number;
  memory_status: MemoryStatus;
}
