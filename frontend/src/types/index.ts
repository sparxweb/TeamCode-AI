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
}

export interface AutoFixResult {
  original_code: string;
  fixed_code: string;
  changes_made: string[] | string;
  remaining_risks: string[] | string;
  is_validated: boolean;
  validation_status?: 'VERIFIED' | 'VALIDATION_LIMITED' | 'VALIDATION_FAILED';
  validation_message: string;
  differs_from_original?: boolean;
  vulnerabilities_resolved?: boolean;
}

export interface CodeReviewResponse {
  id: string;
  timestamp: string;
  language: string;
  filename?: string | null;
  status: 'PASS' | 'FINDINGS';
  review_state?: 'REVIEW_SUCCESS' | 'FINDINGS_FOUND' | 'NO_FINDINGS' | 'NO_ISSUES' | 'AI_PARTIAL_FAILURE' | 'REVIEW_ERROR';
  summary: string;
  overall_severity: Severity;
  confidence: number;
  findings: FindingItem[];
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
