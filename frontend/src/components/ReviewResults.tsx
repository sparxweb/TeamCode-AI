import React, { useState } from 'react';
import type {
  CodeReviewResponse,
  FindingItem,
  Severity,
} from '../types';
import {
  ShieldAlert,
  Bug,
  Sparkles,
  Layers,
  CheckCircle2,
  Brain,
  BookmarkPlus,
  Copy,
  Check,
  AlertTriangle,
  FileSearch,
  RotateCw,
  Eye,
  EyeOff,
  ArrowRight,
  ShieldCheck,
  CheckSquare,
  XCircle,
} from 'lucide-react';

interface ReviewResultsProps {
  review: CodeReviewResponse | null;
  isLoading: boolean;
  loadingStep: string;
  onTeachRuleFromReview?: (rule: string, context: string, tags: string[]) => void;
  onRunReviewAgain?: () => void;
  onApplyFixedCode?: (code: string) => void;
}

export const ReviewResults: React.FC<ReviewResultsProps> = ({
  review,
  isLoading,
  loadingStep,
  onTeachRuleFromReview,
  onRunReviewAgain,
  onApplyFixedCode,
}) => {
  const [copiedSummary, setCopiedSummary] = useState(false);
  const [copiedFixedCode, setCopiedFixedCode] = useState(false);
  const [showChanges, setShowChanges] = useState(true); // default open to show clear Before/After
  const [appliedCode, setAppliedCode] = useState(false);

  // Loading State
  if (isLoading) {
    return (
      <div className="card review-panel review-empty-panel">
        <div className="review-loading-workflow">
          <div className="loading-orbit-spinner" aria-hidden="true"></div>
          <h3 className="loading-workflow-title">
            {loadingStep || 'Analyzing code...'}
          </h3>
          <p className="loading-workflow-sub">
            Executing deterministic security rules, Hindsight memory recall, and AI verification.
          </p>

          <div className="loading-steps-progression">
            <div className={`workflow-step ${loadingStep.includes('Analyzing') || loadingStep.includes('Processing') ? 'current' : 'done'}`}>
              <span className="step-number">1</span>
              <span>Deterministic Security</span>
            </div>
            <span className="step-arrow">&rarr;</span>
            <div className={`workflow-step ${loadingStep.includes('memory') || loadingStep.includes('Recalling') ? 'current' : loadingStep.includes('Generating') ? 'done' : 'pending'}`}>
              <span className="step-number">2</span>
              <span>Hindsight Team Memory</span>
            </div>
            <span className="step-arrow">&rarr;</span>
            <div className={`workflow-step ${loadingStep.includes('Generating') || loadingStep.includes('standards') ? 'current' : 'pending'}`}>
              <span className="step-number">3</span>
              <span>LLM Review & Fix</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Before Review: Empty State
  if (!review) {
    return (
      <div className="card review-panel review-empty-panel">
        <div className="empty-state-workspace">
          <div className="empty-state-icon-circle">
            <FileSearch size={28} className="empty-state-icon" aria-hidden="true" />
          </div>
          <h3 className="empty-state-headline">
            Submit code to receive an authoritative hybrid AI review.
          </h3>
          <p className="empty-state-description">
            TeamCode AI combines local deterministic security analysis, Hindsight team engineering memory, Groq AI reasoning, and verified auto-fixes.
          </p>

          <div className="learning-loop-card">
            <div className="loop-card-title">
              <Brain size={14} className="text-primary" />
              <span>Hybrid Review Pipeline</span>
            </div>
            <div className="loop-steps-row">
              <span className="loop-badge">1. Deterministic Security</span>
              <span className="loop-arrow">&rarr;</span>
              <span className="loop-badge highlight">2. Hindsight Recall</span>
              <span className="loop-arrow">&rarr;</span>
              <span className="loop-badge">3. Groq Analysis</span>
              <span className="loop-arrow">&rarr;</span>
              <span className="loop-badge highlight">4. Validated Auto-Fix</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'critical':
        return <span className="pill-badge pill-critical">CRITICAL</span>;
      case 'high':
        return <span className="pill-badge pill-high">HIGH</span>;
      case 'medium':
        return <span className="pill-badge pill-medium">MEDIUM</span>;
      case 'low':
        return <span className="pill-badge pill-low">LOW</span>;
      case 'info':
      default:
        return <span className="pill-badge pill-info" style={{ backgroundColor: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)' }}>INFO</span>;
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'security':
        return <ShieldAlert size={15} className="cat-icon cat-security" />;
      case 'bug':
      case 'logic':
        return <Bug size={15} className="cat-icon cat-bug" />;
      case 'syntax':
        return <AlertTriangle size={15} className="cat-icon cat-syntax" style={{ color: '#f59e0b' }} />;
      case 'architecture':
        return <Layers size={15} className="cat-icon cat-arch" />;
      case 'performance':
        return <RotateCw size={15} className="cat-icon cat-perf" style={{ color: '#06b6d4' }} />;
      case 'quality':
      default:
        return <Sparkles size={15} className="cat-icon cat-quality" />;
    }
  };

  const copyReviewSummary = () => {
    const findingsCount = review.findings?.length ?? review.issues?.length ?? 0;
    const text = `TeamCode AI Review\nStatus: ${review.status || 'DONE'}\nSeverity: ${review.overall_severity.toUpperCase()}\nFindings: ${findingsCount}\nSummary: ${review.summary}`;
    navigator.clipboard.writeText(text);
    setCopiedSummary(true);
    setTimeout(() => setCopiedSummary(false), 2000);
  };

  const copyFixedCode = () => {
    if (review.auto_fix?.fixed_code) {
      navigator.clipboard.writeText(review.auto_fix.fixed_code);
      setCopiedFixedCode(true);
      setTimeout(() => setCopiedFixedCode(false), 2000);
    }
  };

  const handleApplyFixedCode = () => {
    if (review.auto_fix?.fixed_code && onApplyFixedCode) {
      onApplyFixedCode(review.auto_fix.fixed_code);
      setAppliedCode(true);
      setTimeout(() => setAppliedCode(false), 2000);
    }
  };

  // Determine review state and findings
  const findingsList: FindingItem[] = review.findings || [];
  const isAIPartialFailure = review.review_state === 'AI_PARTIAL_FAILURE';
  const hasFindings = findingsList.length > 0;
  const isPassed = !isAIPartialFailure && !hasFindings && review.status === 'PASS';

  // Count issues by category
  const securityCount = findingsList.filter((f) => f.category === 'security').length;
  const otherCount = findingsList.length - securityCount;

  // Derive changes summary string
  const formatChanges = (changes: string[] | string | undefined): string => {
    if (!changes) return 'Replaced vulnerable code patterns with secure implementations.';
    if (Array.isArray(changes)) {
      return changes.join('; ');
    }
    return String(changes);
  };

  return (
    <div className="card review-panel review-results-panel">
      {/* Panel Top Header */}
      <div className="panel-header">
        <div className="panel-header-title-group">
          <Sparkles size={16} className="panel-header-icon" aria-hidden="true" />
          <h2 className="panel-title">Review</h2>
        </div>

        <div className="panel-header-actions">
          <button
            type="button"
            className="btn-toolbar-ghost"
            onClick={copyReviewSummary}
            title="Copy review summary"
          >
            {copiedSummary ? (
              <>
                <Check size={14} className="text-success" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy size={14} />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>
      </div>

      <div className="results-scroll-body">
        {/* ============================================================== */}
        {/* CASE 1: PASS — NO ISSUES DETECTED                            */}
        {/* ============================================================== */}
        {isPassed && (
          <section className="review-pass-section" aria-labelledby="pass-heading">
            <div className="pass-banner">
              <div className="pass-icon-circle">
                <CheckCircle2 size={32} className="text-success" />
              </div>
              <h3 id="pass-heading" className="pass-title">
                ✓ Code Review Passed
              </h3>
              <p className="pass-subtitle">
                No issues detected.
              </p>
              <div className="pass-instruction">
                No security, quality, or architecture issues were identified. Code looks good — no fix required.
              </div>
            </div>

            <div className="pass-summary-box">
              <div className="pass-summary-meta">
                <span className="meta-tag">Confidence {Math.round((review.confidence || 0.98) * 100)}%</span>
                <span className="meta-tag">{review.language?.toUpperCase() || 'CODE'}</span>
                <span className="meta-tag">Deterministic Checks Passed</span>
              </div>
              <p className="pass-summary-text">{review.summary}</p>
            </div>
          </section>
        )}

        {/* ============================================================== */}
        {/* CASE 2: AI PARTIAL FAILURE WITH NO DETERMINISTIC FINDINGS     */}
        {/* ============================================================== */}
        {isAIPartialFailure && !hasFindings && (
          <section className="review-partial-failure-section" aria-labelledby="partial-heading">
            <div className="partial-failure-banner">
              <div className="partial-failure-icon-circle">
                <AlertTriangle size={32} className="text-warning" />
              </div>
              <h3 id="partial-heading" className="partial-failure-title">
                AI Review Unavailable
              </h3>
              <p className="partial-failure-subtitle">
                Deterministic analysis completed.
              </p>
              <div className="partial-failure-instruction">
                {review.summary || "Deterministic checks found no obvious static pattern violations, but AI review could not be completed."}
              </div>
            </div>
          </section>
        )}

        {/* ============================================================== */}
        {/* CASE 3: FINDINGS EXIST                                        */}
        {/* ============================================================== */}
        {hasFindings && (
          <>
            {isAIPartialFailure && (
              <div className="system-notice-strip" style={{ marginBottom: '1rem', borderRadius: '8px' }}>
                <div className="notice-inner">
                  <ShieldCheck size={14} className="text-primary" />
                  <span className="notice-text">
                    <strong>Review Completed:</strong> Deterministic security analysis completed successfully and flagged {findingsList.length} issue(s) below. (AI review layer was unavailable)
                  </span>
                </div>
              </div>
            )}

            {/* 1. REVIEW RESULT HEADER */}
            <section className="review-section section-review-result" aria-labelledby="review-result-heading">
              <div className="review-result-header-bar">
                <div>
                  <h3 id="review-result-heading" className="review-result-main-title">
                    REVIEW RESULT
                  </h3>
                  <div className="issue-counts-pill-row">
                    {securityCount > 0 && (
                      <span className="count-pill security-pill">
                        <ShieldAlert size={14} />
                        <span>{securityCount} {securityCount === 1 ? 'Security Issue' : 'Security Issues'}</span>
                      </span>
                    )}
                    {otherCount > 0 && (
                      <span className="count-pill general-pill">
                        <Sparkles size={14} />
                        <span>{otherCount} {otherCount === 1 ? 'Quality Finding' : 'Quality Findings'}</span>
                      </span>
                    )}
                    <span className="confidence-pill">
                      Confidence {Math.round(review.confidence * 100)}%
                    </span>
                  </div>
                </div>
              </div>

              {/* FINDINGS STACK */}
              <div className="findings-container">
                {findingsList.map((item, idx) => (
                  <div key={idx} className="finding-box-card">
                    {/* Title + Meta Row */}
                    <div className="finding-box-top">
                      <div className="finding-name-row">
                        <span className="category-bracket-tag">
                          {getCategoryIcon(item.category)}
                          <span>[{item.category.toUpperCase()}]</span>
                        </span>
                        <h4 className="finding-main-title">{item.title}</h4>
                      </div>
                      <div className="finding-badges-row">
                        {getSeverityBadge(item.severity)}
                        {typeof item.confidence === 'number' && (
                          <span className="confidence-pill" style={{ fontSize: '0.75rem', padding: '0.15rem 0.5rem', borderRadius: '4px', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)' }}>
                            Confidence {Math.round(item.confidence <= 1 ? item.confidence * 100 : item.confidence)}%
                          </span>
                        )}
                        <span className="line-num-badge">
                          <strong>Line:</strong> {item.line_start === item.line_end ? item.line_start : `${item.line_start}-${item.line_end}`}
                        </span>
                        {item.rule_id && (
                          <span className="rule-badge">{item.rule_id}</span>
                        )}
                      </div>
                    </div>

                    {/* Evidence Snippet if detected */}
                    {item.evidence && (
                      <div className="finding-evidence-display">
                        <span className="evidence-header-label">Evidence:</span>
                        <pre className="evidence-code-line"><code>{item.evidence}</code></pre>
                      </div>
                    )}

                    {/* Why Section */}
                    <div className="finding-why-section">
                      <span className="why-label">Why:</span>
                      <p className="why-text">{item.explanation}</p>
                    </div>

                    {/* Impact Section */}
                    {item.impact && (
                      <div className="finding-why-section" style={{ marginTop: '0.4rem' }}>
                        <span className="why-label" style={{ color: '#f59e0b' }}>Impact:</span>
                        <p className="why-text">{item.impact}</p>
                      </div>
                    )}

                    {/* Team Rule Violated (From Hindsight) */}
                    {item.team_memory_used && item.team_memory_used.length > 0 && (
                      <div className="team-rule-violated-box">
                        <div className="violated-header">
                          <Brain size={13} className="text-primary" />
                          <span>Team rule violated:</span>
                        </div>
                        <ul className="violated-rules-list">
                          {item.team_memory_used.map((mem, mIdx) => (
                            <li key={mIdx} className="violated-rule-item">
                              "{mem}"
                            </li>
                          ))}
                        </ul>
                        <div className="memory-source-tag">
                          Memory source: Hindsight / teamcode-ai
                        </div>
                      </div>
                    )}

                    {/* Recommended Fix */}
                    {item.recommended_fix && (
                      <div className="finding-rec-fix-section">
                        <span className="rec-fix-label">Recommended Fix:</span>
                        <pre className="rec-fix-code"><code>{item.recommended_fix}</code></pre>
                      </div>
                    )}

                    {/* Save to Hindsight Button */}
                    {onTeachRuleFromReview && (
                      <div className="finding-action-row">
                        <button
                          type="button"
                          className="btn-teach-rule-ghost"
                          onClick={() => {
                            onTeachRuleFromReview(
                              item.recommended_fix || item.title,
                              `Rule from finding: ${item.title}`,
                              [item.category, review.language]
                            );
                          }}
                          title="Save this standard to Hindsight memory bank"
                        >
                          <BookmarkPlus size={13} />
                          <span>Save as Rule in Team Memory</span>
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </section>

            {/* Automatic fix unavailable notice */}
            {(!review.auto_fix || !review.auto_fix.fixed_code) && (
              <div className="system-notice-strip" style={{ marginTop: '1rem', borderRadius: '8px' }}>
                <div className="notice-inner">
                  <AlertTriangle size={14} className="text-warning" />
                  <span className="notice-text">
                    <strong>Automatic fix unavailable:</strong> Safe automatic remediation could not be generated. Please apply manual remediation according to the recommended fix instructions above.
                  </span>
                </div>
              </div>
            )}

            {/* 2. FIXED CODE SECTION */}
            {review.auto_fix && review.auto_fix.fixed_code && (
              <section className="review-section section-fixed-code-panel" aria-labelledby="fixed-code-heading">
                <div className="section-divider"></div>

                <div className="fixed-code-header-bar">
                  <div className="fixed-code-title-group" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <ShieldCheck size={18} className={review.auto_fix.validation_status === 'VERIFIED' ? "text-primary" : "text-warning"} />
                    <h3 id="fixed-code-heading" className="fixed-code-title">
                      {review.auto_fix.validation_status === 'VERIFIED' ? 'FIXED CODE' : 'SUGGESTED FIX'}
                    </h3>
                    {review.auto_fix.validation_status === 'VERIFIED' ? (
                      <span className="validation-status-badge badge-validated">
                        <CheckCircle2 size={13} />
                        <span>VERIFIED</span>
                      </span>
                    ) : review.auto_fix.validation_status === 'VALIDATION_LIMITED' ? (
                      <span className="validation-status-badge badge-limited">
                        <AlertTriangle size={13} />
                        <span>VALIDATION LIMITED</span>
                      </span>
                    ) : (
                      <span className="validation-status-badge badge-review-needed">
                        <XCircle size={13} />
                        <span>VALIDATION FAILED</span>
                      </span>
                    )}
                  </div>

                  <div className="fixed-code-quick-buttons">
                    <button
                      type="button"
                      className="btn-copy-fix-primary"
                      onClick={copyFixedCode}
                      title="Copy fixed code"
                    >
                      {copiedFixedCode ? (
                        <>
                          <Check size={14} />
                          <span>Copied Fixed Code</span>
                        </>
                      ) : (
                        <>
                          <Copy size={14} />
                          <span>[Copy Fixed Code]</span>
                        </>
                      )}
                    </button>

                    {onApplyFixedCode && (
                      <button
                        type="button"
                        className={`btn-apply-fix-primary ${review.auto_fix.validation_status !== 'VERIFIED' ? 'btn-disabled' : ''}`}
                        onClick={review.auto_fix.validation_status === 'VERIFIED' ? handleApplyFixedCode : undefined}
                        disabled={review.auto_fix.validation_status !== 'VERIFIED'}
                        style={review.auto_fix.validation_status !== 'VERIFIED' ? { opacity: 0.45, cursor: 'not-allowed' } : undefined}
                        title={review.auto_fix.validation_status === 'VERIFIED' ? "Apply fixed code to editor" : "Cannot apply: Fix is unvalidated or validation failed"}
                      >
                        {appliedCode ? (
                          <>
                            <CheckSquare size={14} className="text-success" />
                            <span>Applied to Editor</span>
                          </>
                        ) : (
                          <>
                            <ArrowRight size={14} />
                            <span>[Apply to Editor]</span>
                          </>
                        )}
                      </button>
                    )}

                    <button
                      type="button"
                      className="btn-view-changes-ghost"
                      onClick={() => setShowChanges(!showChanges)}
                      title="Toggle Before / After Diff"
                    >
                      {showChanges ? (
                        <>
                          <EyeOff size={14} />
                          <span>[Hide Changes]</span>
                        </>
                      ) : (
                        <>
                          <Eye size={14} />
                          <span>[View Changes]</span>
                        </>
                      )}
                    </button>

                    {onRunReviewAgain && (
                      <button
                        type="button"
                        className="btn-run-again-ghost"
                        onClick={onRunReviewAgain}
                        title="Run review again"
                      >
                        <RotateCw size={14} />
                        <span>[Run Review Again]</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Fixed Code Block */}
                <div className="fixed-code-display-block">
                  <pre className="fixed-code-pre">
                    <code>{review.auto_fix.fixed_code}</code>
                  </pre>
                </div>

                {/* 3. VALIDATION SECTION */}
                <div className="validation-panel-box">
                  <div className="validation-panel-top">
                    <span className="validation-label">VALIDATION</span>
                    {review.auto_fix.validation_status === 'VERIFIED' ? (
                      <span className="validation-status-badge badge-validated">
                        <CheckCircle2 size={14} />
                        <span>Verified</span>
                      </span>
                    ) : review.auto_fix.validation_status === 'VALIDATION_LIMITED' ? (
                      <span className="validation-status-badge badge-limited">
                        <AlertTriangle size={14} />
                        <span>Validation limited</span>
                      </span>
                    ) : (
                      <span className="validation-status-badge badge-review-needed">
                        <XCircle size={14} />
                        <span>Validation failed</span>
                      </span>
                    )}
                  </div>

                  <div className="validation-checklist">
                    <div className={`checklist-item ${review.auto_fix.vulnerabilities_resolved !== false ? 'valid' : 'invalid'}`}>
                      {review.auto_fix.vulnerabilities_resolved !== false ? (
                        <Check size={14} className="text-success" />
                      ) : (
                        <XCircle size={14} className="text-danger" />
                      )}
                      <span>
                        {review.auto_fix.vulnerabilities_resolved !== false
                          ? 'Targeted issue(s) successfully resolved'
                          : 'Targeted issue pattern(s) still detected'}
                      </span>
                    </div>
                    <div className={`checklist-item ${review.auto_fix.differs_from_original !== false ? 'valid' : 'invalid'}`}>
                      {review.auto_fix.differs_from_original !== false ? (
                        <Check size={14} className="text-success" />
                      ) : (
                        <XCircle size={14} className="text-danger" />
                      )}
                      <span>
                        {review.auto_fix.differs_from_original !== false
                          ? 'Fixed code differs from original'
                          : 'Fixed code is identical to original'}
                      </span>
                    </div>
                    <div className={`checklist-item ${review.auto_fix.is_validated ? 'valid' : 'invalid'}`}>
                      {review.auto_fix.is_validated ? (
                        <Check size={14} className="text-success" />
                      ) : (
                        <XCircle size={14} className="text-danger" />
                      )}
                      <span>
                        {review.auto_fix.validation_status === 'VALIDATION_LIMITED'
                          ? 'Validation limited (pattern check passed, compiler check incomplete)'
                          : review.auto_fix.validation_status === 'VERIFIED'
                          ? 'Deterministic validation passed (syntax & security checks)'
                          : 'Validation failed (syntax, missing import, or rule violation)'}
                      </span>
                    </div>
                  </div>

                  {review.auto_fix.validation_message && (
                    <div className="validation-note">
                      {review.auto_fix.validation_message}
                    </div>
                  )}
                </div>

                {/* 4. BEFORE / AFTER COMPARISON */}
                {showChanges && (
                  <div className="before-after-container">
                    <div className="before-after-columns">
                      <div className="comparison-pane pane-before">
                        <div className="pane-title-bar bar-before">
                          <span>BEFORE (original code)</span>
                        </div>
                        <pre className="pane-code-box">
                          <code>{review.auto_fix.original_code}</code>
                        </pre>
                      </div>

                      <div className="comparison-pane pane-after">
                        <div className="pane-title-bar bar-after">
                          <span>AFTER ({review.auto_fix.validation_status === 'VERIFIED' ? 'fixed code' : 'suggested fix'})</span>
                          {review.auto_fix.validation_status === 'VERIFIED' ? (
                            <span className="validated-tag-mini">✓ VERIFIED</span>
                          ) : review.auto_fix.validation_status === 'VALIDATION_LIMITED' ? (
                            <span className="validated-tag-mini limited">VALIDATION LIMITED</span>
                          ) : (
                            <span className="validated-tag-mini review-needed">VALIDATION FAILED</span>
                          )}
                        </div>
                        <pre className="pane-code-box">
                          <code>{review.auto_fix.fixed_code}</code>
                        </pre>
                      </div>
                    </div>

                    {/* CHANGES BLOCK */}
                    <div className="changes-description-card">
                      <div className="changes-label">CHANGES MADE</div>
                      <p className="changes-text">
                        {formatChanges(review.auto_fix.changes_made)}
                      </p>
                    </div>

                    {/* REMAINING RISKS BLOCK */}
                    {review.auto_fix.remaining_risks && (Array.isArray(review.auto_fix.remaining_risks) ? review.auto_fix.remaining_risks.length > 0 : Boolean(review.auto_fix.remaining_risks)) && (
                      <div className="changes-description-card remaining-risks-card" style={{ marginTop: '0.75rem', borderLeft: '3px solid #f59e0b' }}>
                        <div className="changes-label" style={{ color: '#f59e0b' }}>REMAINING RISKS</div>
                        <ul className="risks-list" style={{ margin: '0.5rem 0 0 1rem', padding: 0, fontSize: '0.85rem' }}>
                          {(Array.isArray(review.auto_fix.remaining_risks)
                            ? review.auto_fix.remaining_risks
                            : [String(review.auto_fix.remaining_risks)]
                          ).map((risk: string, rIdx: number) => (
                            <li key={rIdx} style={{ color: 'var(--text-secondary, #94a3b8)', marginBottom: '0.25rem' }}>
                              {risk}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </section>
            )}
          </>
        )}

        {/* ============================================================== */}
        {/* HINDSIGHT TEAM MEMORY RECALL AUDIT TRAIL                      */}
        {/* ============================================================== */}
        <section className={`review-section section-hindsight-memory status-${review.memory_status}`} aria-labelledby="memory-section-heading">
          <div className="memory-section-header">
            <div className="memory-header-left">
              <Brain size={18} className="memory-main-icon" aria-hidden="true" />
              <div>
                <h3 id="memory-section-heading" className="memory-section-title">
                  {review.memory_status === 'recalled' && (
                    <>
                      {review.memories_used.length} team standard{review.memories_used.length === 1 ? '' : 's'} recalled from Hindsight
                    </>
                  )}
                  {review.memory_status === 'none_found' && (
                    <>No team rules matched this snippet in Hindsight</>
                  )}
                  {review.memory_status === 'unavailable' && (
                    <>Team memory unavailable for this review.</>
                  )}
                </h3>
                <p className="memory-section-subtitle">
                  {review.memory_status === 'unavailable'
                    ? 'Team memory unavailable for this review. Proceeding with general security and quality evaluation.'
                    : review.memory_message}
                </p>
              </div>
            </div>

            <span className="memory-status-tag">
              {review.memory_status === 'recalled' ? 'Hindsight Active' : review.memory_status === 'none_found' ? 'Baseline Mode' : 'Offline'}
            </span>
          </div>

          {/* List Recalled Memories */}
          {review.memory_status === 'recalled' && review.memories_used.length > 0 && (
            <div className="memories-display-list">
              {review.memories_used.map((mem, mIdx) => (
                <div key={mem.id || mIdx} className="memory-item-card">
                  <div className="memory-card-top">
                    <span className="memory-badge-rule">Team Standard #{mIdx + 1}</span>
                    {mem.type && <span className="memory-type-pill">{mem.type}</span>}
                    {mem.relevance_score != null && (
                      <span className="memory-relevance-pill" title="Hindsight recall relevance score">
                        {Math.round(mem.relevance_score * 100)}% Match
                      </span>
                    )}
                    {mem.tags && mem.tags.length > 0 && (
                      <div className="memory-tag-chips">
                        {mem.tags.map((t, tidx) => (
                          <span key={tidx} className="tag-chip">#{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="memory-summary-text">{mem.text}</div>
                  {mem.context && (
                    <div className="memory-context-text">
                      <span className="context-label">Intent:</span> {mem.context}
                    </div>
                  )}
                  <div className="memory-card-footer">
                    {mem.id && (
                      <span className="provenance-chip" title={`Hindsight Memory ID: ${mem.id}`}>
                        ID: {mem.id.length > 12 ? `${mem.id.slice(0, 8)}...` : mem.id}
                      </span>
                    )}
                    <span className="provenance-chip">Bank: teamcode-ai</span>
                    <span className="provenance-chip">Source: Hindsight Cloud</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
};
