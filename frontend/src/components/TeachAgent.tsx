import React, { useState } from 'react';
import {
  Brain,
  Save,
  CheckCircle2,
  AlertTriangle,
  Search,
  Sparkles,
  BookOpen,
  Info,
} from 'lucide-react';
import { retainMemory, testRecall } from '../services/api';
import type { MemoryItem, RetainMemoryResponse } from '../types';

interface TeachAgentProps {
  onMemoryRetained?: () => void;
  prefillRule?: { rule: string; context: string; tags: string[] } | null;
}

const MEMORY_TYPES = [
  'Team rule',
  'Architecture decision',
  'Previous review',
  'Exception',
  'Custom knowledge',
];

export const TeachAgent: React.FC<TeachAgentProps> = ({
  onMemoryRetained,
  prefillRule,
}) => {
  const [memoryType, setMemoryType] = useState<string>(
    prefillRule?.tags?.includes('security')
      ? 'Team rule'
      : 'Team rule'
  );
  const [content, setContent] = useState<string>(
    prefillRule?.rule || ''
  );
  const [context, setContext] = useState<string>(
    prefillRule?.context || ''
  );
  const [tagsInput, setTagsInput] = useState<string>(
    prefillRule?.tags?.join(', ') || 'database, sql, security'
  );

  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [retainSuccess, setRetainSuccess] = useState<RetainMemoryResponse | null>(null);
  const [retainError, setRetainError] = useState<string | null>(null);

  // Recall Test state
  const [testQuery, setTestQuery] = useState<string>('database queries SQL parameterized');
  const [isTestingRecall, setIsTestingRecall] = useState<boolean>(false);
  const [recallTestResult, setRecallTestResult] = useState<{
    status: string;
    count: number;
    memories: MemoryItem[];
    message: string;
  } | null>(null);
  const [recallTestError, setRecallTestError] = useState<string | null>(null);

  // Hackathon Demo preset
  const handleLoadDemoRule = () => {
    setMemoryType('Team rule');
    setContent('All database queries in our team must use parameterized queries.');
    setContext('Prevent SQL injection vulnerabilities across all services and ensure PCI-DSS compliance.');
    setTagsInput('database, sql, postgresql, security');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!content.trim()) return;

    setIsSubmitting(true);
    setRetainSuccess(null);
    setRetainError(null);

    const tags = tagsInput
      .split(',')
      .map((t) => t.trim().toLowerCase())
      .filter(Boolean);

    try {
      const res = await retainMemory({
        memory_type: memoryType,
        content: content.trim(),
        context: context.trim() || undefined,
        tags,
      });

      setRetainSuccess(res);
      if (onMemoryRetained) {
        onMemoryRetained();
      }
    } catch (err: any) {
      setRetainError(err.message || 'Failed to store team knowledge in memory.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTestRecall = async () => {
    if (!testQuery.trim()) return;
    setIsTestingRecall(true);
    setRecallTestError(null);
    setRecallTestResult(null);

    try {
      const res = await testRecall(testQuery);
      setRecallTestResult(res);
    } catch (err: any) {
      setRecallTestError(err.message || 'Recall test failed.');
    } finally {
      setIsTestingRecall(false);
    }
  };

  return (
    <div className="team-memory-page">
      {/* Page Header */}
      <div className="card memory-page-hero">
        <div className="memory-hero-content">
          <div className="memory-hero-icon-box">
            <Brain size={22} className="text-primary" />
          </div>
          <div>
            <h2 className="memory-hero-title">Team Memory</h2>
            <p className="memory-hero-subtitle">
              Teach TeamCode AI how your engineering team works.
            </p>
          </div>
        </div>

        {/* Demo Fast-Track Action */}
        <div className="hero-demo-callout">
          <span className="demo-callout-label">
            <strong>Demo Scenario:</strong> Load the parameterized queries rule for the learning loop test.
          </span>
          <button
            type="button"
            className="btn-demo-preset"
            onClick={handleLoadDemoRule}
            aria-label="Load demo rule"
          >
            <Sparkles size={13} />
            <span>Load Demo Rule</span>
          </button>
        </div>
      </div>

      <div className="memory-page-grid">
        {/* Memory Input Form */}
        <div className="card memory-form-card">
          <div className="panel-header">
            <div className="panel-header-title-group">
              <BookOpen size={16} className="panel-header-icon" />
              <h3 className="panel-title">Add Knowledge</h3>
            </div>
          </div>

          <div className="form-card-body">
            {retainSuccess && (
              <div className="alert-message alert-success" role="status">
                <CheckCircle2 size={16} className="alert-icon" />
                <div className="alert-content">
                  <span className="alert-title">Team knowledge stored in Hindsight memory.</span>
                  <p className="alert-sub">
                    Stored knowledge can influence future code reviews when relevant.
                  </p>
                </div>
              </div>
            )}

            {retainError && (
              <div className="alert-message alert-error" role="alert">
                <AlertTriangle size={16} className="alert-icon" />
                <div className="alert-content">
                  <span className="alert-title">Failed to store knowledge.</span>
                  <p className="alert-sub">{retainError}</p>
                </div>
              </div>
            )}

            <form onSubmit={handleSubmit} className="memory-entry-form">
              <div className="form-row">
                <label htmlFor="memory-type-select" className="field-label">
                  Memory Type
                </label>
                <select
                  id="memory-type-select"
                  className="select-control"
                  value={memoryType}
                  onChange={(e) => setMemoryType(e.target.value)}
                >
                  {MEMORY_TYPES.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>

              <div className="form-row">
                <label htmlFor="knowledge-description" className="field-label">
                  Describe the knowledge you want the agent to remember <span className="req-star">*</span>
                </label>
                <textarea
                  id="knowledge-description"
                  className="textarea-control"
                  rows={4}
                  placeholder="e.g., All database queries in our team must use parameterized queries."
                  value={content}
                  onChange={(e) => setContent(e.target.value)}
                  required
                />
              </div>

              <div className="form-row">
                <label htmlFor="knowledge-context" className="field-label">
                  Context / Rationale (Optional)
                </label>
                <textarea
                  id="knowledge-context"
                  className="textarea-control"
                  rows={2}
                  placeholder="Why this rule exists, architectural justification, or compliance standard..."
                  value={context}
                  onChange={(e) => setContext(e.target.value)}
                />
              </div>

              <div className="form-row">
                <label htmlFor="knowledge-tags" className="field-label">
                  Tags / Domains (Comma separated)
                </label>
                <input
                  id="knowledge-tags"
                  type="text"
                  className="input-control"
                  placeholder="database, security, sql, python"
                  value={tagsInput}
                  onChange={(e) => setTagsInput(e.target.value)}
                />
              </div>

              <div className="form-actions-bar">
                <p className="form-disclaimer">
                  <Info size={13} className="text-muted" />
                  <span>Stored knowledge can influence future code reviews when relevant.</span>
                </p>

                <button
                  type="submit"
                  className="btn-primary"
                  disabled={isSubmitting || !content.trim()}
                >
                  {isSubmitting ? (
                    <>
                      <span className="btn-spinner" aria-hidden="true"></span>
                      <span>Saving to Hindsight...</span>
                    </>
                  ) : (
                    <>
                      <Save size={14} />
                      <span>Save to Hindsight</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>

        {/* Live Memory Recall Explorer */}
        <div className="card memory-explorer-card">
          <div className="panel-header">
            <div className="panel-header-title-group">
              <Search size={16} className="panel-header-icon" />
              <h3 className="panel-title">Verify Retrieval (Recall)</h3>
            </div>
          </div>

          <div className="explorer-body">
            <p className="explorer-intro">
              Simulate how the code review agent queries Hindsight memory for relevant standards before generating a review.
            </p>

            <div className="explorer-query-row">
              <input
                type="text"
                className="input-control"
                value={testQuery}
                onChange={(e) => setTestQuery(e.target.value)}
                placeholder="Query team memory..."
                aria-label="Query memory bank"
              />
              <button
                type="button"
                className="btn-secondary"
                onClick={handleTestRecall}
                disabled={isTestingRecall || !testQuery.trim()}
              >
                {isTestingRecall ? 'Searching...' : 'Recall'}
              </button>
            </div>

            {recallTestError && (
              <div className="alert-message alert-error">
                <AlertTriangle size={15} />
                <span>{recallTestError}</span>
              </div>
            )}

            {recallTestResult && (
              <div className="recall-output-container">
                <div className="output-status-bar">
                  <span className="status-badge">
                    {recallTestResult.status === 'recalled' ? 'Memory Found' : recallTestResult.status === 'none_found' ? 'No Memories' : 'Unavailable'}
                  </span>
                  <span className="count-label">{recallTestResult.count} matches</span>
                </div>
                <p className="output-message">{recallTestResult.message}</p>

                {recallTestResult.memories.length > 0 ? (
                  <div className="recalled-cards-stack">
                    {recallTestResult.memories.map((m, idx) => (
                      <div key={m.id || idx} className="recalled-snippet-card">
                        <div className="snippet-top">
                          <span className="match-pill">Match #{idx + 1}</span>
                          {m.type && <span className="type-pill">{m.type}</span>}
                        </div>
                        <div className="snippet-text">{m.text}</div>
                        {m.context && (
                          <div className="snippet-context">
                            <strong>Rationale:</strong> {m.context}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-recall-state">
                    No memories returned for this query. Save a rule using the form on the left!
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
