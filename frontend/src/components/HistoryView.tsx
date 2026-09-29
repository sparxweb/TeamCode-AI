import React, { useEffect, useState } from 'react';
import type { HistoryItem, CodeReviewResponse } from '../types';
import { fetchHistory, fetchReviewById, clearHistory } from '../services/api';
import { History, Trash2, ArrowUpRight, Brain, AlertCircle, RefreshCw, FileCode2 } from 'lucide-react';

interface HistoryViewProps {
  onSelectReview: (review: CodeReviewResponse) => void;
}

export const HistoryView: React.FC<HistoryViewProps> = ({ onSelectReview }) => {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const items = await fetchHistory();
      setHistory(items);
    } catch (err: any) {
      setError(err.message || 'Failed to load review history.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleClear = async () => {
    if (window.confirm('Clear all local prototype review history?')) {
      try {
        await clearHistory();
        setHistory([]);
      } catch (err: any) {
        alert('Failed to clear history: ' + err.message);
      }
    }
  };

  const handleSelect = async (id: string) => {
    try {
      const fullReview = await fetchReviewById(id);
      onSelectReview(fullReview);
    } catch (err: any) {
      alert('Failed to load review details: ' + err.message);
    }
  };

  return (
    <div className="card history-page-card">
      {/* Page Header */}
      <div className="panel-header history-panel-header">
        <div className="panel-header-title-group">
          <History size={18} className="panel-header-icon" />
          <div>
            <h2 className="panel-title">Review History</h2>
            <p className="panel-subtitle">
              Local session logs of executed code reviews. (Distinction: <strong>Review History</strong> tracks previous audit executions, while <strong>Team Memory</strong> stores the agent's persistent long-term knowledge bank).
            </p>
          </div>
        </div>

        <div className="history-header-actions">
          <button
            type="button"
            className="btn-secondary btn-sm"
            onClick={loadHistory}
            disabled={loading}
            aria-label="Refresh history"
          >
            <RefreshCw size={13} className={loading ? 'is-spinning' : ''} />
            <span>Refresh</span>
          </button>
          {history.length > 0 && (
            <button
              type="button"
              className="btn-toolbar-ghost text-danger btn-sm"
              onClick={handleClear}
              aria-label="Clear review history"
            >
              <Trash2 size={13} />
              <span>Clear History</span>
            </button>
          )}
        </div>
      </div>

      <div className="history-body">
        {loading && (
          <div className="history-loading-indicator">
            <span className="btn-spinner" aria-hidden="true"></span>
            <span>Loading review history...</span>
          </div>
        )}

        {error && (
          <div className="alert-message alert-error">
            <AlertCircle size={15} />
            <span>{error}</span>
          </div>
        )}

        {!loading && history.length === 0 && (
          <div className="history-empty-state">
            <div className="empty-icon-circle">
              <History size={24} className="text-muted" />
            </div>
            <h4>No review history yet</h4>
            <p className="text-muted">
              Audit code on the Review tab to view past execution logs and reload prior findings.
            </p>
          </div>
        )}

        {!loading && history.length > 0 && (
          <div className="table-responsive-container">
            <table className="history-data-table" role="table">
              <thead>
                <tr>
                  <th scope="col">Date & Time</th>
                  <th scope="col">File / Snippet</th>
                  <th scope="col">Language</th>
                  <th scope="col">Severity</th>
                  <th scope="col">Issues</th>
                  <th scope="col">Hindsight Memory Used</th>
                  <th scope="col" className="text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {history.map((item) => {
                  const dateStr = new Date(item.timestamp).toLocaleString(undefined, {
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  });

                  return (
                    <tr key={item.id}>
                      <td className="text-secondary nowrap font-mono-sm">
                        {dateStr}
                      </td>
                      <td className="file-name-cell">
                        <div className="file-name-row">
                          <FileCode2 size={14} className="text-muted" />
                          <span className="file-name-text">
                            {item.filename || `Snippet (${item.language})`}
                          </span>
                        </div>
                      </td>
                      <td>
                        <span className="lang-tag-pill">{item.language.toUpperCase()}</span>
                      </td>
                      <td>
                        <span className={`pill-badge pill-${item.overall_severity}`}>
                          {item.overall_severity.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <span className="issues-count-badge">
                          {item.issues_count} {item.issues_count === 1 ? 'issue' : 'issues'}
                        </span>
                      </td>
                      <td>
                        {item.memories_count > 0 ? (
                          <span className="memory-active-pill" title={`${item.memories_count} team memories used in review`}>
                            <Brain size={12} className="text-success" />
                            <span>{item.memories_count} {item.memories_count === 1 ? 'Memory' : 'Memories'} Used</span>
                          </span>
                        ) : (
                          <span className="memory-none-pill">None (Baseline)</span>
                        )}
                      </td>
                      <td className="text-right">
                        <button
                          type="button"
                          className="btn-secondary btn-sm"
                          onClick={() => handleSelect(item.id)}
                          aria-label={`View review from ${dateStr}`}
                        >
                          <span>View</span>
                          <ArrowUpRight size={13} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
