import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { CodeEditor } from './components/CodeEditor';
import { ReviewResults } from './components/ReviewResults';
import { TeachAgent } from './components/TeachAgent';
import { HistoryView } from './components/HistoryView';
import { fetchHealth, submitReview, uploadAndReviewFile } from './services/api';
import type { CodeReviewResponse, ServiceHealth } from './types';
import { AlertCircle, X, ExternalLink } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'review' | 'teach' | 'history'>('review');
  const [health, setHealth] = useState<ServiceHealth | null>(null);

  // Editor & Review state
  const [filename, setFilename] = useState<string>('user_service.py');
  const [code, setCode] = useState<string>(`import psycopg2

def get_user_profile(db_connection, username_input):
    """
    Look up user account profile by provided username parameter.
    """
    cursor = db_connection.cursor()
    
    # Direct string formatting in SQL query (vulnerable to SQLi)
    query = f"SELECT id, username, email, role, created_at FROM users WHERE username = '{username_input}'"
    
    cursor.execute(query)
    user = cursor.fetchone()
    
    if not user:
        return None
        
    return {
        "id": user[0],
        "username": user[1],
        "email": user[2],
        "role": user[3]
    }
`);
  const [language, setLanguage] = useState<string>('python');
  const [contextHint, setContextHint] = useState<string>('User profile lookup query in PostgreSQL.');
  const [review, setReview] = useState<CodeReviewResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [loadingStep, setLoadingStep] = useState<string>('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Teach Agent prefill rule (from review action)
  const [prefillRule, setPrefillRule] = useState<{
    rule: string;
    context: string;
    tags: string[];
  } | null>(null);

  const loadHealth = async () => {
    try {
      const data = await fetchHealth();
      setHealth(data);
    } catch (err: any) {
      console.warn('Backend not responding to health check:', err.message);
    }
  };

  useEffect(() => {
    loadHealth();
    const interval = setInterval(loadHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const handleReviewCode = async () => {
    if (!code.trim()) return;

    setIsLoading(true);
    setErrorMessage(null);
    setLoadingStep('Analyzing code...');

    // Progress without fake percentages
    const t1 = setTimeout(() => {
      setLoadingStep('Checking team memory...');
    }, 800);

    const t2 = setTimeout(() => {
      setLoadingStep('Generating review...');
    }, 1800);

    try {
      const res = await submitReview(code, language, contextHint);
      clearTimeout(t1);
      clearTimeout(t2);
      setReview(res);
    } catch (err: any) {
      clearTimeout(t1);
      clearTimeout(t2);
      let userFriendlyError = err.message || 'Code review could not be completed.';
      if (userFriendlyError.includes('API_KEY')) {
        userFriendlyError = 'Review could not be completed because the required API keys are not configured in your .env file.';
      } else if (userFriendlyError.includes('hindsight') && userFriendlyError.includes('unavailable')) {
        userFriendlyError = 'Review could not be completed because the Hindsight team memory service is unavailable.';
      } else if (userFriendlyError.includes('Groq') && userFriendlyError.includes('unavailable')) {
        userFriendlyError = 'Review could not be completed because the LLM analysis service is currently unavailable.';
      }
      setErrorMessage(userFriendlyError);
    } finally {
      setIsLoading(false);
      setLoadingStep('');
    }
  };

  const handleFileUpload = async (file: File) => {
    setIsLoading(true);
    setErrorMessage(null);
    setFilename(file.name);
    setLoadingStep('Analyzing code...');

    const t1 = setTimeout(() => {
      setLoadingStep('Checking team memory...');
    }, 800);

    const t2 = setTimeout(() => {
      setLoadingStep('Generating review...');
    }, 1800);

    try {
      const res = await uploadAndReviewFile(file, contextHint);
      clearTimeout(t1);
      clearTimeout(t2);
      setReview(res);
      const text = await file.text();
      setCode(text);
      if (res.language) {
        setLanguage(res.language);
      }
    } catch (err: any) {
      clearTimeout(t1);
      clearTimeout(t2);
      let userFriendlyError = err.message || 'File review could not be completed.';
      if (userFriendlyError.includes('Unsupported file format')) {
        userFriendlyError = 'This file format is not supported. Please upload source code files (.py, .ts, .js, .sql, etc.).';
      }
      setErrorMessage(userFriendlyError);
    } finally {
      setIsLoading(false);
      setLoadingStep('');
    }
  };

  const handleTeachRuleFromReview = (
    rule: string,
    context: string,
    tags: string[]
  ) => {
    setPrefillRule({ rule, context, tags });
    setActiveTab('teach');
  };

  const handleSelectHistoricalReview = (historicalReview: CodeReviewResponse) => {
    setReview(historicalReview);
    if (historicalReview.language) {
      setLanguage(historicalReview.language);
    }
    if (historicalReview.filename) {
      setFilename(historicalReview.filename);
    }
    setActiveTab('review');
  };

  return (
    <div className="app-shell">
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        health={health}
        onRefreshHealth={loadHealth}
      />

      {/* Gentle Config Notice Banner if services not fully set up */}
      {health && (!health.groq_configured || !health.hindsight_configured) && (
        <aside className="system-notice-strip" aria-label="Configuration notice">
          <div className="notice-inner">
            <span className="notice-dot" aria-hidden="true"></span>
            <span className="notice-text">
              <strong>Notice:</strong>{' '}
              {!health.groq_configured && 'Groq API Key is not set in .env. '}
              {!health.hindsight_configured &&
                'Hindsight API Key is not set in .env (reviews will evaluate using general software standards without team memory).'}
            </span>
            <a
              href="https://api.hindsight.vectorize.io"
              target="_blank"
              rel="noreferrer"
              className="notice-link"
            >
              <span>Get Hindsight API Key</span>
              <ExternalLink size={12} />
            </a>
          </div>
        </aside>
      )}

      {/* Global Error Banner */}
      {errorMessage && (
        <div className="global-error-toast" role="alert">
          <div className="toast-content">
            <AlertCircle size={16} className="toast-icon" />
            <span>{errorMessage}</span>
          </div>
          <button
            type="button"
            className="toast-close-btn"
            onClick={() => setErrorMessage(null)}
            aria-label="Dismiss error"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* Main Content Area */}
      <main className="app-main-content">
        {activeTab === 'review' && (
          <div className="workspace-two-column">
            <div className="column-left">
              <CodeEditor
                code={code}
                setCode={setCode}
                language={language}
                setLanguage={setLanguage}
                filename={filename}
                setFilename={setFilename}
                contextHint={contextHint}
                setContextHint={setContextHint}
                onReview={handleReviewCode}
                isLoading={isLoading}
                loadingStep={loadingStep}
                onFileUpload={handleFileUpload}
              />
            </div>
            <div className="column-right">
              <ReviewResults
                review={review}
                isLoading={isLoading}
                loadingStep={loadingStep}
                onTeachRuleFromReview={handleTeachRuleFromReview}
                onRunReviewAgain={() => handleReviewCode()}
                onApplyFixedCode={(fixed) => setCode(fixed)}
              />
            </div>
          </div>
        )}

        {activeTab === 'teach' && (
          <TeachAgent
            onMemoryRetained={() => {
              loadHealth();
            }}
            prefillRule={prefillRule}
          />
        )}

        {activeTab === 'history' && (
          <HistoryView onSelectReview={handleSelectHistoricalReview} />
        )}
      </main>

      {/* Clean Engineering Footer */}
      <footer className="app-minimal-footer">
        <div className="footer-inner">
          <div className="footer-meta">
            <span className="meta-brand">TeamCode AI</span>
            <span className="meta-sep">/</span>
            <span>Hindsight Agent Memory System</span>
            <span className="meta-sep">/</span>
            <span>Groq LLM Engine</span>
          </div>
          <div className="footer-status">
            <span>SaaS Architecture • AI Agents 2026</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
