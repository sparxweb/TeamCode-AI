import React, { useRef, useState, useMemo } from 'react';
import { Upload, FileCode, Play, Trash2, FileText } from 'lucide-react';
import Editor from '@monaco-editor/react';

interface CodeEditorProps {
  code: string;
  setCode: (code: string) => void;
  language: string;
  setLanguage: (lang: string) => void;
  filename: string;
  setFilename: (fn: string) => void;
  contextHint: string;
  setContextHint: (hint: string) => void;
  onReview: () => void;
  isLoading: boolean;
  loadingStep: string;
  onFileUpload: (file: File) => void;
}

const DEMO_PRESETS = [
  {
    name: '🎯 Demo: Vulnerable Database Query (SQLi)',
    lang: 'python',
    filename: 'user_service.py',
    code: `import psycopg2

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
`,
    hint: 'User profile lookup query in PostgreSQL.',
  },
  {
    name: '🐛 Demo: Logic Defect & Unreachable Code (Python)',
    lang: 'python',
    filename: 'discount_calculator.py',
    code: `def calculate_discount(price, user_status):
    if price < 0:
        return 0
        print("Invalid price entered")  # Unreachable code

    # Self-comparison logic bug
    if user_status == user_status:
        discount = price * 0.15
        
    return price - discount
`,
    hint: 'Business logic for order discounts.',
  },
  {
    name: '🌐 Demo: DOM XSS & HTML Injection (JavaScript)',
    lang: 'javascript',
    filename: 'profile_renderer.js',
    code: `function renderUserProfile(container, userData) {
    // Unsafe DOM manipulation vulnerable to Cross-Site Scripting (XSS)
    container.innerHTML = "<h1>Welcome, " + userData.name + "</h1><p>" + userData.bio + "</p>";
}
`,
    hint: 'Frontend user profile rendering component.',
  },
  {
    name: '🔑 Demo: Hardcoded Secret & Weak Hashing',
    lang: 'python',
    filename: 'auth_handler.py',
    code: `import hashlib

JWT_SECRET_KEY = "mock_dev_jwt_secret_token_key_12345"
API_TOKEN = "mock_api_token_scanner_val_987654"

def hash_user_password(password_plain):
    # Insecure MD5 hashing without salt or cost factor
    hasher = hashlib.md5()
    hasher.update(password_plain.encode('utf-8'))
    return hasher.hexdigest()
`,
    hint: 'Authentication service password hashing.',
  },
  {
    name: '✅ Demo: Clean Idiomatic Code (No Issues)',
    lang: 'python',
    filename: 'math_utils.py',
    code: `from typing import List

def average_positive_numbers(numbers: List[float]) -> float:
    """Calculates the average of positive numbers in the list."""
    positives = [n for n in numbers if n > 0]
    if not positives:
        return 0.0
    return sum(positives) / len(positives)
`,
    hint: 'Mathematical utility functions.',
  },
];

export const CodeEditor: React.FC<CodeEditorProps> = ({
  code,
  setCode,
  language,
  setLanguage,
  filename,
  setFilename,
  contextHint,
  setContextHint,
  onReview,
  isLoading,
  loadingStep,
  onFileUpload,
}) => {
  const [inputMode, setInputMode] = useState<'paste' | 'upload'>('paste');
  const [isDragging, setIsDragging] = useState(false);
  const [monacoFailed, setMonacoFailed] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const lineCount = useMemo(() => {
    return code ? code.split('\n').length : 0;
  }, [code]);

  const charCount = useMemo(() => {
    return code ? code.length : 0;
  }, [code]);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const f = e.dataTransfer.files[0];
      setFilename(f.name);
      onFileUpload(f);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const f = e.target.files[0];
      setFilename(f.name);
      onFileUpload(f);
    }
  };

  const handleSelectPreset = (presetIndex: number) => {
    const preset = DEMO_PRESETS[presetIndex];
    if (preset) {
      setCode(preset.code);
      setLanguage(preset.lang);
      setFilename(preset.filename);
      setContextHint(preset.hint);
    }
  };

  return (
    <div className="card editor-panel">
      {/* Top Header of Code Input */}
      <div className="panel-header">
        <div className="panel-header-title-group">
          <FileCode size={16} className="panel-header-icon" aria-hidden="true" />
          <h2 className="panel-title">Code Input</h2>
        </div>

        {/* Input Mode Selector */}
        <div className="input-mode-tabs" role="tablist" aria-label="Input Mode">
          <button
            type="button"
            className={`mode-tab ${inputMode === 'paste' ? 'active' : ''}`}
            onClick={() => setInputMode('paste')}
            role="tab"
            aria-selected={inputMode === 'paste'}
          >
            <FileText size={13} aria-hidden="true" />
            <span>Editor</span>
          </button>
          <button
            type="button"
            className={`mode-tab ${inputMode === 'upload' ? 'active' : ''}`}
            onClick={() => setInputMode('upload')}
            role="tab"
            aria-selected={inputMode === 'upload'}
          >
            <Upload size={13} aria-hidden="true" />
            <span>Upload File</span>
          </button>
        </div>
      </div>

      {/* Editor Controls Bar */}
      <div className="editor-toolbar">
        <div className="toolbar-left">
          {/* Filename Input / Display */}
          <div className="file-tab-badge">
            <span className="file-tab-dot"></span>
            <input
              type="text"
              className="filename-input"
              value={filename}
              onChange={(e) => setFilename(e.target.value)}
              placeholder="filename.py"
              title="Click to rename file"
              aria-label="Source file name"
            />
          </div>

          {/* Language Selector */}
          <div className="control-group">
            <label htmlFor="language-select" className="sr-only">Language</label>
            <select
              id="language-select"
              className="select-control"
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              aria-label="Programming Language"
            >
              <option value="auto">Auto-detect</option>
              <option value="python">Python</option>
              <option value="typescript">TypeScript</option>
              <option value="javascript">JavaScript</option>
              <option value="java">Java</option>
              <option value="c">C</option>
              <option value="cpp">C++</option>
              <option value="csharp">C#</option>
              <option value="go">Go</option>
              <option value="rust">Rust</option>
              <option value="php">PHP</option>
              <option value="kotlin">Kotlin</option>
              <option value="swift">Swift</option>
              <option value="ruby">Ruby</option>
              <option value="sql">SQL</option>
              <option value="bash">Bash / Shell</option>
            </select>
          </div>
        </div>

        <div className="toolbar-right">
          {/* Preset Selector */}
          <select
            className="select-control preset-dropdown"
            defaultValue=""
            onChange={(e) => {
              if (e.target.value !== "") {
                handleSelectPreset(Number(e.target.value));
              }
            }}
            aria-label="Load demo preset"
          >
            <option value="" disabled>Load Demo Preset...</option>
            {DEMO_PRESETS.map((p, idx) => (
              <option key={idx} value={idx}>
                {p.name}
              </option>
            ))}
          </select>

          {/* Clear Button */}
          {code && (
            <button
              type="button"
              className="btn-toolbar-ghost"
              onClick={() => setCode('')}
              title="Clear editor code"
              aria-label="Clear code"
            >
              <Trash2 size={14} />
              <span>Clear</span>
            </button>
          )}
        </div>
      </div>

      {/* Editor Body */}
      <div className="editor-surface">
        {inputMode === 'paste' ? (
          <div className="monaco-wrapper">
            {!monacoFailed ? (
              <Editor
                height="450px"
                language={language === 'auto' ? 'python' : language}
                value={code}
                onChange={(value) => setCode(value || '')}
                theme="light"
                onMount={() => setMonacoFailed(false)}
                loading={<div className="editor-loading-state">Initializing Code Editor...</div>}
                options={{
                  minimap: { enabled: false },
                  fontSize: 13,
                  lineHeight: 20,
                  fontFamily: "'JetBrains Mono', 'Fira Code', Menlo, Monaco, Consolas, monospace",
                  fontLigatures: true,
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  wordWrap: 'on',
                  tabSize: 2,
                  automaticLayout: true,
                  renderLineHighlight: 'all',
                  overviewRulerLanes: 0,
                  hideCursorInOverviewRuler: true,
                  scrollbar: {
                    verticalScrollbarSize: 8,
                    horizontalScrollbarSize: 8,
                  },
                }}
              />
            ) : (
              <textarea
                className="fallback-textarea"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="// Paste or write source code here..."
                rows={20}
                spellCheck={false}
              />
            )}
          </div>
        ) : (
          <div
            className={`file-upload-dropzone ${isDragging ? 'is-dragging' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            role="button"
            tabIndex={0}
            aria-label="Upload code file"
          >
            <input
              type="file"
              ref={fileInputRef}
              style={{ display: 'none' }}
              onChange={handleFileChange}
              accept=".py,.js,.ts,.tsx,.jsx,.java,.go,.rs,.cpp,.c,.cs,.php,.rb,.sql,.sh"
            />
            <div className="dropzone-inner">
              <div className="dropzone-icon-circle">
                <Upload size={22} className="dropzone-svg" />
              </div>
              <p className="dropzone-main-text">Drag & drop source code file here</p>
              <p className="dropzone-sub-text">or click to browse from your computer</p>
              <div className="dropzone-supported-tags">
                <span>.py</span>
                <span>.ts</span>
                <span>.js</span>
                <span>.sql</span>
                <span>.go</span>
                <span>.java</span>
                <span>.rs</span>
                <span className="limit-pill">Max 512KB</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Editor Status Bar */}
      <div className="editor-status-bar">
        <div className="status-bar-left">
          <span>{lineCount} lines</span>
          <span className="status-separator">•</span>
          <span>{charCount} chars</span>
          <span className="status-separator">•</span>
          <span className="status-lang">{language.toUpperCase()}</span>
        </div>
        <div className="status-bar-right">
          <span>UTF-8</span>
          <span className="status-separator">•</span>
          <span>Spaces: 2</span>
        </div>
      </div>

      {/* Optional Context & Action Footer */}
      <div className="editor-action-footer">
        <div className="context-field-wrapper">
          <input
            type="text"
            className="context-field"
            placeholder="Optional review context (e.g., 'PostgreSQL query module' or PR goal)..."
            value={contextHint}
            onChange={(e) => setContextHint(e.target.value)}
            aria-label="Optional developer context"
          />
        </div>

        <button
          type="button"
          className="btn-primary review-submit-btn"
          onClick={onReview}
          disabled={isLoading || !code.trim()}
          aria-label="Review Code"
        >
          {isLoading ? (
            <>
              <span className="btn-spinner" aria-hidden="true"></span>
              <span>{loadingStep || 'Reviewing...'}</span>
            </>
          ) : (
            <>
              <Play size={14} fill="currentColor" aria-hidden="true" />
              <span>Review Code</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
};
