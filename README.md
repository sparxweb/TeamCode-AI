# TeamCode AI — Universal Code Review, Error Detection & Auto-Fix Engine

> **Memory-Augmented AI Code Review & Remediation Engine for Engineering Teams**  
> *Built for the AI Agents Hackathon 2026*

TeamCode AI is a general-purpose, hybrid code review and automated remediation platform. It pairs local deterministic static and AST analysis with **Hindsight long-term agent memory** (Vectorize.io) and **Groq LLM contextual reasoning** to detect defects, explain root causes, cite team coding standards, generate clean fixes, and deterministically validate candidate solutions before presentation.

---

## 🎯 What It Does

TeamCode AI dynamically analyzes submitted source code across 13+ programming languages to detect and remedy issues:

- **Syntax & Compilation Issues:** Unclosed delimiters, malformed statements, syntax errors, and missing brackets.
- **Logic Defects:** Self-comparisons (always true/false), unreachable branches after return/raise statements, infinite loops without break conditions.
- **Security Vulnerabilities:** SQL injection, Cross-Site Scripting (DOM XSS), Server-Side Request Forgery (SSRF), Command Injection (`os.system` / shell usage), Path Traversal, Insecure Deserialization (`pickle`), Weak Cryptography (MD5/SHA-1 for passwords), and Insecure Randomness (`random.random` for security tokens).
- **Code Quality & Architecture:** Empty exception swallowing (`except: pass`), excessive nesting, unhandled failure paths.
- **Performance Inefficiencies:** Resource leaks, redundant computations, and unclosed streams.
- **Automated Fix Generation & AST Verification:** Generates minimal, intent-preserving corrections and independently rescores candidate fixes against syntax trees and security rules before marking them **VERIFIED**.

> **Note on Limitations:** Static and AI-assisted code review cannot guarantee detection of 100% of all possible software defects or runtime edge cases. TeamCode AI provides high-confidence detection and verified remediations while recommending human engineering review for complex domain invariants.

---

## ✨ Key Features

1. **Multi-Language Detection & Review:** Native heuristics and rules for Python, JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, PHP, Kotlin, Swift, Ruby, and SQL.
2. **Deterministic + AI Hybrid Engine:** Fast local deterministic checks combined with Groq LLM reasoning (`openai/gpt-oss-120b`). If external AI is temporarily unavailable, deterministic analysis completes gracefully.
3. **Strict Evidence Enforcement:** Every reported finding points to authentic line numbers and exact code snippets extracted directly from user submissions. Evidence is never fabricated.
4. **Hindsight Long-Term Team Memory:** Remembers team conventions, architectural decisions, and review feedback. Clearly isolates current code evidence from team standards.
5. **Deterministic Fix Validation:** Re-reviews candidate fixes with language AST parsers and deterministic security scanners. Rejects fixes that fail syntax, fail to resolve the defect, alter function signatures, or introduce new regressions.
6. **Side-by-Side Before/After Code Comparison:** Visual diff view with explicit "Changes Made" summaries and remaining risk notes.
7. **Same-Page Studio UX:** Monaco-powered editor, file drag-and-drop upload, language selector, and interactive review results on a single unified canvas.
8. **Persistent Audit History:** Local session history records past reviews and validation states without storing sensitive tokens or credentials.

---

## 🏗️ Architecture

```
User Code / File Upload
          │
          ▼
┌─────────────────────────┐
│   Phase 1: Validation   │  Input size & extension check, text sanitization
└────────────┬────────────┘
          │
          ▼
┌─────────────────────────┐
│ Phase 2: Lang Detection │  Multi-language content & filename heuristics
└────────────┬────────────┘
          │
          ▼
┌─────────────────────────┐
│ Phase 3: Syntax & AST   │  Syntax parsing (ast.parse, bracket balancer)
└────────────┬────────────┘
          │
          ▼
┌─────────────────────────┐
│ Phase 4: Deterministic  │  Deterministic security, logic & quality rules
└────────────┬────────────┘
          │
          ▼
┌─────────────────────────┐
│ Phase 5: Hindsight Bank │  Recall semantic team rules & coding policies
└────────────┬────────────┘
          │
          ▼
┌─────────────────────────┐
│  Phase 6: Groq LLM API  │  Deep contextual reasoning & multi-turn fix
└────────────┬────────────┘
          │
          ▼
┌─────────────────────────┐
│ Phase 7: Deduplication  │  Merge findings, enforce real evidence lines
└────────────┬────────────┘
          │
          ▼
┌─────────────────────────┐
│ Phase 8: Fix Validation │  Independent AST parse, rescan & regression test
└────────────┬────────────┘
          │
          ▼
    Verified Results & Diff (Unified UI)
```

---

## 💻 Technology Stack

- **Backend:** Python 3.12, FastAPI, Uvicorn, Pydantic v2, Groq SDK, Hindsight SDK (`hindsight-client`), Pytest.
- **Frontend:** React 19, TypeScript, Vite 8, Monaco Editor (`@monaco-editor/react`), Lucide React, Modern Vanilla CSS.
- **Testing:** Pytest (88 comprehensive automated unit, integration, and regression test cases), Oxlint, TypeScript compiler check (`tsc -b`).

---

## 🚀 Environment Setup & Installation

### Prerequisites
- **Python 3.10+** (Tested on Python 3.12)
- **Node.js 18+** & **npm**
- **Groq API Key** (from [console.groq.com](https://console.groq.com/keys))
- **Hindsight API Key** (Optional, from [hindsight.vectorize.io](https://hindsight.vectorize.io))

### 1. Clone & Configure Environment
```bash
# Copy example configuration template
cp .env.example .env
```

Edit `.env` with your API credentials:
```ini
GROQ_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b

HINDSIGHT_API_KEY=your_hindsight_api_key_here
HINDSIGHT_BASE_URL=https://api.hindsight.vectorize.io
HINDSIGHT_BANK_ID=teamcode-ai
```

### 2. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Create and activate virtual environment
python -m venv venv

# Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# Linux / macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the complete test suite (88 tests)
pytest tests -v

# Start FastAPI development server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger documentation is available at `http://localhost:8000/docs`.

### 3. Frontend Setup
In a separate terminal window:
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Type check and build production bundle
npm run build

# Start Vite development server
npm run dev
```
Open `http://localhost:5173` (or the port displayed by Vite) in your browser.

---

## 🔒 Security & Safe Execution

- **Zero Host Execution:** Submitted or uploaded code is treated strictly as untrusted text. It is never compiled, evaluated, or executed on the host system.
- **Credential Protection:** All API keys (`GROQ_API_KEY`, `HINDSIGHT_API_KEY`) reside exclusively in server-side environment variables and are never bundled into client-side JavaScript.
- **Upload Hardening:** Uploaded files undergo strict extension whitelisting, size limitation (512 KB), binary null-byte rejection, and path-traversal sanitization (`../../malicious.py` $\rightarrow$ `malicious.py`).
- **History Sanitization:** Local history logs strip API keys, secrets, and authorization tokens prior to JSON serialization.

---

## 🧪 Regression Test Suite

The project includes an automated regression test suite covering Section 30 universal specifications:
```bash
cd backend
.\venv\Scripts\python.exe -m pytest tests/test_universal_engine.py -v
```
Covers:
- **Category A:** Clean code across languages
- **Category B:** Syntax & delimiter errors
- **Category E:** Logic errors (self-comparison, unreachable code, infinite loops)
- **Category F:** Security vulnerabilities (XSS, SSRF, command injection, weak crypto, insecure randomness)
- **Category G:** Multiple mixed findings in a single submission
- **Category I:** Code quality & exception handling
- **Category J:** False positive prevention on safe code patterns
- **Category K:** Multi-language detection (13 languages)
- **Category P:** Fix validation rejection (identical code, broken syntax)
- **Category Q:** Fix regression rejection (new security issue introduced)
- **Category R:** File upload validation & path traversal protection
- **Category S:** History persistence & retrieval
