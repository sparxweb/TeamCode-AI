import type {
  CodeReviewResponse,
  RetainMemoryRequest,
  RetainMemoryResponse,
  RecallQueryResponse,
  ServiceHealth,
  HistoryItem,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL || '';

// ─────────────────────────────────────────────────────────────────────────────
// Centralized safe JSON response handler
// Prevents "Unexpected end of JSON input" and surfaces clean error messages
// for every possible failure mode (empty body, HTML, non-JSON, network, etc.)
// ─────────────────────────────────────────────────────────────────────────────
async function safeParseJson<T>(res: Response, context: string): Promise<T> {
  let bodyText: string;
  try {
    bodyText = await res.text();
  } catch {
    throw new Error(`Unable to read response from ${context}. Check your network connection.`);
  }

  // Empty body
  if (!bodyText || bodyText.trim() === '') {
    if (res.status >= 500) {
      throw new Error(`Review service temporarily unavailable (HTTP ${res.status}). Please try again.`);
    }
    if (res.status === 401) throw new Error('Authentication error. Check API configuration.');
    if (res.status === 403) throw new Error('Access denied.');
    if (res.status === 404) throw new Error(`Endpoint not found: ${context}.`);
    if (res.status === 429) throw new Error('Rate limit reached. Please wait a moment and try again.');
    throw new Error(`Received an empty response from the review service (HTTP ${res.status}).`);
  }

  // Detect HTML error pages (Nginx, uvicorn crash pages, Vite proxy errors)
  const trimmed = bodyText.trim();
  if (trimmed.startsWith('<!') || trimmed.startsWith('<html') || trimmed.startsWith('<HTML')) {
    if (res.status === 502 || res.status === 503 || res.status === 504) {
      throw new Error('Review service is temporarily unavailable. Is the backend server running on port 8000?');
    }
    throw new Error(`Received an unexpected HTML response from the review service (HTTP ${res.status}).`);
  }

  // Try parsing JSON
  let data: T;
  try {
    data = JSON.parse(bodyText) as T;
  } catch {
    // Truncate to avoid leaking sensitive server output
    const snippet = trimmed.slice(0, 120);
    throw new Error(`Received an invalid response from the review service. Preview: ${snippet}`);
  }

  // Handle known FastAPI/HTTP error envelopes
  if (!res.ok) {
    const errData = data as Record<string, unknown>;
    // FastAPI validation errors return { detail: [...] }
    if (Array.isArray(errData.detail)) {
      const msgs = (errData.detail as Array<{ msg?: string }>)
        .map((d) => d.msg || JSON.stringify(d))
        .join('; ');
      throw new Error(`Validation error: ${msgs}`);
    }
    const detail = typeof errData.detail === 'string' ? errData.detail : null;
    const message = typeof errData.message === 'string' ? errData.message : null;
    const fallback = detail || message || `Request failed with HTTP ${res.status}`;

    if (res.status === 401) throw new Error('Authentication error. Check API configuration.');
    if (res.status === 403) throw new Error('Access denied.');
    if (res.status === 404) throw new Error(`Endpoint not found (HTTP 404): ${context}`);
    if (res.status === 422) throw new Error(`Validation error: ${fallback}`);
    if (res.status === 429) throw new Error('Rate limit reached. Please wait a moment and try again.');
    if (res.status >= 500) throw new Error(`Review service error: ${fallback}`);
    throw new Error(fallback);
  }

  return data;
}

// ─────────────────────────────────────────────────────────────────────────────
// API functions
// ─────────────────────────────────────────────────────────────────────────────

export async function fetchHealth(): Promise<ServiceHealth> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/health`);
  } catch {
    throw new Error('Unable to connect to the review service. Is the backend running?');
  }
  return safeParseJson<ServiceHealth>(res, 'health check');
}

export async function submitReview(
  code: string,
  language: string,
  contextHint?: string,
  options?: {
    parentReviewId?: string;
    originalCode?: string;
    originalFindings?: unknown[];
    isFixedCodeReview?: boolean;
  }
): Promise<CodeReviewResponse> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/review`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code,
        language: language === 'auto' ? undefined : language,
        context_hint: contextHint || undefined,
        parent_review_id: options?.parentReviewId,
        original_code: options?.originalCode,
        original_findings: options?.originalFindings,
        is_fixed_code_review: options?.isFixedCodeReview ?? false,
      }),
    });
  } catch {
    throw new Error('Unable to connect to the review service. Is the backend server running on port 8000?');
  }
  return safeParseJson<CodeReviewResponse>(res, 'code review');
}

export async function uploadAndReviewFile(
  file: File,
  contextHint?: string
): Promise<CodeReviewResponse> {
  const formData = new FormData();
  formData.append('file', file);
  if (contextHint) {
    formData.append('context_hint', contextHint);
  }

  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/review/upload`, {
      method: 'POST',
      body: formData,
    });
  } catch {
    throw new Error('Unable to connect to the review service. Is the backend server running?');
  }
  return safeParseJson<CodeReviewResponse>(res, 'file review');
}

export async function retainMemory(
  req: RetainMemoryRequest
): Promise<RetainMemoryResponse> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/memory/retain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
  } catch {
    throw new Error('Unable to connect to memory service. Is the backend running?');
  }
  return safeParseJson<RetainMemoryResponse>(res, 'memory retain');
}

export async function testRecall(
  query: string,
  maxTokens?: number
): Promise<RecallQueryResponse> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/memory/recall`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, max_tokens: maxTokens || 2048 }),
    });
  } catch {
    throw new Error('Unable to connect to memory service. Is the backend running?');
  }
  return safeParseJson<RecallQueryResponse>(res, 'memory recall');
}

export async function fetchHistory(): Promise<HistoryItem[]> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/history`);
  } catch {
    throw new Error('Unable to connect to the review service. Is the backend running?');
  }
  return safeParseJson<HistoryItem[]>(res, 'fetch history');
}

export async function fetchReviewById(reviewId: string): Promise<CodeReviewResponse> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/history/${reviewId}`);
  } catch {
    throw new Error('Unable to connect to the review service. Is the backend running?');
  }
  return safeParseJson<CodeReviewResponse>(res, 'fetch review by id');
}

export async function clearHistory(): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}/api/history`, { method: 'DELETE' });
  } catch {
    throw new Error('Unable to connect to the review service. Is the backend running?');
  }
  if (!res.ok) {
    await safeParseJson<unknown>(res, 'clear history');
  }
}
