import type {
  CodeReviewResponse,
  RetainMemoryRequest,
  RetainMemoryResponse,
  RecallQueryResponse,
  ServiceHealth,
  HistoryItem,
} from '../types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

export async function fetchHealth(): Promise<ServiceHealth> {
  const res = await fetch(`${API_BASE}/api/health`);
  if (!res.ok) {
    throw new Error(`Health check failed with HTTP ${res.status}`);
  }
  return res.json();
}

export async function submitReview(
  code: string,
  language: string,
  contextHint?: string
): Promise<CodeReviewResponse> {
  const res = await fetch(`${API_BASE}/api/review`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code,
      language: language === 'auto' ? undefined : language,
      context_hint: contextHint || undefined,
    }),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `Review request failed with HTTP ${res.status}`);
  }
  return data;
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

  const res = await fetch(`${API_BASE}/api/review/upload`, {
    method: 'POST',
    body: formData,
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `File upload review failed with HTTP ${res.status}`);
  }
  return data;
}

export async function retainMemory(
  req: RetainMemoryRequest
): Promise<RetainMemoryResponse> {
  const res = await fetch(`${API_BASE}/api/memory/retain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `Failed to retain memory with HTTP ${res.status}`);
  }
  return data;
}

export async function testRecall(
  query: string,
  maxTokens?: number
): Promise<RecallQueryResponse> {
  const res = await fetch(`${API_BASE}/api/memory/recall`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query, max_tokens: maxTokens || 2048 }),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.detail || `Recall test failed with HTTP ${res.status}`);
  }
  return data;
}

export async function fetchHistory(): Promise<HistoryItem[]> {
  const res = await fetch(`${API_BASE}/api/history`);
  if (!res.ok) {
    throw new Error(`Failed to load history with HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchReviewById(reviewId: string): Promise<CodeReviewResponse> {
  const res = await fetch(`${API_BASE}/api/history/${reviewId}`);
  if (!res.ok) {
    throw new Error(`Failed to load review with HTTP ${res.status}`);
  }
  return res.json();
}

export async function clearHistory(): Promise<void> {
  const res = await fetch(`${API_BASE}/api/history`, { method: 'DELETE' });
  if (!res.ok) {
    throw new Error(`Failed to clear history with HTTP ${res.status}`);
  }
}
