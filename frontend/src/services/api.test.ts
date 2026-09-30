/**
 * Tests for the centralized safeParseJson API response handler.
 * Covers all failure modes that previously caused "Unexpected end of JSON input".
 * Run with: npx vitest run src/services/api.test.ts
 */

import { describe, test, expect, afterEach } from 'vitest';

const originalFetch = globalThis.fetch;

function mockFetch(body: string, status: number, headers: Record<string, string> = {}) {
  const defaultHeaders: Record<string, string> = { 'Content-Type': 'application/json', ...headers };
  globalThis.fetch = async () =>
    new Response(body, {
      status,
      headers: defaultHeaders,
    });
}

function restoreFetch() {
  globalThis.fetch = originalFetch;
}

describe('safeParseJson - API response handler', () => {
  afterEach(restoreFetch);

  test('1. Valid JSON 200 response parses correctly', async () => {
    const payload = {
      status: 'ok',
      groq_configured: true,
      groq_model: 'llama3',
      hindsight_configured: true,
      hindsight_bank_id: 'teamcode-ai',
      hindsight_base_url: 'https://api.hindsight.vectorize.io',
      note: 'ok',
    };
    mockFetch(JSON.stringify(payload), 200);
    const { fetchHealth } = await import('./api');
    const result = await fetchHealth();
    expect(result.status).toBe('ok');
  });

  test('2. Empty response body throws a helpful error', async () => {
    mockFetch('', 500);
    const { fetchHealth } = await import('./api');
    await expect(fetchHealth()).rejects.toThrow(/temporarily unavailable/i);
  });

  test('3. Malformed JSON throws a helpful error without crashing', async () => {
    mockFetch('{invalid json here', 200);
    const { fetchHealth } = await import('./api');
    await expect(fetchHealth()).rejects.toThrow(/invalid response/i);
  });

  test('4. HTML error page (502 from Vite proxy) throws correct message', async () => {
    const htmlBody = '<!DOCTYPE html><html><body>Bad Gateway</body></html>';
    mockFetch(htmlBody, 502, { 'Content-Type': 'text/html' });
    const { fetchHealth } = await import('./api');
    await expect(fetchHealth()).rejects.toThrow(/temporarily unavailable|backend server running/i);
  });

  test('5. HTML 500 error page throws correct message', async () => {
    const htmlBody = '<html><body><h1>Internal Server Error</h1></body></html>';
    mockFetch(htmlBody, 500, { 'Content-Type': 'text/html' });
    const { fetchHealth } = await import('./api');
    await expect(fetchHealth()).rejects.toThrow(/invalid response|unexpected HTML/i);
  });

  test('6. HTTP 400 JSON error surfaces the detail message', async () => {
    mockFetch(JSON.stringify({ detail: 'Code must not be empty' }), 400);
    const { submitReview } = await import('./api');
    await expect(submitReview('', 'python')).rejects.toThrow(/Code must not be empty/i);
  });

  test('7. HTTP 401 JSON triggers authentication error', async () => {
    mockFetch(JSON.stringify({ detail: 'Unauthorized' }), 401);
    const { fetchHealth } = await import('./api');
    await expect(fetchHealth()).rejects.toThrow(/Authentication error/i);
  });

  test('8. HTTP 404 JSON triggers endpoint not found error', async () => {
    mockFetch(JSON.stringify({ detail: 'Not found' }), 404);
    const { fetchHealth } = await import('./api');
    await expect(fetchHealth()).rejects.toThrow(/not found/i);
  });

  test('9. HTTP 422 JSON surfaces validation errors', async () => {
    const payload = { detail: [{ loc: ['body', 'code'], msg: 'field required', type: 'value_error' }] };
    mockFetch(JSON.stringify(payload), 422);
    const { submitReview } = await import('./api');
    await expect(submitReview('', 'python')).rejects.toThrow(/Validation error|field required/i);
  });

  test('10. HTTP 429 triggers rate limit message', async () => {
    mockFetch(JSON.stringify({ detail: 'Too many requests' }), 429);
    const { fetchHealth } = await import('./api');
    await expect(fetchHealth()).rejects.toThrow(/Rate limit/i);
  });

  test('11. HTTP 500 with JSON detail surfaces the detail', async () => {
    mockFetch(JSON.stringify({ detail: 'An unexpected error occurred during review.' }), 500);
    const { submitReview } = await import('./api');
    await expect(submitReview('x = 1', 'python')).rejects.toThrow(/unexpected error|service error/i);
  });

  test('12. HTTP 500 empty body throws service unavailable error', async () => {
    mockFetch('', 500);
    const { submitReview } = await import('./api');
    await expect(submitReview('x = 1', 'python')).rejects.toThrow(/temporarily unavailable/i);
  });

  test('13. Network failure (fetch throws) surfaces connection error', async () => {
    globalThis.fetch = async () => { throw new TypeError('Failed to fetch'); };
    const { submitReview } = await import('./api');
    await expect(submitReview('x = 1', 'python')).rejects.toThrow(/Unable to connect/i);
  });

  test('14. Whitespace-only body is treated as empty', async () => {
    mockFetch('   \n   ', 503);
    const { fetchHealth } = await import('./api');
    await expect(fetchHealth()).rejects.toThrow(/temporarily unavailable|empty response/i);
  });
});
