/**
 * api.js – REST wrapper for POST /api/analyze with a 3-second timeout and
 * unconditional browser-based fallback so Check never stalls or fails.
 */

import { runClientSideAnalysis } from './client-engine.js';

const BASE_URL = '';
const ANALYZE_TIMEOUT_MS = 3000;

function isValidAnalysisResult(data) {
  return Boolean(
    data &&
    typeof data === 'object' &&
    typeof data.score === 'number' &&
    !Number.isNaN(data.score) &&
    typeof data.level === 'string' &&
    Array.isArray(data.signals)
  );
}

/**
 * POST /api/analyze with ~3s AbortController timeout and automatic browser fallback.
 *
 * @param {string}  text   The user-submitted message
 * @param {boolean} useMl  Whether to include the optional ML layer
 * @returns {Promise<object>} Complete AnalysisResult
 */
export async function analyzeText(text, useMl) {
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), ANALYZE_TIMEOUT_MS) : null;

  try {
    const response = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, useMl: Boolean(useMl) }),
      signal: controller ? controller.signal : undefined
    });

    if (!response.ok) {
      console.warn(`[CyberShield] /api/analyze returned HTTP ${response.status}; using browser fallback.`);
    } else {
      const data = await response.json();
      if (isValidAnalysisResult(data)) {
        return data;
      }
      console.warn('[CyberShield] /api/analyze returned malformed payload; using browser fallback.', data);
    }
  } catch (err) {
    console.warn('[CyberShield] /api/analyze unavailable or timed out; using browser fallback:', err);
  } finally {
    if (timer) clearTimeout(timer);
  }

  return runClientSideAnalysis(text, Boolean(useMl));
}
