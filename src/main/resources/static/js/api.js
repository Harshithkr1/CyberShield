/**
 * api.js – thin fetch wrapper for the Cyber Shield REST API
 * with client-side autonomous fallback for static hosts like GitHub Pages.
 */

import { runClientSideAnalysis } from './client-engine.js';

const BASE_URL = '';   // same origin – Spring Boot serves both

/**
 * POST /api/analyze with automatic in-browser fallback
 *
 * @param {string}  text   The user-submitted text (1–5000 chars)
 * @param {boolean} useMl  Whether to request the ML sub-analysis
 * @returns {Promise<object>} Parsed analysis result
 * @throws {Error} with a human-readable message on validation error
 */
export async function analyzeText(text, useMl) {
  // Input validation
  if (!text || !text.trim()) {
    throw new Error('Please enter some text or paste a link to analyse.');
  }
  if (text.length > 5000) {
    throw new Error('The submitted message is too long (maximum 5,000 characters). Please shorten it and try again.');
  }

  // Attempt backend API first (if Spring Boot server is present)
  try {
    const response = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, useMl }),
    });

    if (response.ok) {
      return await response.json();
    }

    if (response.status === 400) {
      const data = await response.json().catch(() => ({}));
      const rawError = data?.error || '';
      if (rawError.includes('blank')) {
        throw new Error('Please enter some text or paste a link to analyse.');
      }
      if (rawError.includes('5000')) {
        throw new Error('The submitted message is too long (maximum 5,000 characters). Please shorten it and try again.');
      }
      throw new Error(rawError || 'Invalid input provided. Please verify your message.');
    }

    // If 404 (e.g. static host like GitHub Pages where /api/analyze does not exist),
    // proceed to client-side engine below
  } catch (err) {
    // If it was an input validation error thrown above, propagate it immediately
    if (err.message.includes('Please enter') || err.message.includes('too long')) {
      throw err;
    }
    // Network error or 404 -> fallback to in-browser engine below
  }

  // Autonomous In-Browser Engine (runs 100% on GitHub Pages without any backend!)
  try {
    return await runClientSideAnalysis(text, useMl);
  } catch (engineErr) {
    console.error('Client-side analysis error:', engineErr);
    throw new Error('Unable to process the message. Please verify your input and try again.');
  }
}
