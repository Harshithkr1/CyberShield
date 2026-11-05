/**
 * api.js – thin fetch wrapper for the Cyber Shield REST API.
 *
 * All communication with the backend lives here so the rest of the app
 * never touches fetch() directly. This makes it easy to mock in tests
 * or swap the base URL for different environments.
 */

const BASE_URL = '';   // same origin – Spring Boot serves both

/**
 * POST /api/analyze
 *
 * @param {string}  text   The user-submitted text (1–5000 chars)
 * @param {boolean} useMl  Whether to request the ML sub-analysis
 * @returns {Promise<object>} Parsed JSON response body
 * @throws {Error} with a human-readable message on any failure
 */
export async function analyzeText(text, useMl) {
  let response;
  try {
    response = await fetch(`${BASE_URL}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, useMl }),
    });
  } catch (err) {
    throw new Error('Unable to connect to the Cyber Shield server. Please check your network connection and try again.');
  }

  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(`The server returned an unexpected response (status ${response.status}).`);
  }

  if (!response.ok) {
    if (response.status === 400) {
      const rawError = data?.error || '';
      if (rawError.includes('blank')) {
        throw new Error('Please enter some text or paste a link to analyse.');
      }
      if (rawError.includes('5000')) {
        throw new Error('The submitted message is too long (maximum 5,000 characters). Please shorten it and try again.');
      }
      throw new Error(rawError || 'Invalid input provided. Please verify your message.');
    }
    throw new Error(data?.error ?? `Analysis request failed (status ${response.status}). Please try again later.`);
  }

  return data;
}
