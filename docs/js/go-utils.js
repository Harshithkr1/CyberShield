/**
 * go-utils.js – Client-side URL validation and #u= base64url fragment helpers.
 * Zero storage, zero logging, zero network requests.
 */

export const MAX_GO_URL_LENGTH = 2000;

export function encodeBase64UrlUtf8(str) {
  const bytes = new TextEncoder().encode(String(str ?? ''));
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function decodeBase64UrlUtf8(b64u) {
  let b64 = String(b64u || '').trim().replace(/-/g, '+').replace(/_/g, '/');
  if (!b64 || /[^A-Za-z0-9+/=]/.test(b64)) {
    throw new Error('Invalid base64url payload');
  }
  while (b64.length % 4 !== 0) b64 += '=';
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

/**
 * Validates that a candidate destination is an http: or https: URL within 2000 chars.
 */
export function validateDestinationUrl(raw) {
  if (typeof raw !== 'string') {
    return { valid: false, url: '', parsed: null };
  }
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > MAX_GO_URL_LENGTH || /[\u0000-\u001f\u007f\s]/.test(trimmed)) {
    return { valid: false, url: '', parsed: null };
  }

  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, url: '', parsed: null };
  }

  const proto = parsed.protocol.toLowerCase();
  if (proto !== 'http:' && proto !== 'https:') {
    return { valid: false, url: '', parsed: null };
  }
  if (!parsed.hostname) {
    return { valid: false, url: '', parsed: null };
  }

  return { valid: true, url: parsed.href, parsed };
}

export function extractFragmentParam(hash, key = 'u') {
  const rawHash = String(hash || '');
  if (!rawHash || rawHash === '#') return '';
  const body = rawHash.startsWith('#') ? rawHash.slice(1) : rawHash;
  const params = new URLSearchParams(body);
  return params.get(key) || '';
}

export function buildProtectedLink(rawUrl, baseHref = (typeof window !== 'undefined' ? window.location.href : 'http://localhost/')) {
  const check = validateDestinationUrl(rawUrl);
  if (!check.valid) return '';
  const target = new URL('go.html', baseHref);
  target.search = '';
  target.hash = `u=${encodeBase64UrlUtf8(check.url)}`;
  return target.href;
}

/**
 * Splits a validated URL into prefix, real host (never userinfo), and remainder.
 */
export function splitUrlHostParts(parsed) {
  const auth = parsed.username
    ? `${parsed.username}${parsed.password ? `:${parsed.password}` : ''}@`
    : '';
  return {
    beforeHost: `${parsed.protocol}//${auth}`,
    host: parsed.host,
    afterHost: `${parsed.pathname}${parsed.search}${parsed.hash}`
  };
}

