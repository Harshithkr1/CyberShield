/**
 * pay-tamper-lab.js – Client for /api/pay/order & /api/pay/verify with 3s timeout
 * and Web Crypto HMAC-SHA256 offline demo fallback.
 */

const API_TIMEOUT_MS = 3000;
const ORDER_TTL_MS = 300_000; // 300 seconds
const TOKEN_PREFIX = 'CS1';
const PUBLIC_DEMO_KEY = 'cybershield-public-offline-demo-key-v1';

// In-memory store for offline Demo mode tamper diffing; resets on reload.
const demoOrders = new Map();
const demoOrdersByRef = new Map();

export function resolvePayApiBase() {
  if (typeof window !== 'undefined' && window.USS && typeof window.USS.apiBaseUrl === 'string') {
    return window.USS.apiBaseUrl.replace(/\/+$/, '');
  }
  if (typeof document !== 'undefined') {
    const meta = document.querySelector('meta[name="api-base-url"]');
    if (meta && meta.content) return meta.content.trim().replace(/\/+$/, '');
  }
  return '';
}

function encodeBase64UrlBytes(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeBase64UrlUtf8(str) {
  return encodeBase64UrlBytes(new TextEncoder().encode(str));
}

function decodeBase64UrlBytes(b64u) {
  let b64 = String(b64u || '').replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeBase64UrlUtf8(b64u) {
  return new TextDecoder().decode(decodeBase64UrlBytes(b64u));
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function buildCanonical(p) {
  return [
    p.pa || '',
    p.pn || '',
    p.am || '',
    p.tr || '',
    p.tn || '',
    String(p.ts ?? '')
  ].join('|');
}

async function demoHmacBytes(canonical) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(PUBLIC_DEMO_KEY),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sigBuf = await crypto.subtle.sign('HMAC', key, enc.encode(canonical));
  return new Uint8Array(sigBuf);
}

function constantTimeEquals(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

async function fetchJsonWithTimeout(url, options) {
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), API_TIMEOUT_MS) : null;
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller ? controller.signal : undefined
    });
    const data = await res.json().catch(() => null);
    return { ok: res.ok, status: res.status, data };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function generateOrderRef() {
  const rand = Math.floor(1000 + Math.random() * 9000);
  return `CS-${Date.now().toString().slice(-6)}-${rand}`;
}

export function extractTokenFromQrResponse(order) {
  if (order?.token) return order.token;
  if (!order?.payload || !order?.signatureHex) return '';
  const payloadB64u = encodeBase64UrlUtf8(JSON.stringify(order.payload));
  const hex = order.signatureHex;
  const sigBytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < sigBytes.length; i++) {
    sigBytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return `${TOKEN_PREFIX}.${payloadB64u}.${encodeBase64UrlBytes(sigBytes)}`;
}

export async function createPayOrder({ receiverVpa, payeeName, amount, note, ref }) {
  const pa = String(receiverVpa || '').trim();
  const tr = String(ref || '').trim();
  const numAmount = Number(amount);
  if (!pa) throw new Error('Receiver UPI ID is required.');
  if (!tr) throw new Error('Order reference is required.');
  if (!Number.isFinite(numAmount) || numAmount <= 0) throw new Error('Amount must be greater than 0.');

  const body = {
    receiverVpa: pa,
    payeeName: String(payeeName || '').trim(),
    amount: Number(numAmount.toFixed(2)),
    note: String(note || '').trim(),
    ref: tr
  };

  let validationError = null;
  try {
    const base = resolvePayApiBase();
    const { ok, status, data } = await fetchJsonWithTimeout(`${base}/api/pay/order`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (ok && data && data.payload && data.signatureHex) {
      const token = extractTokenFromQrResponse(data);
      return { ...data, token, demoMode: false };
    }
    if (status === 400 && data?.error) {
      validationError = new Error(data.error);
    } else {
      console.warn('[PayTamperLab] Server /api/pay/order unavailable, switching to offline demo mode.');
    }
  } catch (err) {
    console.warn('[PayTamperLab] /api/pay/order unreachable/timed out; using Web Crypto demo mode:', err);
  }
  if (validationError) throw validationError;

  return createOfflineDemoOrder(body);
}

export async function createOfflineDemoOrder({ receiverVpa, payeeName, amount, note, ref }) {
  const ts = Date.now();
  const expiresAt = ts + ORDER_TTL_MS;
  const payload = {
    pa: String(receiverVpa || '').trim(),
    pn: String(payeeName || '').trim(),
    am: Number(amount).toFixed(2),
    tr: String(ref || '').trim(),
    tn: String(note || '').trim(),
    ts
  };
  const canonical = buildCanonical(payload);
  const sigBytes = await demoHmacBytes(canonical);
  const signatureHex = toHex(sigBytes);
  const payloadB64u = encodeBase64UrlUtf8(JSON.stringify(payload));
  const sigB64u = encodeBase64UrlBytes(sigBytes);
  const token = `${TOKEN_PREFIX}.${payloadB64u}.${sigB64u}`;

  const storedEntry = { payload, expiresAt };
  demoOrders.set(`${payload.tr}|${payload.ts}`, storedEntry);
  demoOrdersByRef.set(payload.tr, storedEntry);

  return {
    payload,
    canonical,
    signatureHex,
    expiresAt,
    qrPngBase64: '',
    token,
    demoMode: true
  };
}

export function buildTamperedToken(order, tamperMode) {
  const token = order?.token || extractTokenFromQrResponse(order);
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return '';
  if (tamperMode === 'clean' || !tamperMode) return token;

  const cloned = { ...order.payload };
  if (tamperMode === 'swap_vpa') {
    cloned.pa = 'scammer@upi';
  } else if (tamperMode === 'change_amount') {
    cloned.am = '5000.00';
  } else if (tamperMode === 'alter_ts') {
    cloned.ts = Number(cloned.ts) + 60000;
  }

  const newPayloadB64u = encodeBase64UrlUtf8(JSON.stringify(cloned));
  // Preserve original signature so verification proves payload tampering
  return `${parts[0]}.${newPayloadB64u}.${parts[2]}`;
}

export async function verifyPayOrderToken(token, { demoMode = false, nowMs = Date.now(), forceExpired = false } = {}) {
  if (!demoMode) {
    try {
      const base = resolvePayApiBase();
      const { ok, data } = await fetchJsonWithTimeout(`${base}/api/pay/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      });
      if (ok && data && typeof data.valid === 'boolean') {
        const res = forceExpired && data.valid
          ? { ...data, valid: false, reason: 'expired' }
          : data;
        return { ...res, demoMode: false };
      }
    } catch (err) {
      console.warn('[PayTamperLab] /api/pay/verify unreachable/timed out; falling back to offline Web Crypto:', err);
    }
  }

  const offlineRes = await verifyOfflineDemoToken(token, nowMs, forceExpired);
  return { ...offlineRes, demoMode: true };
}

export async function verifyOfflineDemoToken(rawToken, nowMs = Date.now(), forceExpired = false) {
  if (!rawToken || typeof rawToken !== 'string') {
    return { valid: false, reason: 'unsigned or unknown order', changedFields: [], payload: null };
  }
  const parts = rawToken.trim().split('.');
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) {
    return { valid: false, reason: 'unsigned or unknown order', changedFields: [], payload: null };
  }

  let payload;
  let providedSig;
  try {
    payload = JSON.parse(decodeBase64UrlUtf8(parts[1]));
    providedSig = decodeBase64UrlBytes(parts[2]);
  } catch {
    return { valid: false, reason: 'unsigned or unknown order', changedFields: [], payload: null };
  }

  if (!payload || !payload.tr || !payload.ts) {
    return { valid: false, reason: 'unsigned or unknown order', changedFields: [], payload: null };
  }

  const expectedSig = await demoHmacBytes(buildCanonical(payload));
  const sigMatches = constantTimeEquals(providedSig, expectedSig);
  const stored = demoOrders.get(`${payload.tr}|${payload.ts}`) || demoOrdersByRef.get(payload.tr);

  if (!sigMatches) {
    if (!stored) {
      return { valid: false, reason: 'unsigned or unknown order', changedFields: [], payload: null };
    }
    const changedFields = [];
    for (const f of ['pa', 'pn', 'am', 'tr', 'tn', 'ts']) {
      const origVal = String(stored.payload[f] ?? '');
      const recvVal = String(payload[f] ?? '');
      if (origVal !== recvVal) {
        changedFields.push({ field: f, original: origVal, received: recvVal });
      }
    }
    return { valid: false, reason: 'signature mismatch', changedFields, payload };
  }

  const expiresAt = Number(payload.ts) + ORDER_TTL_MS;
  if (forceExpired || nowMs > expiresAt) {
    return { valid: false, reason: 'expired', changedFields: [], payload };
  }

  return { valid: true, reason: 'valid', changedFields: [], payload };
}
