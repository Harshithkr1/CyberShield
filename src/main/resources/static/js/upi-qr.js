/**
 * upi-qr.js – Client-side NPCI UPI intent parser and heuristic safety rules.
 * Runs 100% in the browser with zero network calls.
 */

const KNOWN_UPI_HANDLES = new Set([
  'demobank', 'csbank', 'okaxis', 'okhdfcbank', 'okicici', 'oksbi',
  'ybl', 'ibl', 'axl', 'paytm', 'ptyes', 'ptaxis', 'ptsbi', 'pthdfc',
  'apl', 'yapl', 'rapl', 'upi', 'sbi', 'hdfcbank', 'icici', 'axisbank',
  'kotak', 'indus', 'federal', 'barodampay', 'cnrb', 'pnb', 'unionbank',
  'aubank', 'idfcfirst', 'jupiteraxis', 'sliceaxis', 'niyoicici', 'naviaxis',
  'ikwik', 'waaxis', 'wahdfcbank', 'waicici', 'wasbi', 'airtel', 'jio', 'postbank'
]);

const BRAND_OR_MERCHANT_WORDS = [
  'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'pnb', 'canara', 'rbi', 'npci', 'trai',
  'paytm', 'phonepe', 'gpay', 'google', 'amazon', 'flipkart', 'fedex', 'dhl',
  'store', 'stores', 'shop', 'mart', 'bazaar', 'traders', 'pharmacy', 'enterprise',
  'desk', 'support', 'helpdesk', 'care', 'customer', 'official', 'bank', 'pvt', 'ltd'
];

const SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'rb.gy',
  'cutt.ly', 'short.io', 'tiny.cc', 'is.gd', 'v.gd', 'buff.ly',
  'rebrand.ly', 'shorturl.at', 'wa.me', 'chat.whatsapp.com'
];

const BAIT_WORDS = ['refund', 'kyc', 'cashback', 'reward', 'verification'];

function safeDecode(val) {
  if (!val) return '';
  const plusAsSpace = String(val).replace(/\+/g, ' ');
  try {
    return decodeURIComponent(plusAsSpace).trim();
  } catch {
    return plusAsSpace.trim();
  }
}

/**
 * Parse an NPCI upi://pay?... intent string (handles URL-encoded params).
 * Returns null if input does not contain a valid upi://pay intent.
 */
export function parseUpiUri(rawInput) {
  const trimmed = String(rawInput || '').trim();
  if (!trimmed) return null;

  const match = trimmed.match(/upi:\/\/pay\?[^\s<>"']+/i);
  const candidate = match ? match[0] : (/^upi:\/\/pay$/i.test(trimmed) ? 'upi://pay?' : null);
  if (!candidate) return null;

  const qIdx = candidate.indexOf('?');
  const query = qIdx >= 0 ? candidate.slice(qIdx + 1) : '';
  const params = {};
  for (const part of query.split('&')) {
    if (!part) continue;
    const eq = part.indexOf('=');
    const k = safeDecode(eq >= 0 ? part.slice(0, eq) : part).toLowerCase();
    const v = eq >= 0 ? safeDecode(part.slice(eq + 1)) : '';
    if (k && params[k] === undefined) params[k] = v;
  }

  return {
    raw: candidate,
    pa: params.pa || '',
    pn: params.pn || '',
    am: params.am || '',
    tn: params.tn || '',
    tr: params.tr || '',
    cu: params.cu || ''
  };
}

function looksPersonalVpa(pa, pn) {
  const atIdx = pa.indexOf('@');
  if (atIdx <= 0) return false;
  const user = pa.slice(0, atIdx).toLowerCase();
  const cleanUser = user.replace(/[._-]/g, '');
  const cleanPn = String(pn || '').toLowerCase().replace(/[^a-z0-9]/g, '');

  // If any meaningful token from the VPA username matches the payee name (e.g. ravi.stores, demo-shop)
  const userTokens = user.split(/[._-]+/).filter((t) => t.length >= 4);
  if (cleanPn.length >= 4 && (
    cleanUser.includes(cleanPn.slice(0, 6)) ||
    cleanPn.includes(cleanUser) ||
    userTokens.some((t) => cleanPn.includes(t))
  )) {
    return false;
  }

  // Phone number, digits inside handle, or username completely unrelated to payee name
  if (/^(?:\+?91)?[6-9]\d{9}$/.test(cleanUser)) return true;
  if (/\d{2,}/.test(cleanUser)) return true;
  return true;
}

/**
 * Evaluate parsed UPI fields against offline safety rules.
 */
export function analyzeUpiFields(parsed, expectedAmountInput = '') {
  if (!parsed) return null;

  const flags = [];
  const pa = parsed.pa || '';
  const pn = parsed.pn || '';
  const am = parsed.am || '';
  const tn = parsed.tn || '';

  const pnLower = pn.toLowerCase();
  const paLower = pa.toLowerCase();
  const tnLower = tn.toLowerCase();

  // 1. Merchant/brand claim vs personal-looking VPA
  const claimsBrandOrBusiness = BRAND_OR_MERCHANT_WORDS.some((w) =>
    new RegExp(`\\b${w}\\b`, 'i').test(pnLower)
  );
  if (claimsBrandOrBusiness && pa && looksPersonalVpa(pa, pn)) {
    flags.push({
      id: 'merchant_personal_vpa',
      title: `Payee name "${pn}" sounds like a business or bank, but UPI ID "${pa}" looks personal or unrelated.`,
      why: 'Why this matters: Scammers often set a convincing display name (pn) over a personal or random VPA (pa).'
    });
  }

  // 2. Amount missing
  if (!am) {
    flags.push({
      id: 'missing_amount',
      title: 'Amount is missing (am is blank) — the receiver can fill in any amount.',
      why: 'Why this matters: Open-amount QRs let an attacker demand a much higher sum than you agreed to pay.'
    });
  }

  // 3. Expected amount mismatch
  const expectedStr = String(expectedAmountInput || '').trim();
  if (expectedStr && am) {
    const expNum = Number(expectedStr);
    const amNum = Number(am);
    if (Number.isFinite(expNum) && expNum > 0 && Number.isFinite(amNum) && Math.abs(amNum - expNum) > 0.009) {
      flags.push({
        id: 'amount_mismatch',
        title: `QR amount (${parsed.cu || 'INR'} ${amNum}) differs from your expected amount (${parsed.cu || 'INR'} ${expNum}).`,
        why: 'Why this matters: Pre-filled QR amounts lock what your app debits unless you catch the difference before entering your PIN.'
      });
    }
  }

  // 4. Odd/unknown handle, raw IP, http:// link, or shortener in tn or pa
  const atParts = paLower.split('@');
  const handle = atParts.length === 2 ? atParts[1] : '';
  const oddPa = !pa || atParts.length !== 2 || !handle || !KNOWN_UPI_HANDLES.has(handle);
  const combinedCheck = `${paLower} ${tnLower}`;
  const hasIp = /\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(combinedCheck);
  const hasHttp = /http:\/\//i.test(combinedCheck);
  const shortenerHit = SHORTENERS.find((s) => combinedCheck.includes(s));

  if (hasIp || hasHttp || shortenerHit || (pa && oddPa)) {
    const reasons = [];
    if (pa && oddPa) reasons.push(`unfamiliar UPI handle "@${handle || 'missing'}"`);
    if (hasIp) reasons.push('raw IP address');
    if (hasHttp) reasons.push('plain http:// link');
    if (shortenerHit) reasons.push(`URL shortener (${shortenerHit})`);
    flags.push({
      id: 'suspicious_handle_or_link',
      title: `Suspicious handle or link detected (${reasons.join(', ')}).`,
      why: 'Why this matters: Genuine UPI shop notes rarely embed shortened links, unencrypted URLs, or unusual handles.'
    });
  }

  // 5. Bait words in pn or tn
  const baitHits = BAIT_WORDS.filter((w) =>
    new RegExp(`\\b${w}\\b`, 'i').test(`${pnLower} ${tnLower}`)
  );
  if (baitHits.length > 0) {
    flags.push({
      id: 'bait_words',
      title: `Bait wording found in name or note: "${baitHits.join('", "')}".`,
      why: 'Why this matters: Payment QRs always debit your account — "refund", "cashback", or "KYC" notes are used to trick you into paying.'
    });
  }

  return {
    parsed,
    flags,
    cleanMessage: flags.length === 0
      ? 'Nothing suspicious in the QR itself. Still match the name on your payment app screen before paying.'
      : '',
    guidance: [
      'Compare the Payee Name (pn) above with the name shown on YOUR payment app confirmation screen.',
      'If the name, amount, or purpose mismatches in any way, cancel the payment immediately.'
    ]
  };
}

const DEFAULT_DEMO_REGISTRY = {
  'demo-shop@csbank': 'Cyber Shield Demo Store',
  'qwe978xyz@ybl': 'Ravi Kumar',
  'ravi.stores@demobank': 'Ravi Stores',
  'ravi@demobank': 'Ravi Stores',
  'metro.bazaar@okaxis': 'Metro Bazaar',
  'ananya.tailors@demobank': 'Ananya Tailoring Works',
  'city.pharma@demobank': 'City Care Pharmacy',
  'sharma.hardware@demobank': 'Sharma Hardware & Tools',
  'lakshmi.fruits@demobank': 'Lakshmi Fresh Fruits',
  'freshkart.demo@csbank': 'FreshKart Demo Mart'
};

let cachedDemoRegistry = null;

export async function preloadDemoRegistry() {
  if (cachedDemoRegistry) return cachedDemoRegistry;
  try {
    const url = new URL('data/demo-registry.json', window.location.href).href;
    const res = await fetch(url);
    if (res.ok) {
      const json = await res.json();
      if (json && json.entries && typeof json.entries === 'object') {
        cachedDemoRegistry = { ...DEFAULT_DEMO_REGISTRY, ...json.entries };
        return cachedDemoRegistry;
      }
    }
  } catch {
    // Offline/static fallback to embedded demo registry
  }
  cachedDemoRegistry = { ...DEFAULT_DEMO_REGISTRY };
  return cachedDemoRegistry;
}

function normalizeDisplayName(name) {
  return String(name || '').trim().replace(/\s+/g, ' ').toLowerCase();
}

/**
 * Synchronous Demo Bank (fictional) registry lookup against preloaded/embedded entries.
 * Never makes a network call during decode and never fails.
 */
export function lookupDemoRegistry(parsed) {
  const entries = cachedDemoRegistry || DEFAULT_DEMO_REGISTRY;
  const pa = String(parsed?.pa || '').trim().toLowerCase();
  const qrPn = String(parsed?.pn || '').trim();
  const registeredName = pa && Object.prototype.hasOwnProperty.call(entries, pa) ? entries[pa] : null;
  const missingPn = !qrPn;

  let status = 'UNKNOWN';
  if (registeredName) {
    if (!missingPn && normalizeDisplayName(registeredName) === normalizeDisplayName(qrPn)) {
      status = 'MATCH';
    } else if (!missingPn) {
      status = 'MISMATCH';
    }
  }

  return {
    bankLabel: 'Demo Bank (fictional)',
    pa,
    qrPn,
    registeredName,
    missingPn,
    status
  };
}
