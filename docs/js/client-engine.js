/**
 * client-engine.js - In-browser rule-based & optional ML scam analysis engine.
 *
 * Runs 100% autonomously in the browser as a fallback whenever /api/analyze
 * times out, returns an error/malformed payload, or is unreachable.
 * Replicates Cyber Shield's scoring bands and AnalysisResult contract.
 */

const DEFAULT_RULES = {
  scoringThresholds: { low: 0, medium: 25, high: 50, critical: 75 },
  mlScoring: { ruleWeight: 0.6, mlWeight: 0.4, noSignalCap: 49 },
  brands: [
    { name: 'SBI', officialDomains: ['sbi.co.in', 'onlinesbi.sbi', 'sbiglobal.in'] },
    { name: 'HDFC', officialDomains: ['hdfcbank.com', 'hdfc.com'] },
    { name: 'ICICI', officialDomains: ['icicibank.com', 'iciciprulife.com'] },
    { name: 'Paytm', officialDomains: ['paytm.com', 'paytmbank.com'] },
    { name: 'PhonePe', officialDomains: ['phonepe.com'] },
    { name: 'Google Pay', officialDomains: ['pay.google.com', 'gpay.app'] },
    { name: 'Amazon', officialDomains: ['amazon.in', 'amazon.com', 'pay.amazon.in'] },
    { name: 'Flipkart', officialDomains: ['flipkart.com', 'fkpay.in'] },
    { name: 'India Post', officialDomains: ['indiapost.gov.in', 'epostoffice.gov.in'] },
    { name: 'FedEx', officialDomains: ['fedex.com', 'fedex.in'] },
    { name: 'DHL', officialDomains: ['dhl.com', 'dhl.in'] },
    { name: 'IRCTC', officialDomains: ['irctc.co.in', 'irctcconnect.com'] },
    { name: 'Income Tax', officialDomains: ['incometax.gov.in', 'efiling.incometax.gov.in'] },
    { name: 'UIDAI', officialDomains: ['uidai.gov.in', 'myaadhaar.uidai.gov.in'] },
    { name: 'Axis Bank', officialDomains: ['axisbank.com'] },
    { name: 'Kotak', officialDomains: ['kotak.com', 'kotakbank.com'] },
    { name: 'PNB', officialDomains: ['pnbindia.in', 'netpnb.com'] },
    { name: 'BOI', officialDomains: ['bankofindia.co.in'] },
    { name: 'Canara', officialDomains: ['canarabank.com'] },
    { name: 'Union Bank', officialDomains: ['unionbankofindia.com'] },
    { name: 'NSDL', officialDomains: ['nsdl.co.in'] },
    { name: 'RBI', officialDomains: ['rbi.org.in'] },
    { name: 'TRAI', officialDomains: ['trai.gov.in'] },
    { name: 'MCA', officialDomains: ['mca.gov.in'] }
  ],
  urlShorteners: [
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl', 'rb.gy',
    'cutt.ly', 'short.io', 'tiny.cc', 'is.gd', 'v.gd', 'buff.ly',
    'rebrand.ly', 'shorturl.at', 'wa.me', 'chat.whatsapp.com'
  ],
  suspiciousTlds: [
    '.xyz', '.top', '.club', '.online', '.site', '.store', '.tech',
    '.info', '.biz', '.ws', '.cc', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.pw', '.icu', '.buzz', '.link', '.click', '.download', '.zip',
    '.mov', '.ltd', '.vip', '.win'
  ],
  urlKeywords: [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'secure',
    'update', 'confirm', 'account', 'banking', 'netbanking', 'kyc',
    'blocked', 'suspended', 'wallet', 'reward', 'prize', 'winner',
    'claim', 'refund', 'cashback', 'otp', 'aadhar', 'aadhaar', 'pan',
    'password', 'pay'
  ],
  digitalArrestPhrases: [
    'digital arrest', 'you are under digital arrest', 'narcotics control bureau',
    'ncb officer', 'central bureau of investigation', 'enforcement directorate',
    'ed officer', 'cybercrime police', 'cybercrime department', 'cyber cell',
    'money laundering', 'drug trafficking', 'drug parcel', 'illegal parcel',
    'arrest warrant issued', 'arrest warrant', 'non-bailable warrant',
    'stay on video call', 'stay on the call', 'keep the video call on',
    'do not tell anyone', 'do not disconnect', 'rbi verification',
    'safe account', 'transfer to safe account', 'move money to safe account',
    'pay to avoid arrest', 'pay fine', 'settle the case', 'police complaint',
    'legal action will be taken', 'cbi', 'police', 'arrest',
    'डिजिटल अरेस्ट', 'वीडियो कॉल पर बने रहें', 'किसी को न बताएं',
    'सुरक्षित खाते में पैसे ट्रांसफर', 'सुरक्षित खाते', 'गिरफ्तार', 'गिरफ्तारी', 'पुलिस', 'कानूनी कार्रवाई',
    'ಡಿಜಿಟಲ್ ಅರೆಸ್ಟ್', 'ಪೊಲೀಸ್', 'ಬಂಧನ', 'ಕಾನೂನು ಕ್ರಮ'
  ],
  maliciousAppPhrases: [
    'download this apk', 'install this apk', 'download the apk',
    'download anydesk', 'install anydesk', 'download teamviewer',
    'install teamviewer', 'remote access', 'share your screen',
    'screen share', 'install quick support', 'quicksupport',
    'enable unknown sources', 'install unknown sources', 'install from unknown sources',
    'accessibility permission', 'enable accessibility', 'sms permission',
    'sideload', 'electricity bill app', 'rto challan app', 'pm kisan app'
  ],
  kycThreatPhrases: [
    'kyc verification required', 'complete your kyc', 'kyc expired', 'kyc has expired',
    'your kyc is incomplete', 'kyc update required', 'kyc update',
    'your account will be blocked', 'will be blocked', 'account will be blocked today',
    'account has been blocked', 'account has been suspended', 'your card will be blocked',
    'electricity connection will be disconnected', 'will be disconnected',
    'pay customs duty', 'customs clearance', 'customs fee', 'package is on hold',
    'खाता बंद', 'ब्लॉक', 'केवाईसी', 'ಕನೆಕ್ಷನ್ ಕಟ್', 'ಖಾತೆ ಬ್ಲಾಕ್', 'ಬ್ಲಾಕ್ ಆಗುತ್ತದೆ', 'ಮುಕ್ತಾಯಗೊಳ್ಳುತ್ತದೆ'
  ],
  urgencyPhrases: [
    'immediately', 'immediate action required', 'act now', 'respond immediately',
    'within 24 hours', 'within 2 hours', 'within 1 hour', 'last chance',
    'final warning', 'urgent notice', 'urgent action', 'expires today',
    'ತಕ್ಷಣ', 'ಇಂದೇ', 'ಅಂತಿಮ ಎಚ್ಚರಿಕೆ', 'तुरंत', 'अभी', 'आज ही', '24 घंटे'
  ],
  otpSolicitationPhrases: [
    'share your otp', 'enter your otp', 'provide your otp', 'send your otp',
    'give your otp', 'one time password', 'confirm with otp', 'verify with otp',
    'ओटीपी', 'ಓಟಿಪಿ'
  ],
  sensitiveDataPhrases: [
    'share your cvv', 'enter your cvv', 'cvv number', 'cvv',
    'enter your pin', 'share your pin', 'enter upi pin', 'share your upi pin',
    'upi pin', 'atm pin', 'net banking password', 'share your password',
    'aadhaar number', 'aadhar number', 'pan number', 'pan card',
    'पिन', 'ಪಿನ್'
  ],
  prizeBaitPhrases: [
    'congratulations you have won', 'you are a lucky winner', 'claim your prize',
    'claim your reward', 'lottery winner', 'cash reward', 'tax refund', 'claim your refund'
  ],
  phishingPhrases: [
    'verify your account', 'click the link to verify', 'update your details',
    'confirm your bank details', 'unusual activity detected', 'suspicious login detected'
  ],
  pressureCtaPhrases: [
    'click now', 'call immediately', 'reply immediately', 'do not delay',
    'tap here immediately', 'click to avoid', 'ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳಿ'
  ]
};

let cachedRules = null;
let cachedTextModel = null;
let cachedUrlModel = null;

const SMS_SYNONYMS = {
  your: '(?:your|ur)', ur: '(?:your|ur)',
  you: '(?:you|u)', u: '(?:you|u)',
  are: '(?:are|r)', r: '(?:are|r)',
  please: '(?:please|plz|pls)', plz: '(?:please|plz|pls)', pls: '(?:please|plz|pls)',
  thanks: '(?:thanks|thx)', thx: '(?:thanks|thx)',
  okay: '(?:okay|ok)', ok: '(?:okay|ok)',
  aadhaar: '(?:aadhaar|aadhar)', aadhar: '(?:aadhaar|aadhar)'
};

const AUTHORITY_TERMS = [
  'cbi', 'police', 'customs', 'ncb', 'ed', 'trai', 'rbi',
  'cyber cell', 'court', 'supreme court', 'high court',
  'narcotics', 'enforcement directorate', 'सीबीआई', 'पुलिस', 'ಪೊಲೀಸ್'
];

const PAYMENT_TERMS = [
  'safe account', 'rbi verification', 'transfer to safe', 'move your money',
  'move money', 'transfer funds', 'pay to avoid', 'pay fine', 'pay customs',
  'customs fee', 'clearance fee', 'deposit', 'settle the case',
  'सुरक्षित खाते', 'पैसे ट्रांसफर'
];

const SECRECY_TERMS = [
  'do not tell anyone', 'do not disconnect', 'stay on video call',
  'stay on the call', 'keep the video call on', 'confidential',
  'skype', 'google meet', 'whatsapp video',
  'किसी को न बताएं', 'वीडियो कॉल पर बने रहें'
];

const MULTI_PART_TLDS = new Set(['co', 'gov', 'org', 'net', 'ac', 'res', 'gen']);

function resolveAssetUrl(rel) {
  try {
    return new URL(rel, window.location.href).href;
  } catch {
    return rel;
  }
}

async function fetchJsonSafe(primaryRel, fallbackRel) {
  for (const rel of [primaryRel, fallbackRel].filter(Boolean)) {
    try {
      const res = await fetch(resolveAssetUrl(rel));
      if (res.ok) return await res.json();
    } catch {
      // try next path or inline fallback
    }
  }
  return null;
}

async function loadRules() {
  if (cachedRules) return cachedRules;
  const loaded = await fetchJsonSafe('data/rules.json', 'rules.json');
  if (!loaded || typeof loaded !== 'object') {
    cachedRules = DEFAULT_RULES;
    return cachedRules;
  }
  const merged = { ...DEFAULT_RULES, ...loaded };
  for (const key of [
    'urlShorteners', 'suspiciousTlds', 'urlKeywords',
    'digitalArrestPhrases', 'maliciousAppPhrases', 'kycThreatPhrases',
    'urgencyPhrases', 'otpSolicitationPhrases', 'sensitiveDataPhrases',
    'prizeBaitPhrases', 'phishingPhrases', 'pressureCtaPhrases'
  ]) {
    merged[key] = Array.from(new Set([...(loaded[key] || []), ...(DEFAULT_RULES[key] || [])]));
  }
  cachedRules = merged;
  return cachedRules;
}

async function loadMlModels() {
  if (cachedTextModel && cachedUrlModel) return true;
  try {
    const [textModel, urlModel] = await Promise.all([
      cachedTextModel || fetchJsonSafe('data/ml/text_model.json', 'ml/text_model.json'),
      cachedUrlModel || fetchJsonSafe('data/ml/url_model.json', 'ml/url_model.json')
    ]);
    cachedTextModel = textModel;
    cachedUrlModel = urlModel;
    return Boolean(cachedTextModel && cachedUrlModel);
  } catch (err) {
    console.warn('[CyberShield] ML model load failed; falling back to rules-only:', err);
    return false;
  }
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isAsciiText(s) {
  return /^[\x00-\x7F]+$/.test(s);
}

function findPhraseMatch(text, lowerText, phrase) {
  const trimmed = phrase.trim();
  if (!trimmed) return null;

  if (!isAsciiText(trimmed)) {
    const idx = lowerText.indexOf(trimmed.toLowerCase());
    if (idx >= 0) {
      return { text: text.slice(idx, idx + trimmed.length), index: idx };
    }
    return null;
  }

  const tokens = trimmed.split(/\s+/);
  const parts = tokens.map((tok) => SMS_SYNONYMS[tok.toLowerCase()] || escapeRegex(tok));
  const rx = new RegExp('\\b' + parts.join('[\\s\\-_/.]+') + '\\b', 'i');
  const m = rx.exec(text);
  return m ? { text: m[0], index: m.index } : null;
}

function scanPhrases(text, lowerText, phrases, signalId, category, points, explanationTpl) {
  if (!text || !Array.isArray(phrases)) return [];
  const signals = [];
  for (const phrase of phrases) {
    if (typeof phrase !== 'string' || !phrase.trim()) continue;
    const hit = findPhraseMatch(text, lowerText, phrase);
    if (hit) {
      signals.push({
        id: signalId,
        category,
        points,
        explanation: `${explanationTpl} Detected: "${hit.text}".`,
        matchedText: hit.text,
        start: hit.index,
        end: hit.index + hit.text.length
      });
    }
  }
  return signals;
}

function scanRegexRule(text, regex, signalId, category, points, explanation) {
  const flags = regex.flags.includes('g') ? regex.flags : `${regex.flags}g`;
  const rx = new RegExp(regex.source, flags);
  const hits = [];
  let m;
  while ((m = rx.exec(text)) !== null) {
    if (!m[0]) break;
    hits.push({
      id: signalId,
      category,
      points,
      explanation,
      matchedText: m[0],
      start: m.index,
      end: m.index + m[0].length
    });
  }
  return hits;
}

function extractUrls(text) {
  const matches = [];
  const rx = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|in|org|net|xyz|top|club|online|site|store|tech|info|biz|ws|cc|tk|ml|ga|cf|gq|pw|icu|buzz|link|click|download|zip|mov|ltd|vip|win|apk|live|pro)\b[^\s<>"'{}|\\^`]*/gi;
  let m;
  while ((m = rx.exec(text)) !== null) {
    const clean = m[0].replace(/[.,;:!?)]+$/, '');
    matches.push({ url: clean, start: m.index, end: m.index + clean.length });
  }
  return matches;
}

function extractHost(urlStr) {
  try {
    const u = /^https?:\/\//i.test(urlStr) ? urlStr : `http://${urlStr}`;
    return new URL(u).hostname.toLowerCase();
  } catch {
    return urlStr.replace(/^https?:\/\//i, '').split(/[\/?#]/)[0].split(':')[0].toLowerCase();
  }
}

function isOfficialHost(host, officialDomains) {
  if (!host || !Array.isArray(officialDomains)) return false;
  return officialDomains.some((dom) => {
    const d = dom.toLowerCase();
    return host === d || host.endsWith(`.${d}`);
  });
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, () => new Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) dp[i][0] = i;
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[a.length][b.length];
}

function calculateEntropy(str) {
  if (!str) return 0;
  const counts = {};
  for (const c of str) counts[c] = (counts[c] || 0) + 1;
  let ent = 0;
  for (const k in counts) {
    const p = counts[k] / str.length;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function extractUrlFeatures(urlStr, suspiciousTlds) {
  const raw = urlStr.trim();
  const lower = raw.toLowerCase();
  let dotCount = 0, hyphenCount = 0, digitCount = 0;
  for (const c of raw) {
    if (c === '.') dotCount++;
    else if (c === '-') hyphenCount++;
    else if (c >= '0' && c <= '9') digitCount++;
  }
  const host = extractHost(raw);
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) ? 1.0 : 0.0;
  const tld = host.includes('.') ? host.substring(host.lastIndexOf('.') + 1) : '';
  const suspiciousTld = suspiciousTlds.has(tld) ? 1.0 : 0.0;
  const usesHttps = lower.startsWith('https://') ? 1.0 : 0.0;
  const parts = host.split('.').filter(Boolean);
  const subdomainCount = parts.length >= 3 && MULTI_PART_TLDS.has(parts[parts.length - 2])
    ? Math.max(0, parts.length - 3)
    : Math.max(0, parts.length - 2);

  return [raw.length, dotCount, hyphenCount, digitCount, calculateEntropy(raw), isIp, suspiciousTld, usesHttps, subdomainCount];
}

function sigmoid(z) {
  return 1.0 / (1.0 + Math.exp(-z));
}

function classifyTextClient(text, model) {
  const tokens = text.toLowerCase().match(/\b\w+\b/g) || [];
  if (!tokens.length) return { probability: sigmoid(model.intercept), topWords: [] };

  const ngrams = [...tokens];
  for (let i = 0; i < tokens.length - 1; i++) ngrams.push(`${tokens[i]} ${tokens[i + 1]}`);

  const termCounts = {};
  for (const tok of ngrams) {
    if (Object.prototype.hasOwnProperty.call(model.vocabulary, tok)) {
      const idx = model.vocabulary[tok];
      termCounts[idx] = (termCounts[idx] || 0) + 1;
    }
  }
  const entries = Object.entries(termCounts);
  if (!entries.length) return { probability: sigmoid(model.intercept), topWords: [] };

  let sumSq = 0;
  const tfidfMap = {};
  for (const [idxStr, count] of entries) {
    const idx = parseInt(idxStr, 10);
    const val = count * model.idf[idx];
    tfidfMap[idx] = val;
    sumSq += val * val;
  }
  const l2Norm = Math.sqrt(sumSq);
  const idxToTerm = new Map(Object.entries(model.vocabulary).map(([t, i]) => [i, t]));

  let dot = 0;
  const contributions = [];
  for (const [idxStr, val] of Object.entries(tfidfMap)) {
    const idx = parseInt(idxStr, 10);
    const xNorm = l2Norm > 0 ? val / l2Norm : 0;
    const coef = model.coefficients[idx];
    dot += xNorm * coef;
    if (coef > 0 && idxToTerm.has(idx)) {
      contributions.push({ term: idxToTerm.get(idx), impact: coef * val });
    }
  }

  contributions.sort((a, b) => b.impact - a.impact);
  return {
    probability: sigmoid(dot + model.intercept),
    topWords: contributions.slice(0, 5).map((c) => c.term)
  };
}

function classifyUrlClient(urlStr, model, suspiciousTlds) {
  const feats = extractUrlFeatures(urlStr, suspiciousTlds);
  let dot = 0;
  for (let i = 0; i < feats.length; i++) {
    const std = model.stds[i] === 0 ? 1.0 : model.stds[i];
    dot += ((feats[i] - model.means[i]) / std) * model.coefficients[i];
  }
  return sigmoid(dot + model.intercept);
}

function filterOverlapping(signals) {
  if (!signals || !signals.length) return [];
  const spanSignals = signals.filter((s) => s.start >= 0 && s.end > s.start);
  const otherSignals = signals.filter((s) => !(s.start >= 0 && s.end > s.start));

  spanSignals.sort((a, b) => (b.points !== a.points ? b.points - a.points : (b.end - b.start) - (a.end - a.start)));

  const accepted = [];
  for (const candidate of spanSignals) {
    let overlap = false;
    for (const acc of accepted) {
      if (candidate.category === 'URL' && acc.category === 'URL') continue;
      if (Math.max(candidate.start, acc.start) < Math.min(candidate.end, acc.end)) {
        overlap = true;
        break;
      }
    }
    if (!overlap) accepted.push(candidate);
  }

  const combined = [...accepted, ...otherSignals];
  combined.sort((a, b) => a.start - b.start);
  return combined;
}

/**
 * Execute rule-based + optional ML scam evaluation in the browser.
 * Never throws; always returns a complete AnalysisResult object.
 */
export async function runClientSideAnalysis(text, useMl = true) {
  const input = String(text || '');
  const lower = input.toLowerCase();
  const rules = await loadRules();
  const signals = [];

  signals.push(
    ...scanPhrases(input, lower, rules.digitalArrestPhrases, 'digitalArrest.phrase', 'DIGITAL_ARREST', 20, 'Law enforcement impersonation, arrest threat, or coercive pressure found.'),
    ...scanPhrases(input, lower, rules.maliciousAppPhrases, 'maliciousApp.phrase', 'MALICIOUS_APP', 15, 'Requests dangerous app install, sideloading, or screen/device access.'),
    ...scanPhrases(input, lower, rules.kycThreatPhrases, 'text.kycThreat', 'TEXT', 14, 'Uses KYC suspension, account blocking, or disconnection threats.'),
    ...scanPhrases(input, lower, rules.urgencyPhrases, 'text.urgency', 'TEXT', 8, 'Creates artificial urgency or countdown pressure to rush your action.'),
    ...scanPhrases(input, lower, rules.pressureCtaPhrases, 'text.pressureCta', 'TEXT', 10, 'Pushes immediate action without verifying first.'),
    ...scanPhrases(input, lower, rules.otpSolicitationPhrases, 'text.otpSolicitation', 'TEXT', 18, 'Asks you to share or enter a One-Time Password (OTP).'),
    ...scanPhrases(input, lower, rules.sensitiveDataPhrases, 'text.sensitiveData', 'TEXT', 16, 'Requests confidential banking PIN, CVV, password, or ID numbers.'),
    ...scanPhrases(input, lower, rules.prizeBaitPhrases, 'text.prizeBait', 'TEXT', 12, 'Uses prize, lottery, or refund bait to lure payment or credentials.'),
    ...scanPhrases(input, lower, rules.phishingPhrases, 'text.phishing', 'TEXT', 12, 'Matches common banking phishing wording.')
  );

  signals.push(
    ...scanRegexRule(
      input,
      /\b(?:enter|type|input|put|share|provide)\b[^.!?\n]{0,45}\b(?:upi\s*)?pin\b[^.!?\n]{0,45}\b(?:to\s+)?(?:receive|accept|get|claim|collect)\b/i,
      'text.pinToReceive',
      'TEXT',
      20,
      'Asks you to enter a PIN to receive money — receiving money never requires entering a PIN.'
    ),
    ...scanRegexRule(
      input,
      /\b(?:processing\s+(?:fee|charge)s?|customs\s+(?:duty|fee)|clearance\s+fee|registration\s+fee|advance\s+(?:fee|payment)|pay\s+(?:rs\.?|inr|₹)?\s*\d+(?:\s*(?:fee|charge|to\s+release))?)\b/i,
      'text.feeRequest',
      'TEXT',
      14,
      'Demands an upfront fee or processing charge, a classic scam pattern.'
    ),
    ...scanRegexRule(
      input,
      /\b(?:legal\s+action|arrest\s+warrant|police\s+(?:action|case|complaint)|account\s+will\s+be\s+blocked(?:\s+today)?)\b/i,
      'text.blockingOrLegalThreat',
      'TEXT',
      14,
      'Threatens legal action, police involvement, or immediate account blocking.'
    )
  );

  const urlMatches = extractUrls(input);
  const foundUrls = urlMatches.map((m) => m.url);
  const suspiciousTldSet = new Set((rules.suspiciousTlds || []).map((t) => t.toLowerCase().replace(/^\./, '')));
  const shortenerSet = new Set((rules.urlShorteners || []).map((s) => s.toLowerCase()));
  const urlKeywords = Array.isArray(rules.urlKeywords) ? rules.urlKeywords : DEFAULT_RULES.urlKeywords;
  const brands = Array.isArray(rules.brands) ? rules.brands : DEFAULT_RULES.brands;

  for (const match of urlMatches) {
    const rawUrl = match.url;
    const lowerUrl = rawUrl.toLowerCase();
    const host = extractHost(rawUrl);

    if (/\.apk(?:[?#]|$)/i.test(rawUrl)) {
      signals.push({
        id: 'maliciousApp.apkLink',
        category: 'MALICIOUS_APP',
        points: 18,
        explanation: 'Direct link to an Android installer (.apk) outside official app stores.',
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      signals.push({
        id: 'url.ipAddress',
        category: 'URL',
        points: 16,
        explanation: `Link points to a raw IP address (${host}) instead of a registered bank or company domain.`,
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    if (shortenerSet.has(host)) {
      signals.push({
        id: 'url.shortener',
        category: 'URL',
        points: 10,
        explanation: `Uses a URL shortener (${host}) that hides the true destination.`,
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    const tld = host.includes('.') ? host.substring(host.lastIndexOf('.') + 1) : '';
    if (suspiciousTldSet.has(tld)) {
      signals.push({
        id: 'url.suspiciousTld',
        category: 'URL',
        points: 12,
        explanation: `Uses a high-risk domain ending (.${tld}) commonly abused in scam links.`,
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    if (lowerUrl.startsWith('http://')) {
      const paymentLike = /(pay|upi|bank|kyc|verify|login|account|bill|refund)/i.test(lowerUrl);
      signals.push({
        id: 'url.noHttps',
        category: 'URL',
        points: paymentLike ? 10 : 6,
        explanation: paymentLike
          ? 'Uses insecure plain HTTP on a payment/verification link instead of HTTPS.'
          : 'Uses unencrypted HTTP instead of HTTPS.',
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    const hitKeywords = urlKeywords.filter((k) => lowerUrl.includes(k));
    if (hitKeywords.length > 0) {
      signals.push({
        id: 'url.keyword',
        category: 'URL',
        points: 10,
        explanation: `Link includes deceptive keywords (${hitKeywords.slice(0, 4).join(', ')}).`,
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    for (const b of brands) {
      const officialDomains = Array.isArray(b.officialDomains) ? b.officialDomains : [];
      if (!officialDomains.length || isOfficialHost(host, officialDomains)) continue;
      const bRoot = officialDomains[0].split('.')[0].toLowerCase();
      const hostParts = host.split('.');
      const hostRoot = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : hostParts[0];

      if (host.includes(bRoot) || hostRoot.startsWith(bRoot) || hostRoot.endsWith(bRoot)) {
        signals.push({
          id: 'url.brandImpersonation',
          category: 'URL',
          points: 16,
          explanation: `Domain "${host}" mimics "${b.name}" instead of its official website (${officialDomains[0]}).`,
          matchedText: rawUrl,
          start: match.start,
          end: match.end
        });
        break;
      }

      if (bRoot.length >= 4 && hostParts[0]) {
        const subDist = levenshtein(hostParts[0].split('-')[0], bRoot);
        const rootDist = levenshtein(hostRoot.split('-')[0], bRoot);
        if (Math.min(subDist, rootDist) === 1) {
          signals.push({
            id: 'url.typosquatting',
            category: 'URL',
            points: 16,
            explanation: `Lookalike domain "${host}" closely mimics "${b.name}" (${officialDomains[0]}).`,
            matchedText: rawUrl,
            start: match.start,
            end: match.end
          });
          break;
        }
      }
    }
  }

  const phoneHits = [...input.matchAll(/(?:\+?91[\s-]?)?[6-9]\d{9}\b/g)];
  for (const b of brands) {
    const brandRx = new RegExp(`\\b${escapeRegex(b.name)}\\b`, 'i');
    const brandMatch = brandRx.exec(input);
    if (!brandMatch) continue;
    const officialDomains = Array.isArray(b.officialDomains) ? b.officialDomains : [];
    const hasUnofficialUrl = urlMatches.some((u) => !isOfficialHost(extractHost(u.url), officialDomains));
    if (hasUnofficialUrl || phoneHits.length > 0) {
      signals.push({
        id: 'text.brandMismatch',
        category: 'TEXT',
        points: 16,
        explanation: hasUnofficialUrl
          ? `Claims to be from "${b.name}", but links to an unofficial domain instead of ${officialDomains[0] || 'its official site'}.`
          : `Claims to be from "${b.name}", while giving a personal 10-digit mobile number.`,
        matchedText: brandMatch[0],
        start: brandMatch.index,
        end: brandMatch.index + brandMatch[0].length
      });
      break;
    }
  }

  const distinct = filterOverlapping(signals);
  const sorted = [...distinct].sort((a, b) => b.points - a.points);
  let accum = 0;
  for (let i = 0; i < sorted.length; i++) {
    accum += sorted[i].points * Math.pow(0.8, i);
  }
  let ruleScore = Math.min(100, Math.round(accum));

  const hasAuthority = AUTHORITY_TERMS.some((t) => lower.includes(t));
  const hasPayment = PAYMENT_TERMS.some((t) => lower.includes(t));
  const hasSecrecy = SECRECY_TERMS.some((t) => lower.includes(t));
  const isDigitalArrestCombo = hasAuthority && hasPayment && hasSecrecy;
  if (isDigitalArrestCombo) {
    ruleScore = Math.max(ruleScore, 85);
  }

  let finalScore = ruleScore;
  let mlResult = null;
  if (useMl) {
    try {
      const ready = await loadMlModels();
      if (ready && cachedTextModel && cachedUrlModel) {
        const textClf = classifyTextClient(input, cachedTextModel);
        let maxUrlProb = 0.0;
        for (const u of foundUrls) {
          const p = classifyUrlClient(u, cachedUrlModel, suspiciousTldSet);
          if (p > maxUrlProb) maxUrlProb = p;
        }
        const mlScore = Math.round(Math.max(textClf.probability, maxUrlProb) * 100);
        const blended = Math.round(0.6 * ruleScore + 0.4 * mlScore);

        if (isDigitalArrestCombo || ruleScore >= 75) {
          finalScore = Math.max(ruleScore, blended);
        } else if (distinct.length === 0) {
          finalScore = Math.min(blended, 24);
        } else {
          finalScore = blended;
        }

        mlResult = {
          textProbability: textClf.probability,
          urlProbability: foundUrls.length ? maxUrlProb : 0.0,
          topWords: textClf.topWords,
          ruleScore,
          mlScore
        };
      }
    } catch (mlErr) {
      console.warn('[CyberShield] Client ML skipped, using rules only:', mlErr);
      mlResult = null;
      finalScore = ruleScore;
    }
  }

  const thresholds = rules.scoringThresholds || DEFAULT_RULES.scoringThresholds;
  let level = 'LOW';
  if (finalScore >= thresholds.critical) level = 'CRITICAL';
  else if (finalScore >= thresholds.high) level = 'HIGH';
  else if (finalScore >= thresholds.medium) level = 'MEDIUM';

  if (isDigitalArrestCombo) {
    level = 'CRITICAL';
    finalScore = Math.max(finalScore, 85);
  }

  let summary = 'No red flags found. Still verify in your official bank app.';
  if (isDigitalArrestCombo) {
    summary = 'Critical threat detected: Law enforcement impersonation demanding secrecy and money transfer. Real agencies never arrest over video calls or demand payments.';
  } else if (distinct.length === 0 || level === 'LOW') {
    summary = 'No red flags found. Still verify in your official bank app.';
  } else if (level === 'CRITICAL') {
    summary = 'Extremely high risk. Multiple severe scam indicators detected. Stop all interaction immediately.';
  } else if (level === 'HIGH') {
    summary = 'High risk indicators detected. Do not click links, install apps, or share OTP/PIN details.';
  } else if (level === 'MEDIUM') {
    summary = 'Suspicious indicators found. Verify independently in your official bank app before acting.';
  }

  let scamType = 'NONE';
  if (distinct.length > 0) {
    if (distinct.some((s) => s.category === 'DIGITAL_ARREST')) scamType = 'DIGITAL_ARREST';
    else if (distinct.some((s) => s.category === 'MALICIOUS_APP')) scamType = 'MALICIOUS_APP';
    else if (distinct.some((s) => s.id === 'text.otpSolicitation' || s.id === 'text.pinToReceive' || s.id === 'text.sensitiveData')) scamType = 'CREDENTIAL_PHISHING';
    else scamType = 'PHISHING';
  }

  return {
    score: finalScore,
    level,
    summary,
    scamType,
    signals: distinct,
    urls: foundUrls,
    ml: mlResult
  };
}
