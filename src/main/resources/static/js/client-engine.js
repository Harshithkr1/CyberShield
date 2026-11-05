/**
 * client-engine.js - In-browser scam detection engine for Cyber Shield.
 *
 * Replicates the exact rule engine and ML inference from Spring Boot in pure JavaScript.
 * Enables Cyber Shield to run 100% autonomously on static hosts like GitHub Pages
 * without requiring any backend server.
 */

let cachedRules = null;
let cachedTextModel = null;
let cachedUrlModel = null;

const SMS_SYNONYMS = {
  your: '(?:your|ur)',
  ur: '(?:your|ur)',
  you: '(?:you|u)',
  u: '(?:you|u)',
  are: '(?:are|r)',
  r: '(?:are|r)',
  please: '(?:please|plz|pls)',
  plz: '(?:please|plz|pls)',
  pls: '(?:please|plz|pls)',
  thanks: '(?:thanks|thx)',
  thx: '(?:thanks|thx)',
  okay: '(?:okay|ok)',
  ok: '(?:okay|ok)',
  aadhaar: '(?:aadhaar|aadhar)',
  aadhar: '(?:aadhaar|aadhar)'
};

const AUTHORITY_TERMS = new Set([
  'cbi', 'police', 'customs', 'ncb', 'ed', 'trai', 'rbi',
  'cyber cell', 'court', 'supreme court', 'high court',
  'narcotics', 'enforcement directorate'
]);

const PAYMENT_TERMS = new Set([
  'safe account', 'rbi verification', 'transfer to safe', 'move your money',
  'move money', 'pay to avoid', 'pay fine', 'pay customs', 'customs fee',
  'clearance fee', 'deposit', 'settle the case'
]);

const SECRECY_TERMS = new Set([
  'do not tell anyone', 'do not disconnect', 'stay on video call',
  'stay on the call', 'keep the video call on', 'confidential',
  'skype', 'google meet', 'whatsapp video'
]);

const MULTI_PART_TLDS = new Set(['co', 'gov', 'org', 'net', 'ac', 'res', 'gen']);

async function loadStaticAssets() {
  if (cachedRules && cachedTextModel && cachedUrlModel) return;

  // Resolve base path (handles nested github pages repo path e.g. /cybershield/)
  const getUrl = (rel) => {
    try {
      return new URL(rel, window.location.href).href;
    } catch {
      return rel;
    }
  };

  const [rulesRes, textRes, urlRes] = await Promise.all([
    fetch(getUrl('data/rules.json')).catch(() => fetch(getUrl('rules.json'))),
    fetch(getUrl('data/ml/text_model.json')).catch(() => fetch(getUrl('ml/text_model.json'))),
    fetch(getUrl('data/ml/url_model.json')).catch(() => fetch(getUrl('ml/url_model.json'))),
  ]);

  cachedRules = await rulesRes.json();
  cachedTextModel = await textRes.json();
  cachedUrlModel = await urlRes.json();
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function compilePhraseRegex(phrase) {
  const tokens = phrase.trim().split(/\s+/);
  const parts = tokens.map(tok => {
    const lower = tok.toLowerCase();
    if (SMS_SYNONYMS[lower]) return SMS_SYNONYMS[lower];
    return escapeRegex(tok);
  });
  return new RegExp('\\b' + parts.join('[\\s\\-_/.]+') + '\\b', 'iu');
}

function scanPhrases(text, phrases, signalId, category, points, explanationTpl, limit = 0) {
  if (!text || !phrases) return [];
  const signals = [];
  for (const phrase of phrases) {
    if (!phrase) continue;
    if (limit > 0 && signals.length >= limit) break;
    const rx = compilePhraseRegex(phrase);
    const m = rx.exec(text);
    if (m) {
      signals.push({
        id: signalId,
        category,
        points,
        explanation: `${explanationTpl}. Detected: "${m[0]}".`,
        matchedText: m[0],
        start: m.index,
        end: m.index + m[0].length
      });
    }
  }
  return signals;
}

function extractUrls(text) {
  const matches = [];
  const rx = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`]+|(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|in|org|net|xyz|top|live|online|site|club|apk|biz|info|link|vip|pro)\b[^\s<>"'{}|\\^`]*/gi;
  let m;
  while ((m = rx.exec(text)) !== null) {
    let clean = m[0].replace(/[.,;:!?)]+$/, '');
    matches.push({
      url: clean,
      start: m.index,
      end: m.index + clean.length
    });
  }
  return matches;
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

function extractHost(urlStr) {
  try {
    let u = urlStr;
    if (!/^https?:\/\//i.test(u)) u = 'http://' + u;
    const parsed = new URL(u);
    return parsed.hostname.toLowerCase();
  } catch {
    const stripped = urlStr.replace(/^https?:\/\//i, '').split(/[\/?#]/)[0];
    return stripped.split(':')[0].toLowerCase();
  }
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
  const urlLength = raw.length;
  let dotCount = 0, hyphenCount = 0, digitCount = 0;
  for (const c of raw) {
    if (c === '.') dotCount++;
    else if (c === '-') hyphenCount++;
    else if (c >= '0' && c <= '9') digitCount++;
  }
  const entropy = calculateEntropy(raw);
  const host = extractHost(raw);
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(host) ? 1.0 : 0.0;
  
  const lastDot = host.lastIndexOf('.');
  const tld = lastDot >= 0 ? host.substring(lastDot + 1) : '';
  const suspiciousTld = (suspiciousTlds.has(tld) || ['xyz', 'top', 'club', 'site', 'online', 'work', 'click', 'buzz', 'rest', 'fit', 'gq', 'cf', 'ga', 'ml', 'tk', 'cc', 'icu', 'fun', 'live', 'vip'].includes(tld)) ? 1.0 : 0.0;
  const usesHttps = lower.startsWith('https://') ? 1.0 : 0.0;
  
  const parts = host.split('.').filter(Boolean);
  let subdomainCount = 0;
  if (parts.length >= 3 && MULTI_PART_TLDS.has(parts[parts.length - 2])) {
    subdomainCount = Math.max(0, parts.length - 3);
  } else {
    subdomainCount = Math.max(0, parts.length - 2);
  }

  return [urlLength, dotCount, hyphenCount, digitCount, entropy, isIp, suspiciousTld, usesHttps, subdomainCount];
}

function sigmoid(z) {
  return 1.0 / (1.0 + Math.exp(-z));
}

function classifyTextClient(text, model) {
  if (!text || !text.trim()) {
    return { probability: sigmoid(model.intercept), topWords: [] };
  }
  const lower = text.toLowerCase();
  const tokens = lower.match(/\b\w+\b/g) || [];
  if (!tokens.length) {
    return { probability: sigmoid(model.intercept), topWords: [] };
  }

  const ngrams = [...tokens];
  for (let i = 0; i < tokens.length - 1; i++) {
    ngrams.push(tokens[i] + ' ' + tokens[i + 1]);
  }

  const termCounts = {};
  for (const t of ngrams) {
    if (model.vocabulary.hasOwnProperty(t)) {
      const idx = model.vocabulary[t];
      termCounts[idx] = (termCounts[idx] || 0) + 1;
    }
  }

  const entries = Object.entries(termCounts);
  if (!entries.length) {
    return { probability: sigmoid(model.intercept), topWords: [] };
  }

  let sumSq = 0;
  const tfidfMap = {};
  for (const [idxStr, count] of entries) {
    const idx = parseInt(idxStr, 10);
    const val = count * model.idf[idx];
    tfidfMap[idx] = val;
    sumSq += val * val;
  }
  const l2Norm = Math.sqrt(sumSq);

  let dot = 0;
  const contributions = [];
  for (const [idxStr, val] of Object.entries(tfidfMap)) {
    const idx = parseInt(idxStr, 10);
    const xNorm = l2Norm > 0 ? val / l2Norm : 0;
    const coef = model.coefficients[idx];
    dot += xNorm * coef;

    if (coef > 0) {
      // Find term
      for (const [term, tIdx] of Object.entries(model.vocabulary)) {
        if (tIdx === idx) {
          contributions.push({ term, impact: coef * val });
          break;
        }
      }
    }
  }

  contributions.sort((a, b) => b.impact - a.impact);
  const topWords = contributions.slice(0, 5).map(c => c.term);
  const prob = sigmoid(dot + model.intercept);
  return { probability: prob, topWords };
}

function classifyUrlClient(urlStr, model, suspiciousTlds) {
  const feats = extractUrlFeatures(urlStr, suspiciousTlds);
  let dot = 0;
  for (let i = 0; i < feats.length; i++) {
    const std = model.stds[i] === 0 ? 1.0 : model.stds[i];
    const scaled = (feats[i] - model.means[i]) / std;
    dot += scaled * model.coefficients[i];
  }
  return sigmoid(dot + model.intercept);
}

function filterOverlapping(signals) {
  if (!signals || !signals.length) return [];
  const spanSignals = signals.filter(s => s.start >= 0 && s.end > s.start);
  const otherSignals = signals.filter(s => !(s.start >= 0 && s.end > s.start));

  spanSignals.sort((a, b) => {
    if (b.points !== a.points) return b.points - a.points;
    return (b.end - b.start) - (a.end - a.start);
  });

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

export async function runClientSideAnalysis(text, useMl = true) {
  await loadStaticAssets();

  const rules = cachedRules;
  const signals = [];
  const textLower = text.toLowerCase();

  // 1. Digital Arrest phrase scanning
  signals.push(...scanPhrases(text, rules.digitalArrestPhrases.highRisk, 'digitalArrest.phrase', 'DIGITAL_ARREST', 20, 'Digital arrest coercion or law enforcement impersonation phrase detected'));
  signals.push(...scanPhrases(text, rules.digitalArrestPhrases.authorityKeywords, 'digitalArrest.authority', 'DIGITAL_ARREST', 15, 'Government, law enforcement or regulatory agency impersonation detected'));
  signals.push(...scanPhrases(text, rules.digitalArrestPhrases.actionDemands, 'digitalArrest.actionDemand', 'DIGITAL_ARREST', 15, 'Coercive demand to remain on video call or transfer funds'));
  signals.push(...scanPhrases(text, rules.digitalArrestPhrases.legalThreats, 'digitalArrest.legalThreat', 'DIGITAL_ARREST', 15, 'Threat of arrest warrant, asset seizure, or immediate prosecution'));

  // 2. Malicious App phrase scanning
  signals.push(...scanPhrases(text, rules.appPhrases.highRisk, 'maliciousApp.phrase', 'MALICIOUS_APP', 15, 'Dangerous permission or device-access request phrase detected'));
  signals.push(...scanPhrases(text, rules.appPhrases.stealthTricks, 'maliciousApp.stealth', 'MALICIOUS_APP', 14, 'Instruction to bypass device security or enable sideloading'));
  signals.push(...scanPhrases(text, rules.appPhrases.lures, 'maliciousApp.lure', 'MALICIOUS_APP', 10, 'Common lure phrase used to trick victims into downloading malware'));

  // 3. Phishing phrase scanning
  signals.push(...scanPhrases(text, rules.phishingPhrases.kycThreats, 'text.kycThreat', 'TEXT', 14, 'Threat of account suspension, KYC expiration, or penalty detected'));
  signals.push(...scanPhrases(text, rules.phishingPhrases.urgentAction, 'text.urgency', 'TEXT', 8, 'Urgency or panic-inducing phrase detected'));
  signals.push(...scanPhrases(text, rules.phishingPhrases.otpSolicitation, 'text.otpSolicitation', 'TEXT', 18, 'Direct solicitation of One-Time Password (OTP) or PIN'));
  signals.push(...scanPhrases(text, rules.phishingPhrases.lotteryReward, 'text.lotteryReward', 'TEXT', 12, 'Unrealistic prize, cash lottery, or gift promise detected'));
  signals.push(...scanPhrases(text, rules.phishingPhrases.sensitiveData, 'text.sensitiveData', 'TEXT', 16, 'Request for sensitive credentials, Aadhaar, PAN, or passwords'));

  // 4. URL detection
  const urlMatches = extractUrls(text);
  const foundUrls = urlMatches.map(m => m.url);
  const suspiciousTldSet = new Set((rules.suspiciousTlds || []).map(t => t.toLowerCase().replace(/^\./, '')));
  const shortenerSet = new Set((rules.shorteners || []).map(s => s.toLowerCase()));

  for (const match of urlMatches) {
    const rawUrl = match.url;
    const lowerUrl = rawUrl.toLowerCase();
    const host = extractHost(rawUrl);

    if (/\.apk(?:[?#]|$)/i.test(rawUrl)) {
      signals.push({
        id: 'maliciousApp.apkLink',
        category: 'MALICIOUS_APP',
        points: 15,
        explanation: 'Direct link to an Android package (.apk) file outside an official app store.',
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      signals.push({
        id: 'url.ipAddress',
        category: 'URL',
        points: 18,
        explanation: `URL points directly to a raw IP address (${host}) rather than a registered domain.`,
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    if (shortenerSet.has(host)) {
      signals.push({
        id: 'url.shortener',
        category: 'URL',
        points: 8,
        explanation: `URL uses known shortener (${host}) which conceals the real destination.`,
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    const lastDot = host.lastIndexOf('.');
    const tld = lastDot >= 0 ? host.substring(lastDot + 1) : '';
    if (suspiciousTldSet.has(tld)) {
      signals.push({
        id: 'url.suspiciousTld',
        category: 'URL',
        points: 10,
        explanation: `URL uses the suspicious top-level domain '.${tld}'.`,
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    if (lowerUrl.startsWith('http://')) {
      signals.push({
        id: 'url.noHttps',
        category: 'URL',
        points: 6,
        explanation: 'URL uses plain HTTP rather than HTTPS, leaving data unencrypted.',
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    // Keyword in URL
    const keywords = ['verify', 'secure', 'login', 'kyc', 'update', 'banking', 'account', 'pay'];
    const hitKeywords = keywords.filter(k => lowerUrl.includes(k));
    if (hitKeywords.length > 0) {
      signals.push({
        id: 'url.keyword',
        category: 'URL',
        points: 10,
        explanation: `URL contains suspicious keyword(s): ${hitKeywords.join(', ')}.`,
        matchedText: rawUrl,
        start: match.start,
        end: match.end
      });
    }

    // Brand impersonation / typosquatting
    for (const b of (rules.brands || [])) {
      const bRoot = b.canonicalDomain.split('.')[0].toLowerCase();
      const hostParts = host.split('.');
      const hostRoot = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : hostParts[0];
      if (hostRoot !== bRoot && (host.includes(bRoot) || hostRoot.startsWith(bRoot) || hostRoot.endsWith(bRoot))) {
        signals.push({
          id: 'url.brandImpersonation',
          category: 'URL',
          points: 15,
          explanation: `URL appears to impersonate official brand "${b.name}".`,
          matchedText: rawUrl,
          start: match.start,
          end: match.end
        });
        break;
      }
      if (hostRoot !== bRoot && bRoot.length >= 5) {
        const dist = levenshtein(hostRoot, bRoot);
        if (dist === 1) {
          signals.push({
            id: 'url.typosquatting',
            category: 'URL',
            points: 12,
            explanation: `Domain "${hostRoot}" is a high-confidence typosquat of "${b.name}".`,
            matchedText: rawUrl,
            start: match.start,
            end: match.end
          });
          break;
        }
      }
    }
  }

  // 5. Scoring
  const distinct = filterOverlapping(signals);
  const sorted = [...distinct].sort((a, b) => b.points - a.points);
  let accum = 0;
  for (let i = 0; i < sorted.length; i++) {
    accum += sorted[i].points * Math.pow(0.80, i);
  }
  let ruleScore = Math.min(100, Math.round(accum));

  // Combinations
  const textSignals = distinct.map(s => s.matchedText.toLowerCase());
  const hasAuthority = distinct.some(s => s.id.includes('authority') || s.id.includes('digitalArrest')) &&
    Array.from(AUTHORITY_TERMS).some(t => textLower.includes(t));
  const hasPayment = Array.from(PAYMENT_TERMS).some(t => textLower.includes(t));
  const hasSecrecy = Array.from(SECRECY_TERMS).some(t => textLower.includes(t));

  const isDigitalArrestCombo = hasAuthority && hasPayment && hasSecrecy;
  if (isDigitalArrestCombo) {
    ruleScore = Math.max(ruleScore, 85);
  }

  let finalScore = ruleScore;
  let mlResult = null;

  if (useMl && cachedTextModel && cachedUrlModel) {
    const textClf = classifyTextClient(text, cachedTextModel);
    let maxUrlProb = 0.0;
    for (const u of foundUrls) {
      const p = classifyUrlClient(u, cachedUrlModel, suspiciousTldSet);
      if (p > maxUrlProb) maxUrlProb = p;
    }
    const mlScore = Math.round(Math.max(textClf.probability, maxUrlProb) * 100);
    const blended = Math.round(0.6 * ruleScore + 0.4 * mlScore);

    if (isDigitalArrestCombo || ruleScore >= 80) {
      finalScore = Math.max(ruleScore, blended);
    } else if (distinct.length === 0) {
      finalScore = Math.min(blended, 49);
    } else {
      finalScore = blended;
    }

    mlResult = {
      textProbability: textClf.probability,
      urlProbability: foundUrls.length ? maxUrlProb : 0.0,
      topWords: textClf.topWords,
      ruleScore: ruleScore,
      mlScore: mlScore
    };
  }

  // Determine Level
  let level = 'LOW';
  if (finalScore >= 80) level = 'CRITICAL';
  else if (finalScore >= 50) level = 'HIGH';
  else if (finalScore >= 20) level = 'MEDIUM';

  // Digital arrest combo override
  if (isDigitalArrestCombo && level !== 'CRITICAL') {
    level = 'CRITICAL';
    finalScore = Math.max(finalScore, 85);
  }

  // Summary
  let summary = 'A few minor patterns were noted. Treat with light caution.';
  if (distinct.length === 0) summary = 'No suspicious patterns detected. Always stay vigilant.';
  else if (isDigitalArrestCombo) summary = 'Critical threat detected: Coercive law enforcement impersonation demanding secret money transfer. A real agency never arrests over a video call and never asks for payment to a private account.';
  else if (level === 'CRITICAL') summary = 'Extremely high risk. This is very likely a scam. Stop all interaction.';
  else if (level === 'HIGH') summary = 'Multiple high-risk signals detected. Do not click links or share data.';
  else if (level === 'MEDIUM') summary = 'Several suspicious patterns found. Verify before acting.';

  // Scam type
  let scamType = 'SAFE';
  if (distinct.length > 0) {
    if (distinct.some(s => s.category === 'DIGITAL_ARREST')) scamType = 'DIGITAL_ARREST';
    else if (distinct.some(s => s.category === 'MALICIOUS_APP')) scamType = 'MALICIOUS_APP';
    else if (distinct.some(s => s.id === 'text.otpSolicitation')) scamType = 'CREDENTIAL_PHISHING';
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
