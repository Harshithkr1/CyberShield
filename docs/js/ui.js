/**
 * ui.js – DOM manipulation helpers for Cyber Shield.
 *
 * Every function in this module takes a result object (or primitive) and
 * writes safely to the DOM using document.createElement and textContent only.
 * No innerHTML is ever used with user text, guaranteeing complete protection
 * against XSS.
 */

// ── DOM references ────────────────────────────────────────────────────────

const $ = (id) => document.getElementById(id);

const emptyState       = $('empty-state');
const loadingState     = $('loading-state');
const errorState       = $('error-state');
const errorMsg         = $('error-message');
const resultCard       = $('result-card');

const gaugeArc         = $('gauge-arc');
const gaugeNeedle      = $('gauge-needle');
const gaugeScore       = $('gauge-score');
const riskBadge        = $('risk-badge');
const scamType         = $('scam-type');
const resultSummary    = $('result-summary');

const highlightedSec   = $('highlighted-section');
const highlightLegend  = $('highlight-legend');
const highlightedBox   = $('highlighted-message');

const signalsSection   = $('signals-section');
const signalsTitle     = $('signals-title');
const signalsList      = $('signals-list');

const urlsSection      = $('urls-section');
const urlsList         = $('urls-list');

const actionPanel      = $('action-panel');
const criticalAlert    = $('critical-alert');
const actionTitle      = $('action-title');
const actionList       = $('action-list');

const btnCopyResult    = $('btn-copy-result');
const copyHint         = $('copy-hint');
const copyToast        = $('copy-toast');

const mlSection        = $('ml-section');
const mlDetails        = $('ml-details');
const scoreFormula     = $('score-formula');

// Gauge geometry constants (M20 100 A80 80 0 0 1 180 100 -> radius 80 -> pi * 80)
const GAUGE_CIRCUMFERENCE = 251.2;

// Active animation frame handle
let gaugeAnimHandle = null;

// Stored current report for clipboard copying
let currentReportText = '';

// SVG Namespace
const SVG_NS = 'http://www.w3.org/2000/svg';

// ── State helpers ─────────────────────────────────────────────────────────

/** Hide every result-area child, then show the requested one. */
function showOnly(el) {
  [emptyState, loadingState, errorState, resultCard].forEach((node) => {
    if (node) node.classList.toggle('hidden', node !== el);
  });
}

export function showEmpty() {
  showOnly(emptyState);
}

export function showLoading() {
  showOnly(loadingState);
}

export function showError(message) {
  if (errorMsg) {
    errorMsg.textContent = message || 'An unexpected error occurred. Please verify your message and try again.';
  }
  showOnly(errorState);
}

// ── Helper: Safe SVG Icon Creator ─────────────────────────────────────────

function createSvg(viewBox, pathD, className) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', viewBox);
  svg.setAttribute('fill', 'currentColor');
  svg.setAttribute('aria-hidden', 'true');
  if (className) svg.setAttribute('class', className);

  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('d', pathD);
  path.setAttribute('fill-rule', 'evenodd');
  path.setAttribute('clip-rule', 'evenodd');
  svg.appendChild(path);
  return svg;
}

// ── Result rendering ──────────────────────────────────────────────────────

/**
 * Render a full AnalysisResult onto the result card and make it visible.
 *
 * @param {object} result – parsed API response
 * @param {string} [originalText] – the user-submitted text for highlight rendering
 */
export function showResult(result, originalText = '') {
  if (!result) return;

  const score    = typeof result.score === 'number' ? result.score : 0;
  const level    = result.level ?? 'LOW';
  const type     = result.scamType ?? 'SAFE';
  const summary  = result.summary ?? '';
  const signals  = Array.isArray(result.signals) ? result.signals : [];
  const urls     = Array.isArray(result.urls) ? result.urls : [];

  // Fallback to input textarea value if originalText wasn't passed directly
  if (!originalText) {
    originalText = $('input-text')?.value ?? '';
  }

  // 1. Set level attribute for CSS styling
  resultCard.dataset.level = level;

  // 2. Animate gauge score & needle (colored in level color)
  animateGauge(score, level);

  // 3. Risk badge with text label & icon, plus scam type label
  renderRiskBadge(level);

  if (scamType) {
    scamType.textContent = type && type !== 'SAFE'
      ? `Threat Vector: ${formatScamType(type)}`
      : 'No Threat Pattern Detected';
  }

  // 4. One-line summary
  if (resultSummary) {
    resultSummary.textContent = summary;
  }

  // 5. Render highlighted message (textContent only, zero innerHTML) & legend
  renderHighlightedMessage(originalText, signals);

  // 6. Render "Why this score" signals list grouped by category & sorted by points
  renderSignalsList(signals);

  // 7. Render detected URLs list
  renderUrlsList(urls);

  // 8. Render "What should I do now" advice panel (numbered checklist & 1930 alert for Critical)
  renderActionPanel(level, type);

  // 9. Prepare plain-text report for Copy button
  prepareCopyReport(result, originalText);

  // 10. ML section (if ML output is provided or off-note when disabled)
  renderMlSection(result);

  // Reveal the card
  showOnly(resultCard);
}

// ── Gauge animation ───────────────────────────────────────────────────────

function animateGauge(targetScore, level) {
  if (gaugeAnimHandle) {
    cancelAnimationFrame(gaugeAnimHandle);
  }

  const clampedScore = Math.max(0, Math.min(targetScore, 100));
  const targetOffset = GAUGE_CIRCUMFERENCE * (1 - clampedScore / 100);
  if (gaugeArc) {
    gaugeArc.style.strokeDashoffset = targetOffset;
  }

  // Needle angle: -90° (0 score) to +90° (100 score)
  const deg = -90 + (clampedScore / 100) * 180;
  if (gaugeNeedle) {
    gaugeNeedle.setAttribute('transform', `rotate(${deg}, 100, 100)`);
  }

  // Score font colors matching level
  const colours = {
    LOW: 'var(--risk-low)',
    MEDIUM: 'var(--risk-medium)',
    HIGH: 'var(--risk-high)',
    CRITICAL: 'var(--risk-critical)'
  };
  const color = colours[level] || 'var(--silver-300)';
  if (gaugeScore) {
    gaugeScore.style.fill = color;
  }

  // Count-up animation
  const startTime = performance.now();
  const duration = 850; // ms

  function updateNumber(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const easeProgress = 1 - Math.pow(1 - progress, 3);
    const currentVal = Math.round(easeProgress * clampedScore);

    if (gaugeScore) {
      gaugeScore.textContent = String(currentVal);
    }

    if (progress < 1) {
      gaugeAnimHandle = requestAnimationFrame(updateNumber);
    }
  }

  gaugeAnimHandle = requestAnimationFrame(updateNumber);
}

// ── Risk Badge (Text label + icon) ────────────────────────────────────────

function renderRiskBadge(level) {
  if (!riskBadge) return;
  riskBadge.replaceChildren();

  const config = {
    LOW: {
      label: 'LOW RISK',
      path: 'M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM13.707 8.707a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z'
    },
    MEDIUM: {
      label: 'MEDIUM RISK',
      path: 'M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z'
    },
    HIGH: {
      label: 'HIGH RISK',
      path: 'M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.63-1.515 2.63H3.72c-1.347 0-2.189-1.463-1.515-2.63l6.28-10.875zM10 5a1 1 0 011 1v4a1 1 0 11-2 0V6a1 1 0 011-1zm0 8a1.25 1.25 0 100-2.5 1.25 1.25 0 000 2.5z'
    },
    CRITICAL: {
      label: 'CRITICAL THREAT',
      path: 'M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM10 6a1 1 0 00-1 1v4a1 1 0 102 0V7a1 1 0 00-1-1zm0 8a1.25 1.25 0 100-2.5 1.25 1.25 0 000 2.5z'
    }
  };

  const item = config[level] || config.LOW;
  const icon = createSvg('0 0 20 20', item.path, 'risk-badge-icon');
  const span = document.createElement('span');
  span.className = 'risk-badge-text';
  span.textContent = item.label;

  riskBadge.appendChild(icon);
  riskBadge.appendChild(span);
}

// ── Category Classification & Metadata ────────────────────────────────────

const CATEGORY_META = {
  DIGITAL_ARREST: {
    key: 'arrest',
    title: 'Digital Arrest & Coercion',
    dotClass: 'dot-arrest'
  },
  MALICIOUS_APP: {
    key: 'apk',
    title: 'Malicious App & Sideloading',
    dotClass: 'dot-apk'
  },
  URL: {
    key: 'url',
    title: 'Deceptive URL & Domain',
    dotClass: 'dot-url'
  },
  CREDENTIAL: {
    key: 'credential',
    title: 'Credentials & OTPs',
    dotClass: 'dot-credential'
  },
  URGENCY: {
    key: 'urgency',
    title: 'Urgency & Pressure',
    dotClass: 'dot-urgency'
  },
  PHISHING: {
    key: 'phishing',
    title: 'Phishing Patterns & Lures',
    dotClass: 'dot-phishing'
  }
};

function classifySignal(signal) {
  const cat = String(signal.category || '').toUpperCase();
  const id  = String(signal.id || '').toLowerCase();

  if (cat === 'DIGITAL_ARREST' || id.includes('digitalarrest')) return 'DIGITAL_ARREST';
  if (cat === 'MALICIOUS_APP' || id.includes('maliciousapp') || id.includes('apk')) return 'MALICIOUS_APP';
  if (cat === 'URL' || id.startsWith('url.')) return 'URL';
  if (id.includes('otp') || id.includes('sensitivedata') || id.includes('kyc') || id.includes('prizebait')) return 'CREDENTIAL';
  if (id.includes('urgency') || id.includes('pressure') || id.includes('caps') || id.includes('exclamation')) return 'URGENCY';
  return 'PHISHING';
}

// ── Highlighted original message & legend ─────────────────────────────────

/**
 * Builds the highlighted message DOM tree using document.createElement
 * and textContent only. Never uses innerHTML with user text to prevent XSS.
 * Resolves overlapping intervals cleanly via boundary point slicing.
 */
function renderHighlightedMessage(originalText, signals) {
  if (!highlightedBox || !highlightedSec) return;

  highlightedBox.replaceChildren();
  if (highlightLegend) highlightLegend.replaceChildren();

  const text = String(originalText || '');
  if (!text) {
    highlightedSec.classList.add('hidden');
    return;
  }
  highlightedSec.classList.remove('hidden');

  // 1. Collect valid intervals
  const rawIntervals = [];
  for (const s of signals) {
    if (typeof s.start === 'number' && typeof s.end === 'number' &&
        s.start >= 0 && s.end > s.start && s.end <= text.length) {

      const spanLen = s.end - s.start;
      if (s.id?.startsWith('text.excessive') && spanLen >= text.length * 0.9 && signals.length > 1) {
        continue; // Skip whole-message caps swamping specific phrases
      }

      rawIntervals.push({
        start: s.start,
        end: s.end,
        categoryKey: classifySignal(s),
        points: s.points || 0
      });
    }
  }

  // If no highlights found, append plain text
  if (rawIntervals.length === 0) {
    highlightedBox.appendChild(document.createTextNode(text));
    return;
  }

  // 2. Generate non-overlapping boundary points
  const pointsSet = new Set([0, text.length]);
  for (const iv of rawIntervals) {
    pointsSet.add(iv.start);
    pointsSet.add(iv.end);
  }
  const sortedPoints = Array.from(pointsSet).sort((a, b) => a - b);

  // 3. Segment evaluation & DOM construction
  const categoryCounts = {};
  let currentGroup = null;

  for (let i = 0; i < sortedPoints.length - 1; i++) {
    const segStart = sortedPoints[i];
    const segEnd   = sortedPoints[i + 1];
    if (segStart >= segEnd) continue;

    // Find intervals covering this segment
    const covering = rawIntervals.filter((iv) => iv.start <= segStart && iv.end >= segEnd);

    if (covering.length === 0) {
      // Plain text segment
      if (currentGroup && currentGroup.isHighlight) {
        commitSegmentGroup(currentGroup, highlightedBox);
        currentGroup = null;
      }
      if (!currentGroup) {
        currentGroup = { isHighlight: false, text: text.slice(segStart, segEnd) };
      } else {
        currentGroup.text += text.slice(segStart, segEnd);
      }
    } else {
      // Highlighted segment: choose covering interval with highest points
      covering.sort((a, b) => b.points - a.points);
      const best = covering[0];
      const catKey = best.categoryKey;

      if (currentGroup && (!currentGroup.isHighlight || currentGroup.catKey !== catKey)) {
        commitSegmentGroup(currentGroup, highlightedBox);
        currentGroup = null;
      }

      if (!currentGroup) {
        currentGroup = { isHighlight: true, catKey, text: text.slice(segStart, segEnd) };
        categoryCounts[catKey] = (categoryCounts[catKey] || 0) + 1;
      } else {
        currentGroup.text += text.slice(segStart, segEnd);
      }
    }
  }

  if (currentGroup) {
    commitSegmentGroup(currentGroup, highlightedBox);
  }

  // 4. Render Category Legend
  if (highlightLegend) {
    for (const [catKey, meta] of Object.entries(CATEGORY_META)) {
      const count = categoryCounts[catKey] || 0;
      if (count > 0) {
        const chip = document.createElement('div');
        chip.className = 'legend-chip';

        const dot = document.createElement('span');
        dot.className = `legend-dot ${meta.dotClass}`;
        dot.setAttribute('aria-hidden', 'true');

        const titleSpan = document.createElement('span');
        titleSpan.className = 'legend-title';
        titleSpan.textContent = meta.title;

        const countSpan = document.createElement('span');
        countSpan.className = 'legend-count';
        countSpan.textContent = `${count} ${count === 1 ? 'trigger' : 'triggers'}`;

        chip.appendChild(dot);
        chip.appendChild(titleSpan);
        chip.appendChild(countSpan);
        highlightLegend.appendChild(chip);
      }
    }
  }
}

function commitSegmentGroup(group, container) {
  if (!group || !group.text) return;
  if (!group.isHighlight) {
    container.appendChild(document.createTextNode(group.text));
  } else {
    const meta = CATEGORY_META[group.catKey] || CATEGORY_META.PHISHING;
    const mark = document.createElement('mark');
    mark.className = `highlighted-phrase mark-${meta.key}`;
    mark.textContent = group.text;
    container.appendChild(mark);
  }
}

// ── "Why this score" signals list (Grouped & Sorted) ──────────────────────

function renderSignalsList(signals) {
  if (!signalsList || !signalsSection) return;

  signalsList.replaceChildren();

  if (signalsTitle) {
    signalsTitle.textContent = signals.length > 0
      ? `Why this score (${signals.length} ${signals.length === 1 ? 'indicator' : 'indicators'} detected)`
      : 'Why this score';
  }

  if (signals.length === 0) {
    const emptyNotice = document.createElement('div');
    emptyNotice.className = 'signals-empty-card';
    const msg = document.createElement('p');
    msg.className = 'signal-explanation';
    msg.textContent = 'No suspicious indicators found. The text shows no known deceptive phrases, fraudulent URL structures, or coercive scripts.';
    emptyNotice.appendChild(msg);
    signalsList.appendChild(emptyNotice);
    signalsSection.classList.remove('hidden');
    return;
  }

  // 1. Group signals by category
  const groups = {};
  for (const s of signals) {
    const key = classifySignal(s);
    if (!groups[key]) groups[key] = [];
    groups[key].push(s);
  }

  // 2. Sort signals within each group by points descending
  for (const key in groups) {
    groups[key].sort((a, b) => (b.points ?? 0) - (a.points ?? 0));
  }

  // 3. Sort groups by highest scoring signal descending
  const sortedGroupKeys = Object.keys(groups).sort((a, b) => {
    const maxA = Math.max(...groups[a].map((s) => s.points ?? 0));
    const maxB = Math.max(...groups[b].map((s) => s.points ?? 0));
    return maxB - maxA;
  });

  // 4. Render Group Containers
  for (const groupKey of sortedGroupKeys) {
    const groupSignals = groups[groupKey];
    const meta = CATEGORY_META[groupKey] || CATEGORY_META.PHISHING;
    const totalPoints = groupSignals.reduce((acc, curr) => acc + (curr.points ?? 0), 0);

    const groupEl = document.createElement('div');
    groupEl.className = 'signal-category-group';

    // Group Header
    const headerEl = document.createElement('div');
    headerEl.className = 'signal-group-header';

    const headerLeft = document.createElement('div');
    headerLeft.className = 'signal-group-left';

    const dot = document.createElement('span');
    dot.className = `legend-dot ${meta.dotClass}`;
    dot.setAttribute('aria-hidden', 'true');

    const groupTitle = document.createElement('h3');
    groupTitle.className = 'signal-group-title';
    groupTitle.textContent = meta.title;

    headerLeft.appendChild(dot);
    headerLeft.appendChild(groupTitle);

    const groupBadge = document.createElement('span');
    groupBadge.className = 'signal-group-badge';
    groupBadge.textContent = `${groupSignals.length} ${groupSignals.length === 1 ? 'signal' : 'signals'} · +${totalPoints} pts`;

    headerEl.appendChild(headerLeft);
    headerEl.appendChild(groupBadge);
    groupEl.appendChild(headerEl);

    // List of signal items
    const itemsList = document.createElement('div');
    itemsList.className = 'signal-items-list';

    for (const s of groupSignals) {
      const card = document.createElement('div');
      card.className = 'signal-card';
      card.setAttribute('role', 'listitem');

      // Top row: Points + Explanation
      const topRow = document.createElement('div');
      topRow.className = 'signal-card-top';

      const pointsPill = document.createElement('span');
      pointsPill.className = `signal-points pill-${meta.key}`;
      pointsPill.textContent = `+${s.points ?? 0} pts`;

      const explanation = document.createElement('p');
      explanation.className = 'signal-explanation';
      explanation.textContent = s.explanation ?? 'Suspicious pattern identified.';

      topRow.appendChild(pointsPill);
      topRow.appendChild(explanation);
      card.appendChild(topRow);

      // Matched text callout if present
      if (s.matchedText) {
        const matchedBox = document.createElement('div');
        matchedBox.className = 'signal-matched';
        const label = document.createElement('span');
        label.className = 'matched-label';
        label.textContent = 'Matched: ';
        const quote = document.createElement('code');
        quote.className = 'matched-code';
        quote.textContent = `"${s.matchedText}"`;
        matchedBox.appendChild(label);
        matchedBox.appendChild(quote);
        card.appendChild(matchedBox);
      }

      // Collapsible technical details
      const details = document.createElement('details');
      details.className = 'signal-details';

      const summary = document.createElement('summary');
      summary.className = 'signal-details-summary';
      summary.textContent = 'Technical details & rule metadata';
      details.appendChild(summary);

      const detailsBody = document.createElement('div');
      detailsBody.className = 'signal-details-body';

      const ruleLine = document.createElement('div');
      ruleLine.className = 'detail-line';
      ruleLine.textContent = `Rule ID: ${s.id || 'N/A'}`;
      detailsBody.appendChild(ruleLine);

      if (typeof s.start === 'number' && typeof s.end === 'number' && s.start >= 0) {
        const offsetLine = document.createElement('div');
        offsetLine.className = 'detail-line';
        offsetLine.textContent = `Position: chars ${s.start}–${s.end}`;
        detailsBody.appendChild(offsetLine);
      }

      const catLine = document.createElement('div');
      catLine.className = 'detail-line';
      catLine.textContent = `Category: ${s.category || 'TEXT'}`;
      detailsBody.appendChild(catLine);

      details.appendChild(detailsBody);
      card.appendChild(details);

      itemsList.appendChild(card);
    }

    groupEl.appendChild(itemsList);
    signalsList.appendChild(groupEl);
  }

  signalsSection.classList.remove('hidden');
}

// ── URLs list ─────────────────────────────────────────────────────────────

function renderUrlsList(urls) {
  if (!urlsList || !urlsSection) return;

  urlsList.replaceChildren();

  if (urls.length === 0) {
    urlsSection.classList.add('hidden');
    return;
  }

  for (const url of urls) {
    const li = document.createElement('li');
    li.className = 'url-item';
    li.textContent = url;
    li.setAttribute('title', url);
    urlsList.appendChild(li);
  }

  urlsSection.classList.remove('hidden');
}

// ── "What should I do now" advice panel ───────────────────────────────────

function renderActionPanel(level, scamType) {
  if (!actionList || !actionPanel) return;

  actionList.replaceChildren();

  // 1. Critical Helpline 1930 Emergency Banner
  if (criticalAlert) {
    criticalAlert.replaceChildren();
    if (level === 'CRITICAL') {
      criticalAlert.classList.remove('hidden');

      const alertIcon = createSvg(
        '0 0 20 20',
        'M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM10 6a1 1 0 00-1 1v4a1 1 0 102 0V7a1 1 0 00-1-1zm0 8a1.25 1.25 0 100-2.5 1.25 1.25 0 000 2.5z',
        'critical-alert-icon'
      );

      const alertBody = document.createElement('div');
      alertBody.className = 'critical-alert-body';

      const alertTag = document.createElement('span');
      alertTag.className = 'critical-alert-tag';
      alertTag.textContent = 'Emergency Immediate Action';

      const alertTitle = document.createElement('h4');
      alertTitle.className = 'critical-alert-title';
      alertTitle.textContent = 'Call 1930 National Cyber Crime Helpline';

      const alertDesc = document.createElement('p');
      alertDesc.className = 'critical-alert-desc';
      alertDesc.textContent =
        'If you have transferred funds or shared banking OTPs, call 1930 immediately within the Golden Hour to freeze stolen money in transit. You can also file a complaint at cybercrime.gov.in.';

      const alertBtns = document.createElement('div');
      alertBtns.className = 'critical-alert-btns';

      const btn1930 = document.createElement('a');
      btn1930.href = 'tel:1930';
      btn1930.className = 'pill pill-call-1930';
      btn1930.textContent = '📞 Dial 1930 Toll-Free';

      const btnPortal = document.createElement('a');
      btnPortal.href = 'https://cybercrime.gov.in';
      btnPortal.target = '_blank';
      btnPortal.rel = 'noopener noreferrer';
      btnPortal.className = 'pill';
      btnPortal.textContent = 'cybercrime.gov.in →';

      alertBtns.appendChild(btn1930);
      alertBtns.appendChild(btnPortal);

      alertBody.appendChild(alertTag);
      alertBody.appendChild(alertTitle);
      alertBody.appendChild(alertDesc);
      alertBody.appendChild(alertBtns);

      criticalAlert.appendChild(alertIcon);
      criticalAlert.appendChild(alertBody);
    } else {
      criticalAlert.classList.add('hidden');
    }
  }

  // 2. Numbered Checklist Steps
  const steps = getActionSteps(level, scamType);

  steps.forEach((stepText, idx) => {
    const li = document.createElement('li');
    li.className = 'checklist-item';

    const numBadge = document.createElement('span');
    numBadge.className = 'checklist-num';
    numBadge.textContent = String(idx + 1).padStart(2, '0');

    const contentBox = document.createElement('div');
    contentBox.className = 'checklist-content';

    const p = document.createElement('p');
    p.className = 'checklist-text';
    p.textContent = stepText;

    contentBox.appendChild(p);
    li.appendChild(numBadge);
    li.appendChild(contentBox);
    actionList.appendChild(li);
  });

  actionPanel.classList.remove('hidden');
}

function getActionSteps(level, scamType) {
  const normType = String(scamType || '').toUpperCase();

  if (normType.includes('DIGITAL_ARREST')) {
    return [
      'Disconnect the video call or hang up immediately. Real police, CBI, ED, and courts NEVER conduct trials or arrest anyone over video calls.',
      'Never transfer money to any "safe account", "RBI verification account", or private bank details. Real government agencies never ask for funds to clear cases.',
      'Report this incident immediately to the National Cyber Crime Helpline by dialling 1930 or filing a complaint at cybercrime.gov.in.',
      'If you shared sensitive identity (Aadhaar/PAN) or banking information, inform your bank right away to monitor and protect your accounts.'
    ];
  }

  if (normType.includes('CREDENTIAL_PHISHING') || normType.includes('PHISHING')) {
    return [
      'Do NOT click any links in this message or enter your password, PIN, CVV, or Aadhaar details.',
      'Never disclose your One-Time Password (OTP) to anyone. Legitimate banks and services will never call or message to ask for your OTP.',
      'If you already entered passwords or banking credentials, contact your bank immediately to block your cards and freeze internet banking.',
      'Block the sender’s phone number or email and report the message as spam.'
    ];
  }

  if (normType.includes('MALICIOUS_APP')) {
    return [
      'Do NOT download or install the .apk file or any app linked in this message.',
      'Never enable "Install from Unknown Sources" or grant Accessibility / SMS permissions to unfamiliar apps.',
      'If you already installed an app (e.g. AnyDesk, TeamViewer, or unknown APK), disconnect your internet immediately, uninstall the app, and run a malware scan.',
      'Only download software from official app stores (Google Play Store or Apple App Store).'
    ];
  }

  switch (level) {
    case 'CRITICAL':
    case 'HIGH':
      return [
        'Do not reply, click any links, download attachments, or call the phone numbers in this message.',
        'Verify the communication independently by looking up the official customer service contact on the organisation\'s genuine website.',
        'Report this attempt to your messaging provider and to cybercrime.gov.in (Helpline: 1930).'
      ];

    case 'MEDIUM':
      return [
        'Proceed with caution. Verify the sender\'s identity through a verified independent channel before taking any action.',
        'Do not use links or phone numbers provided inside this message.',
        'Never disclose confidential credentials like OTPs, ATM PINs, or UPI PINs.'
      ];

    case 'LOW':
    default:
      return [
        'No immediate scam patterns were detected, but always stay vigilant with unexpected messages.',
        'Never share passwords, banking PINs, or OTPs with anyone.',
        'Always check the sender\'s full address and verify links before clicking.'
      ];
  }
}

// ── Plain-text Report Generator for Copy Button ───────────────────────────

function prepareCopyReport(result, originalText) {
  const score    = result.score ?? 0;
  const level    = result.level ?? 'LOW';
  const type     = formatScamType(result.scamType ?? 'SAFE');
  const summary  = result.summary ?? '';
  const signals  = result.signals ?? [];
  const urls     = result.urls ?? [];
  const actions  = getActionSteps(level, result.scamType);

  const lines = [];
  lines.push('================================================================');
  lines.push('CYBER SHIELD ANALYSIS REPORT');
  lines.push('================================================================');
  lines.push(`Risk Score:  ${score} / 100`);
  lines.push(`Risk Level:  ${level}`);
  lines.push(`Scam Type:   ${type}`);
  lines.push(`Summary:     ${summary}`);
  lines.push('');

  if (originalText) {
    lines.push('Analysed Message:');
    lines.push(`"${originalText}"`);
    lines.push('');
  }

  if (urls.length > 0) {
    lines.push('Detected URLs:');
    urls.forEach((u) => lines.push(`• ${u}`));
    lines.push('');
  }

  lines.push(`Why this score (${signals.length} indicators):`);
  if (signals.length === 0) {
    lines.push('• No suspicious patterns detected.');
  } else {
    signals.forEach((s) => {
      lines.push(`• [${s.category ?? 'SIGNAL'}] (+${s.points ?? 0} pts) ${s.explanation ?? ''}`);
      if (s.matchedText) {
        lines.push(`  Matched: "${s.matchedText}"`);
      }
    });
  }
  lines.push('');

  lines.push('What should I do now:');
  actions.forEach((act, idx) => {
    lines.push(`${idx + 1}. ${act}`);
  });
  lines.push('');

  lines.push('Disclaimer:');
  lines.push('Cyber Shield gives a heuristic risk estimate, not a guarantee. When in doubt, don\'t click, don\'t pay, and verify through official channels.');
  lines.push('================================================================');

  currentReportText = lines.join('\n');

  if (btnCopyResult) {
    btnCopyResult.onclick = handleCopyReport;
  }
}

async function handleCopyReport() {
  if (!currentReportText || !btnCopyResult) return;

  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(currentReportText);
    } else {
      const ta = document.createElement('textarea');
      ta.value = currentReportText;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }

    const span = btnCopyResult.querySelector('span');
    const originalText = span ? span.textContent : 'Copy result';
    if (span) span.textContent = '✓ Copied!';
    btnCopyResult.classList.add('copied');

    if (copyHint) {
      copyHint.textContent = 'Report copied to clipboard!';
    }

    // Show floating toast
    if (copyToast) {
      copyToast.classList.add('show');
    }

    setTimeout(() => {
      if (span) span.textContent = originalText;
      btnCopyResult.classList.remove('copied');
      if (copyHint) copyHint.textContent = '';
      if (copyToast) copyToast.classList.remove('show');
    }, 2500);
  } catch (err) {
    if (copyHint) {
      copyHint.textContent = 'Failed to copy report to clipboard.';
    }
  }
}

// ── ML Section (Confidence lines + top words + hybrid score breakdown) ───

function renderMlSection(result) {
  if (!mlSection || !mlDetails) return;

  mlDetails.replaceChildren();

  const ml = result?.ml;
  if (!ml) {
    // When ML layer is off, hide detailed metrics and show a small note "ML layer off"
    mlSection.classList.remove('hidden');
    mlSection.classList.add('ml-off-mode');

    const note = document.createElement('div');
    note.className = 'ml-off-note';
    note.textContent = 'ML layer off';
    mlDetails.appendChild(note);

    if (scoreFormula) {
      scoreFormula.textContent = '';
      scoreFormula.classList.add('hidden');
    }
    return;
  }

  mlSection.classList.remove('hidden');
  mlSection.classList.remove('ml-off-mode');

  const { textProbability, urlProbability, topWords, ruleScore: rawRuleScore, mlScore: rawMlScore } = ml;
  const urls = Array.isArray(result?.urls) ? result.urls : [];
  const hasUrls = urls.length > 0;

  const textPct = Math.round((textProbability || 0) * 100);
  const urlPct  = Math.round((urlProbability || 0) * 100);
  const mlScore = (rawMlScore != null && rawMlScore > 0) ? rawMlScore : (hasUrls ? Math.max(textPct, urlPct) : textPct);
  const ruleScore = rawRuleScore != null ? rawRuleScore : (result?.score ?? 0);
  const finalScore = result?.score ?? 0;

  // 1. Show both numbers: "Rules score: X, ML: Y%, Final: Z"
  const formulaText = `Rules score: ${ruleScore}, ML: ${mlScore}%, Final: ${finalScore}`;

  if (scoreFormula) {
    scoreFormula.textContent = formulaText;
    scoreFormula.classList.remove('hidden');
  }

  const formulaBox = document.createElement('div');
  formulaBox.className = 'ml-score-breakdown';
  formulaBox.textContent = formulaText;
  mlDetails.appendChild(formulaBox);

  // 2. Language pattern confidence: NN% scam-like
  const langBox = document.createElement('div');
  langBox.className = 'ml-confidence-item';

  const langHeader = document.createElement('div');
  langHeader.className = 'ml-confidence-header';

  const langTitle = document.createElement('span');
  langTitle.className = 'ml-confidence-title';
  langTitle.textContent = `Language pattern confidence: ${textPct}% scam-like`;

  langHeader.appendChild(langTitle);
  langBox.appendChild(langHeader);

  const langTrack = document.createElement('div');
  langTrack.className = 'ml-bar-track';

  const langFill = document.createElement('div');
  langFill.className = 'ml-bar-fill';
  langFill.style.width = `${Math.max(0, Math.min(100, textPct))}%`;

  langTrack.appendChild(langFill);
  langBox.appendChild(langTrack);
  mlDetails.appendChild(langBox);

  // 3. Top influencing words as small chips
  if (Array.isArray(topWords) && topWords.length > 0) {
    const wordsSection = document.createElement('div');
    wordsSection.className = 'ml-top-words';

    const wordsTitle = document.createElement('span');
    wordsTitle.className = 'ml-words-title';
    wordsTitle.textContent = 'Top influencing words:';
    wordsSection.appendChild(wordsTitle);

    const chipsRow = document.createElement('div');
    chipsRow.className = 'ml-chips-row';

    for (const word of topWords) {
      const chip = document.createElement('span');
      chip.className = 'ml-word-chip';
      chip.textContent = word;
      chipsRow.appendChild(chip);
    }

    wordsSection.appendChild(chipsRow);
    mlDetails.appendChild(wordsSection);
  }

  // 4. URL pattern confidence when a URL was found
  if (hasUrls) {
    const urlBox = document.createElement('div');
    urlBox.className = 'ml-confidence-item';

    const urlHeader = document.createElement('div');
    urlHeader.className = 'ml-confidence-header';

    const urlTitle = document.createElement('span');
    urlTitle.className = 'ml-confidence-title';
    urlTitle.textContent = `URL pattern confidence: ${urlPct}% scam-like`;

    urlHeader.appendChild(urlTitle);
    urlBox.appendChild(urlHeader);

    const urlTrack = document.createElement('div');
    urlTrack.className = 'ml-bar-track';

    const urlFill = document.createElement('div');
    urlFill.className = 'ml-bar-fill';
    urlFill.style.width = `${Math.max(0, Math.min(100, urlPct))}%`;

    urlTrack.appendChild(urlFill);
    urlBox.appendChild(urlTrack);
    mlDetails.appendChild(urlBox);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────

function formatCategory(cat) {
  return String(cat || '')
    .toLowerCase()
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function formatScamType(key) {
  return String(key || '')
    .toLowerCase()
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function pct(v) {
  return typeof v === 'number' ? `${(v * 100).toFixed(1)}%` : '—';
}
