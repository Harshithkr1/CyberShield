/**
 * verify.js – Frontend for the #verify module ("1 Before", "2 During", "3 After").
 *
 * Calls /api/verify/* endpoints, builds all DOM nodes via createElement + textContent
 * (zero innerHTML), routes all text through i18n, and stores only the demo receipt
 * trail under localStorage key "uss.trail" (inside try/catch).
 */

import { initI18n, t, onLangChange } from './i18n.js';
import { getServerStatus, onServerStatusChange } from './health.js';
import { parseUpiUri, analyzeUpiFields, preloadDemoRegistry, lookupDemoRegistry } from './upi-qr.js';
import { generateOrderRef, createPayOrder, buildTamperedToken, verifyPayOrderToken } from './pay-tamper-lab.js';
import { createReceiptBundle, verifyReceiptBundleJson, savePreparedReport, loadPreparedReport, renderPreparedReportRoot } from './receipt-evidence.js';
import { buildProtectedLink, validateDestinationUrl } from './go-utils.js';

const TRAIL_STORAGE_KEY = 'uss.trail';
const verifyRoot = document.getElementById('verify-root');

const state = {
  activeTab: 't1', // 't1' | 't2' | 't3'
  merchants: [],
  merchantsLoaded: false,
  // Tab 1 (Before)
  qrUriInput: '',
  qrExpectedAmount: '',
  qrError: '',
  qrResult: null,
  qrWebLink: '',
  qrPlainText: '',
  qrRegistryResult: null,
  camActive: false,
  camNotice: '',
  camStream: null,
  camRaf: null,
  camTimer: null,
  upiInput: '',
  nameInput: '',
  tab1Loading: false,
  tab1Error: '',
  tab1Result: null,
  // Tab 2 (During – Tamper Lab & Signed QR)
  selectedMerchantId: 'ravi-stores',
  amountInput: '500',
  tab2Loading: false,
  tab2Error: '',
  tab2Copied: false,
  qrData: null,
  tamperAmountInput: '5000',
  tamperCheckLoading: false,
  tamperCheckResult: null,
  labVpa: 'demo-shop@csbank',
  labPayee: 'Cyber Shield Demo Store',
  labAmount: '500',
  labNote: 'Order payment',
  labRef: generateOrderRef(),
  labLoading: false,
  labError: '',
  labOrder: null,
  labTamperMode: 'clean',
  labVerifyResult: null,
  labClockHandle: null,
  // Tab 3 (After)
  evStatus: 'completed',
  evRrn: '',
  evVpa: '',
  evName: '',
  evAmount: '',
  evTimestamp: new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16),
  evApp: '',
  evNotes: '',
  evError: '',
  evBundle: null,
  evVerifyJsonText: '',
  evVerifyResult: null,
  trail: readStoredTrail(),
  tamperedIndex: null,
  tab3Loading: false,
  tab3Message: '',
  trailCheckResult: null
};

// ── Storage helpers (try/catch, key prefixed with "uss.") ───────────────────

function readStoredTrail() {
  try {
    const raw = localStorage.getItem(TRAIL_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function writeStoredTrail(trail) {
  try {
    localStorage.setItem(TRAIL_STORAGE_KEY, JSON.stringify(trail));
  } catch {
    // ignore storage limits
  }
}

// ── DOM & Base64url helpers ───────────────────────────────────────────────

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function encodeBase64UrlUtf8(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64UrlUtf8(b64u) {
  let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

function buildTamperedPayload(originalPayload, newAmountRupeesStr) {
  const canonical = decodeBase64UrlUtf8(originalPayload);
  const parts = canonical.split('|');
  if (parts.length !== 7) return originalPayload;
  const newRupees = Number(newAmountRupeesStr);
  if (!Number.isFinite(newRupees) || newRupees <= 0) return originalPayload;
  const newPaise = Math.round(newRupees * 100);
  parts[3] = String(newPaise);
  return encodeBase64UrlUtf8(parts.join('|'));
}

async function apiJson(url, options) {
  const res = await fetch(url, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

async function loadMerchants() {
  try {
    const list = await apiJson('/api/verify/merchants', { method: 'GET' });
    if (Array.isArray(list) && list.length > 0) {
      state.merchants = list;
      state.merchantsLoaded = true;
      if (!list.some((m) => m.id === state.selectedMerchantId)) {
        state.selectedMerchantId = list[0].id;
      }
    }
  } catch {
    state.merchantsLoaded = false;
  }
}

// ── Tab 1: Before payment (Receiver Verification) ─────────────────────────

async function runReceiverVerify(upiOverride, nameOverride) {
  const upi = (upiOverride !== undefined ? upiOverride : state.upiInput).trim();
  const name = (nameOverride !== undefined ? nameOverride : state.nameInput).trim();
  state.upiInput = upi;
  state.nameInput = name;

  if (!upi) {
    state.tab1Error = t('verify.tab1.upiRequired');
    state.tab1Result = null;
    render();
    return;
  }

  state.tab1Loading = true;
  state.tab1Error = '';
  render();

  try {
    state.tab1Result = await apiJson('/api/verify/receiver', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ upiId: upi, name: name || null })
    });
  } catch (err) {
    state.tab1Error = err.message;
    state.tab1Result = null;
  } finally {
    state.tab1Loading = false;
    render();
  }
}

function buildHonestyCard(badgeKey, titleKey, bodyKey) {
  const card = el('div', 'verify-honesty-card');
  card.setAttribute('role', 'note');
  card.appendChild(el('span', 'verify-honesty-badge', t(`verify.honesty.${badgeKey}`)));
  card.appendChild(el('h3', 'verify-honesty-title', t(`verify.honesty.${titleKey}`)));
  card.appendChild(el('p', 'verify-honesty-body', t(`verify.honesty.${bodyKey}`)));
  return card;
}

function stopCameraScan(shouldRender = false) {
  if (state.camTimer) {
    clearTimeout(state.camTimer);
    state.camTimer = null;
  }
  if (state.camRaf) {
    cancelAnimationFrame(state.camRaf);
    state.camRaf = null;
  }
  if (state.camStream) {
    state.camStream.getTracks().forEach((tr) => { try { tr.stop(); } catch {} });
    state.camStream = null;
  }
  state.camActive = false;
  if (shouldRender) render();
}

function inspectUpiText(rawText) {
  const input = (rawText !== undefined ? String(rawText) : state.qrUriInput).trim();
  state.qrUriInput = input;
  state.qrWebLink = '';
  state.qrPlainText = '';

  const parsed = parseUpiUri(input);
  if (parsed) {
    state.qrError = '';
    state.qrResult = analyzeUpiFields(parsed, state.qrExpectedAmount);
    state.qrRegistryResult = lookupDemoRegistry(parsed);
    render();
    return;
  }

  const webCheck = validateDestinationUrl(input);
  if (webCheck.valid) {
    state.qrError = '';
    state.qrResult = null;
    state.qrRegistryResult = null;
    state.qrWebLink = webCheck.url;
    render();
    return;
  }

  if (input && rawText !== undefined) {
    state.qrError = '';
    state.qrResult = null;
    state.qrRegistryResult = null;
    state.qrPlainText = input;
    render();
    return;
  }

  state.qrError = t('verify.qr.invalidUri');
  state.qrResult = null;
  state.qrRegistryResult = null;
  render();
}

let cachedBarcodeDetector = null;
let barcodeDetectorChecked = false;

function getQrBarcodeDetector() {
  if (barcodeDetectorChecked) return cachedBarcodeDetector;
  barcodeDetectorChecked = true;
  if (typeof window !== 'undefined' && 'BarcodeDetector' in window) {
    try {
      cachedBarcodeDetector = new window.BarcodeDetector({ formats: ['qr_code'] });
    } catch {
      cachedBarcodeDetector = null;
    }
  }
  return cachedBarcodeDetector;
}

function drawScaledSource(source, srcW, srcH, maxDim, boostContrast = false) {
  const scale = maxDim && Math.max(srcW, srcH) > maxDim
    ? maxDim / Math.max(srcW, srcH)
    : 1;
  const w = Math.max(1, Math.round(srcW * scale));
  const h = Math.max(1, Math.round(srcH * scale));
  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.drawImage(source, 0, 0, w, h);

  if (boostContrast) {
    const imgData = ctx.getImageData(0, 0, w, h);
    const d = imgData.data;
    for (let i = 0; i < d.length; i += 4) {
      const lum = 0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2];
      const v = lum < 128 ? Math.max(0, lum * 0.5) : Math.min(255, 128 + (lum - 128) * 1.6);
      d[i] = v;
      d[i + 1] = v;
      d[i + 2] = v;
    }
    ctx.putImageData(imgData, 0, 0);
  }
  return { canvas, ctx, w, h };
}

async function decodeCanvasPixels(source, width, height, maxDim = 800, boostContrast = false) {
  if (!width || !height) return false;
  const { canvas, ctx, w, h } = drawScaledSource(source, width, height, maxDim, boostContrast);

  const detector = getQrBarcodeDetector();
  if (detector) {
    try {
      const codes = await detector.detect(canvas);
      const hit = Array.isArray(codes) ? codes.find((c) => c && c.rawValue) : null;
      if (hit && hit.rawValue) {
        stopCameraScan(false);
        inspectUpiText(hit.rawValue);
        return true;
      }
    } catch {
      // Fall back cleanly to local jsQR
    }
  }

  if (typeof window.jsQR !== 'function') {
    return false;
  }
  const imgData = ctx.getImageData(0, 0, w, h);
  const decoded = window.jsQR(imgData.data, w, h, { inversionAttempts: 'attemptBoth' });
  if (decoded && decoded.data) {
    stopCameraScan(false);
    inspectUpiText(decoded.data);
    return true;
  }
  return false;
}

async function decodeWithRetries(source, w, h) {
  const passes = [
    [1200, false],
    [1000, false],
    [600, false],
    [1000, true]
  ];
  for (const [maxDim, boost] of passes) {
    if (await decodeCanvasPixels(source, w, h, maxDim, boost)) {
      return true;
    }
  }
  return false;
}

async function decodeQrImageFile(file) {
  if (!file) return;
  if (typeof createImageBitmap === 'function') {
    let bitmap = null;
    try {
      bitmap = await createImageBitmap(file);
      const ok = await decodeWithRetries(bitmap, bitmap.width, bitmap.height);
      if (ok) return;
    } catch {
      // Fall through to FileReader fallback or error message
    } finally {
      if (bitmap && typeof bitmap.close === 'function') bitmap.close();
    }
  }

  // Fallback for environments where createImageBitmap fails on a specific image type (never uses blob:)
  await new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = () => {
      const img = new Image();
      img.onload = async () => {
        const ok = await decodeWithRetries(img, img.naturalWidth || img.width, img.naturalHeight || img.height);
        if (!ok) {
          state.qrError = t('verify.qr.noQrFound');
          state.qrResult = null;
          state.qrWebLink = '';
          state.qrPlainText = '';
          render();
        }
        resolve();
      };
      img.onerror = () => {
        state.qrError = t('verify.qr.noQrFound');
        state.qrResult = null;
        state.qrWebLink = '';
        state.qrPlainText = '';
        render();
        resolve();
      };
      img.src = String(reader.result || '');
    };
    reader.onerror = () => {
      state.qrError = t('verify.qr.noQrFound');
      state.qrResult = null;
      state.qrWebLink = '';
      state.qrPlainText = '';
      render();
      resolve();
    };
    reader.readAsDataURL(file);
  });
}

async function decodeSampleQrImg(imgEl) {
  if (!imgEl) return;
  try {
    if (!imgEl.complete && typeof imgEl.decode === 'function') {
      await imgEl.decode();
    }
    const w = imgEl.naturalWidth || imgEl.width;
    const h = imgEl.naturalHeight || imgEl.height;
    if (!w || !h || !(await decodeCanvasPixels(imgEl, w, h, 800, false))) {
      state.qrError = t('verify.qr.noQrFound');
      state.qrResult = null;
      render();
    }
  } catch {
    state.qrError = t('verify.qr.noQrFound');
    state.qrResult = null;
    render();
  }
}

function waitForLoadedMetadata(videoEl) {
  if (videoEl.readyState >= 1 && videoEl.videoWidth > 0) return Promise.resolve();
  return new Promise((resolve) => {
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      videoEl.removeEventListener('loadedmetadata', finish);
      resolve();
    };
    videoEl.addEventListener('loadedmetadata', finish, { once: true });
    setTimeout(finish, 2000);
  });
}

async function startCameraScan() {
  if (!window.isSecureContext) {
    state.camNotice = t('verify.qr.camNeedHttps');
    state.camActive = false;
    render();
    return;
  }
  if (!navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== 'function') {
    state.camNotice = t('verify.qr.camUnavailable');
    state.camActive = false;
    render();
    return;
  }
  state.camNotice = '';
  state.qrError = '';
  try {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' } },
      audio: false
    });
    state.camStream = stream;
    state.camActive = true;
    render();

    const videoEl = document.getElementById('verify-qr-video');
    if (!videoEl) return;
    videoEl.playsInline = true;
    videoEl.setAttribute('playsinline', '');
    videoEl.muted = true;
    videoEl.srcObject = stream;
    await waitForLoadedMetadata(videoEl);
    await videoEl.play().catch(() => {});

    let decodingFrame = false;
    const scanTick = async () => {
      if (!state.camActive || !state.camStream) return;
      if (!decodingFrame && videoEl.readyState >= 2 && videoEl.videoWidth > 0 && videoEl.videoHeight > 0) {
        decodingFrame = true;
        try {
          const hit = await decodeCanvasPixels(videoEl, videoEl.videoWidth, videoEl.videoHeight, 800, false);
          if (hit) return;
        } finally {
          decodingFrame = false;
        }
      }
      if (state.camActive) {
        state.camTimer = setTimeout(() => {
          state.camRaf = requestAnimationFrame(scanTick);
        }, 100);
      }
    };
    state.camTimer = setTimeout(() => {
      state.camRaf = requestAnimationFrame(scanTick);
    }, 100);
  } catch (err) {
    stopCameraScan(false);
    const name = err && err.name ? err.name : '';
    if (name === 'NotAllowedError' || name === 'PermissionDeniedError') {
      state.camNotice = t('verify.qr.camDenied');
    } else if (name === 'NotFoundError' || name === 'DevicesNotFoundError') {
      state.camNotice = t('verify.qr.camNoDevice');
    } else {
      state.camNotice = t('verify.qr.camUnavailable');
    }
    render();
  }
}

function renderQrInspector(panel) {
  const box = el('div', 'verify-qr-inspector');
  box.appendChild(el('h3', 'verify-qr-inspector-title', t('verify.qr.heading')));
  box.appendChild(el('p', 'verify-tab-explainer', t('verify.qr.sub')));

  // Paste image / UPI text handler inside Tab 1 inspector
  box.addEventListener('paste', (e) => {
    const items = e.clipboardData?.items;
    if (items) {
      for (const item of items) {
        if (item.type && item.type.startsWith('image/')) {
          const blob = item.getAsFile();
          if (blob) {
            e.preventDefault();
            decodeQrImageFile(blob);
            return;
          }
        }
      }
    }
    const pastedText = e.clipboardData?.getData('text') || '';
    if (/upi:\/\/pay/i.test(pastedText)) {
      e.preventDefault();
      inspectUpiText(pastedText);
    }
  });

  // 1. "Try a sample" buttons backed by static PNG files generated with qrcode
  const samplesRow = el('div', 'verify-qr-samples');
  samplesRow.appendChild(el('span', 'verify-samples-lbl', t('verify.qr.samplesLabel')));
  const sampleDefs = [
    { key: 'sampleClean', src: 'samples/qr/clean-shop.png' },
    { key: 'sampleBait', src: 'samples/qr/bait-word.png' },
    { key: 'sampleBlank', src: 'samples/qr/amount-blank.png' }
  ];
  for (const s of sampleDefs) {
    const btn = el('button', 'verify-chip verify-qr-sample-btn');
    btn.type = 'button';
    const thumb = document.createElement('img');
    thumb.src = s.src;
    thumb.alt = '';
    thumb.className = 'verify-qr-sample-thumb';
    btn.appendChild(thumb);
    btn.appendChild(document.createTextNode(t(`verify.qr.${s.key}`)));
    btn.addEventListener('click', () => decodeSampleQrImg(thumb));
    samplesRow.appendChild(btn);
  }
  box.appendChild(samplesRow);

  // 1b. Demo Bank (fictional) quick-fill cases: match, mismatch, unknown
  const demoRow = el('div', 'verify-samples-row');
  demoRow.appendChild(el('span', 'verify-samples-lbl', t('verify.qr.demoLookupLabel')));
  const demoCases = [
    { key: 'demoMatchChip', uri: 'upi://pay?pa=demo-shop@csbank&pn=Cyber%20Shield%20Demo%20Store&am=499.00&cu=INR&tr=CS101&tn=Shop%20order' },
    { key: 'demoMismatchChip', uri: 'upi://pay?pa=qwe978xyz@ybl&pn=Zomato%20Outlet&am=320.00&cu=INR&tr=ZM902&tn=Order%20bill' },
    { key: 'demoUnknownChip', uri: 'upi://pay?pa=unknownshop@okicici&pn=Local%20Vendor&am=150.00&cu=INR&tr=LV12' }
  ];
  for (const dc of demoCases) {
    const chip = el('button', 'verify-chip', t(`verify.qr.${dc.key}`));
    chip.type = 'button';
    chip.addEventListener('click', () => inspectUpiText(dc.uri));
    demoRow.appendChild(chip);
  }
  box.appendChild(demoRow);

  // 2. Camera scan + image upload controls
  const actionsRow = el('div', 'verify-qr-controls');
  const camBtn = el('button', 'learn-btn-secondary', t(state.camActive ? 'verify.qr.camStop' : 'verify.qr.camStart'));
  camBtn.type = 'button';
  camBtn.addEventListener('click', () => {
    if (state.camActive) stopCameraScan(true);
    else startCameraScan();
  });
  actionsRow.appendChild(camBtn);

  const fileLabel = el('label', 'verify-chip verify-file-label', t('verify.qr.uploadLabel'));
  const fileInput = document.createElement('input');
  fileInput.type = 'file';
  fileInput.accept = 'image/*';
  fileInput.className = 'verify-file-input';
  fileInput.addEventListener('change', (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) decodeQrImageFile(f);
    e.target.value = '';
  });
  fileLabel.appendChild(fileInput);
  actionsRow.appendChild(fileLabel);
  box.appendChild(actionsRow);

  box.appendChild(el('p', 'verify-paste-hint', t('verify.qr.pasteZoneHint')));

  if (state.camNotice) {
    box.appendChild(el('div', 'verify-inline-note verify-cam-fallback', state.camNotice));
  }

  if (state.camActive) {
    const camBox = el('div', 'verify-cam-preview');
    const video = document.createElement('video');
    video.id = 'verify-qr-video';
    video.setAttribute('playsinline', '');
    video.muted = true;
    video.className = 'verify-qr-video';
    camBox.appendChild(video);
    box.appendChild(camBox);
  }

  // 3. Pasted UPI link text + Optional expected amount form
  const form = el('form', 'verify-form');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    inspectUpiText();
  });

  const grid = el('div', 'verify-input-grid');

  const uriField = el('div', 'verify-field');
  const uriLbl = el('label', 'verify-label', t('verify.qr.uriLabel'));
  uriLbl.setAttribute('for', 'verify-qr-uri-input');
  const uriInp = el('input', 'verify-input');
  uriInp.id = 'verify-qr-uri-input';
  uriInp.type = 'text';
  uriInp.placeholder = t('verify.qr.uriPlaceholder');
  uriInp.value = state.qrUriInput;
  uriInp.maxLength = 600;
  uriInp.addEventListener('input', (e) => { state.qrUriInput = e.target.value; });
  uriField.appendChild(uriLbl);
  uriField.appendChild(uriInp);

  const expField = el('div', 'verify-field');
  const expLbl = el('label', 'verify-label', t('verify.qr.expectedLabel'));
  expLbl.setAttribute('for', 'verify-qr-expected-input');
  const expInp = el('input', 'verify-input');
  expInp.id = 'verify-qr-expected-input';
  expInp.type = 'number';
  expInp.step = '0.01';
  expInp.min = '0.01';
  expInp.placeholder = t('verify.qr.expectedPlaceholder');
  expInp.value = state.qrExpectedAmount;
  expInp.addEventListener('input', (e) => {
    state.qrExpectedAmount = e.target.value;
    if (state.qrResult && state.qrResult.parsed) {
      state.qrResult = analyzeUpiFields(state.qrResult.parsed, state.qrExpectedAmount);
    }
  });
  expInp.addEventListener('change', () => {
    if (state.qrResult && state.qrResult.parsed) render();
  });
  expField.appendChild(expLbl);
  expField.appendChild(expInp);

  grid.appendChild(uriField);
  grid.appendChild(expField);
  form.appendChild(grid);

  const inspectBtn = el('button', 'learn-btn-primary', t('verify.qr.inspectBtn'));
  inspectBtn.type = 'submit';
  form.appendChild(inspectBtn);
  box.appendChild(form);

  if (state.qrError) {
    box.appendChild(el('div', 'verify-error-box', state.qrError));
  }

  if (state.qrWebLink) {
    const webBox = el('div', 'verify-qr-output');
    webBox.appendChild(el('h4', 'verify-qr-subhead', t('verify.qr.webLinkTitle')));
    webBox.appendChild(el('p', 'verify-qr-plain-text', state.qrWebLink));
    const linkBtn = el('a', 'learn-btn-primary go-btn-link', t('verify.qr.checkWebLinkBtn'));
    linkBtn.href = buildProtectedLink(state.qrWebLink);
    webBox.appendChild(linkBtn);
    box.appendChild(webBox);
  } else if (state.qrPlainText) {
    const plainBox = el('div', 'verify-qr-output');
    plainBox.appendChild(el('h4', 'verify-qr-subhead', t('verify.qr.plainTextTitle')));
    plainBox.appendChild(el('p', 'verify-qr-plain-text', state.qrPlainText));
    box.appendChild(plainBox);
  }

  // 4. Decoded fields + flags + "What to do now"
  if (state.qrResult) {
    const { parsed, flags, cleanMessage, guidance } = state.qrResult;
    const out = el('div', 'verify-qr-output');

    out.appendChild(el('h4', 'verify-qr-subhead', t('verify.qr.fieldsTitle')));
    const fieldsGrid = el('div', 'verify-qr-fields-grid');
    const fieldSpecs = [
      ['fieldPa', parsed.pa],
      ['fieldPn', parsed.pn],
      ['fieldAm', parsed.am ? `${parsed.cu || 'INR'} ${parsed.am}` : ''],
      ['fieldCu', parsed.cu],
      ['fieldTn', parsed.tn],
      ['fieldTr', parsed.tr],
      ['fieldMc', parsed.mc],
      ['fieldMode', parsed.mode]
    ];
    for (const [lblKey, val] of fieldSpecs) {
      const fCard = el('div', `verify-qr-field-card${!val ? ' is-blank' : ''}`);
      fCard.appendChild(el('span', 'verify-qr-field-lbl', t(`verify.qr.${lblKey}`)));
      fCard.appendChild(el('strong', 'verify-qr-field-val', val || t('verify.qr.missingValue')));
      fieldsGrid.appendChild(fCard);
    }
    out.appendChild(fieldsGrid);

    out.appendChild(el('h4', 'verify-qr-subhead', t('verify.qr.flagsTitle')));
    if (flags.length === 0) {
      const cleanCard = el('div', 'verify-verdict-card status-verified');
      cleanCard.appendChild(el('p', 'verify-verdict-reason', cleanMessage));
      out.appendChild(cleanCard);
    } else {
      const flagsList = el('ul', 'verify-qr-flags-list');
      for (const fl of flags) {
        const li = el('li', 'verify-qr-flag-item');
        li.appendChild(el('strong', 'verify-qr-flag-title', fl.title));
        li.appendChild(el('p', 'verify-qr-flag-why', fl.why));
        flagsList.appendChild(li);
      }
      out.appendChild(flagsList);
    }

    const todoBox = el('div', 'verify-qr-todo');
    todoBox.appendChild(el('h4', 'verify-qr-subhead', t('verify.qr.whatToDoTitle')));
    const ul = el('ul', 'verify-qr-todo-list');
    for (const step of guidance) {
      ul.appendChild(el('li', '', step));
    }
    todoBox.appendChild(ul);
    out.appendChild(todoBox);

    // 5. Auto Demo Bank (fictional) VPA registry lookup + honest CAN/CANNOT card
    const reg = state.qrRegistryResult || lookupDemoRegistry(parsed);
    const statusCls = reg.status === 'MATCH'
      ? 'status-verified'
      : reg.status === 'MISMATCH'
        ? 'status-tampered'
        : 'status-lookalike';
    const regCard = el('div', `verify-verdict-card verify-registry-card ${statusCls}`);
    const regHeader = el('p', 'verify-registry-head');
    regHeader.appendChild(document.createTextNode(`${t('verify.qr.registryHeading')} `));
    regHeader.appendChild(el('strong', '', reg.registeredName || t('verify.qr.registryNotListed')));
    regCard.appendChild(regHeader);

    if (reg.missingPn) {
      regCard.appendChild(el('p', 'verify-registry-missing-pn', t('verify.qr.registryMissingPn')));
    }

    if (reg.status === 'MATCH') {
      regCard.appendChild(el('strong', 'verify-verdict-badge', t('verify.qr.registryMatchTitle')));
      regCard.appendChild(el('p', 'verify-verdict-reason', t('verify.qr.registryMatchNote')));
    } else if (reg.status === 'MISMATCH') {
      regCard.appendChild(el('strong', 'verify-verdict-badge', t('verify.qr.registryMismatchBadge')));
      const mismatchLine = el('p', 'verify-verdict-reason verify-mismatch-line');
      mismatchLine.appendChild(document.createTextNode('QR claims '));
      mismatchLine.appendChild(el('mark', 'verify-name-highlight', reg.qrPn));
      mismatchLine.appendChild(document.createTextNode(' but Demo Bank registers '));
      mismatchLine.appendChild(el('mark', 'verify-name-highlight', reg.registeredName));
      mismatchLine.appendChild(document.createTextNode(' — do not pay.'));
      regCard.appendChild(mismatchLine);
    } else {
      regCard.appendChild(el('p', 'verify-verdict-reason', t('verify.qr.registryUnknownNote')));
    }
    out.appendChild(regCard);

    const honestCard = el('div', 'verify-qr-honest-limits');
    honestCard.appendChild(el('span', 'verify-honesty-badge', t('verify.qr.honestBankTag')));
    const hGrid = el('div', 'verify-limits-grid');
    const c1 = el('div', 'verify-limit-col can-col');
    c1.appendChild(el('h4', 'verify-limit-head', t('verify.qr.honestCanLbl')));
    c1.appendChild(el('p', 'verify-limit-body', t('verify.qr.honestCanText')));
    const c2 = el('div', 'verify-limit-col cannot-col');
    c2.appendChild(el('h4', 'verify-limit-head', t('verify.qr.honestCannotLbl')));
    c2.appendChild(el('p', 'verify-limit-body', t('verify.qr.honestCannotText')));
    hGrid.appendChild(c1);
    hGrid.appendChild(c2);
    honestCard.appendChild(hGrid);
    out.appendChild(honestCard);

    box.appendChild(out);
  }

  panel.appendChild(box);
}

function renderTab1(panel) {
  panel.appendChild(buildHonestyCard('beforeBadge', 'beforeTitle', 'beforeBody'));
  renderQrInspector(panel);
  if (!state.merchantsLoaded) return;
  panel.appendChild(el('p', 'verify-tab-explainer', t('verify.tab1.explainer')));

  // Example chips
  const samplesRow = el('div', 'verify-samples-row');
  samplesRow.appendChild(el('span', 'verify-samples-lbl', t('verify.tab1.samplesLabel')));

  const examples = [
    { key: 'sampleVerified', upi: 'ravi@demobank', name: 'Ravi Stores' },
    { key: 'sampleMismatch', upi: 'ravi@demobank', name: 'Ramesh Traders' },
    { key: 'sampleLookalike', upi: 'ravl@demobank', name: '' },
    { key: 'sampleUnknown', upi: 'randomshop@otherbank', name: '' }
  ];

  for (const ex of examples) {
    const chip = el('button', 'verify-chip', t(`verify.tab1.${ex.key}`));
    chip.type = 'button';
    chip.addEventListener('click', () => runReceiverVerify(ex.upi, ex.name));
    samplesRow.appendChild(chip);
  }
  panel.appendChild(samplesRow);

  // Inputs
  const form = el('form', 'verify-form');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    runReceiverVerify();
  });

  const grid = el('div', 'verify-input-grid');

  const upiField = el('div', 'verify-field');
  const upiLbl = el('label', 'verify-label', t('verify.tab1.upiLabel'));
  upiLbl.setAttribute('for', 'verify-upi-input');
  const upiInp = el('input', 'verify-input');
  upiInp.id = 'verify-upi-input';
  upiInp.type = 'text';
  upiInp.placeholder = t('verify.tab1.upiPlaceholder');
  upiInp.value = state.upiInput;
  upiInp.maxLength = 120;
  upiInp.addEventListener('input', (e) => { state.upiInput = e.target.value; });
  upiField.appendChild(upiLbl);
  upiField.appendChild(upiInp);

  const nameField = el('div', 'verify-field');
  const nameLbl = el('label', 'verify-label', t('verify.tab1.nameLabel'));
  nameLbl.setAttribute('for', 'verify-name-input');
  const nameInp = el('input', 'verify-input');
  nameInp.id = 'verify-name-input';
  nameInp.type = 'text';
  nameInp.placeholder = t('verify.tab1.namePlaceholder');
  nameInp.value = state.nameInput;
  nameInp.maxLength = 120;
  nameInp.addEventListener('input', (e) => { state.nameInput = e.target.value; });
  nameField.appendChild(nameLbl);
  nameField.appendChild(nameInp);

  grid.appendChild(upiField);
  grid.appendChild(nameField);
  form.appendChild(grid);

  const submitBtn = el('button', 'learn-btn-primary', t('verify.tab1.verifyBtn'));
  submitBtn.type = 'submit';
  submitBtn.disabled = state.tab1Loading;
  form.appendChild(submitBtn);
  panel.appendChild(form);

  if (state.tab1Error) {
    panel.appendChild(el('p', 'verify-inline-error', state.tab1Error));
  }

  if (state.tab1Result) {
    const res = state.tab1Result;
    const status = res.status || 'UNKNOWN';
    const card = el('div', `verify-verdict-card status-${status.toLowerCase()}`);
    card.appendChild(el('span', 'verify-verdict-badge', t(`verify.tab1.verdicts.${status}`)));
    card.appendChild(el('p', 'verify-verdict-desc', t(`verify.tab1.verdictDesc.${status}`)));
    if (res.reason) {
      card.appendChild(el('p', 'verify-verdict-reason', res.reason));
    }
    if (res.closestMatch) {
      card.appendChild(
        el('p', 'verify-verdict-match', `${t('verify.tab1.closestLabel')} ${res.closestMatch.name} (${res.closestMatch.upiId})`)
      );
    }
    panel.appendChild(card);
  }
}

// ── Tab 2: During payment (Signed QR & Tamper Check) ──────────────────────

async function generateSignedQr() {
  const num = Number(state.amountInput);
  if (!Number.isFinite(num) || num < 0.01 || num > 100000) {
    state.tab2Error = t('verify.tab2.invalidAmount');
    render();
    return;
  }

  state.tab2Loading = true;
  state.tab2Error = '';
  state.tamperCheckResult = null;
  render();

  try {
    const data = await apiJson('/api/verify/qr', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        merchantId: state.selectedMerchantId,
        amountRupees: Number(num.toFixed(2))
      })
    });
    state.qrData = data;
    // Pre-populate Try-It-Yourself field to demonstrate amount tampering (e.g. 500 -> 5000)
    state.tamperAmountInput = Number(data.amountRupees) === 500 ? '5000' : String(Number(data.amountRupees) * 10);
  } catch (err) {
    state.tab2Error = err.message;
  } finally {
    state.tab2Loading = false;
    render();
  }
}

async function runTamperCheck() {
  if (!state.qrData) return;
  const num = Number(state.tamperAmountInput);
  if (!Number.isFinite(num) || num < 0.01 || num > 100000) {
    state.tab2Error = t('verify.tab2.invalidAmount');
    render();
    return;
  }

  state.tamperCheckLoading = true;
  state.tab2Error = '';
  render();

  try {
    const editedPaise = Math.round(num * 100);
    const payloadToSend = editedPaise === state.qrData.amountPaise
      ? state.qrData.payload
      : buildTamperedPayload(state.qrData.payload, num.toFixed(2));

    const checkResult = await apiJson('/api/verify/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        payload: payloadToSend,
        signature: state.qrData.signature
      })
    });

    state.tamperCheckResult = {
      checkResult,
      originalRupees: `Rs.${Number(state.qrData.amountRupees).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`,
      receivedRupees: `Rs.${num.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`
    };
  } catch (err) {
    state.tab2Error = err.message;
  } finally {
    state.tamperCheckLoading = false;
    render();
  }
}

function stopLabCountdown() {
  if (state.labClockHandle) {
    clearInterval(state.labClockHandle);
    state.labClockHandle = null;
  }
}

function formatCountdownText(expiresAtMs) {
  const remMs = Math.max(0, Number(expiresAtMs || 0) - Date.now());
  if (remMs <= 0) return t('verify.tab2.lab.expiredClock');
  const totalSec = Math.ceil(remMs / 1000);
  const mm = String(Math.floor(totalSec / 60)).padStart(2, '0');
  const ss = String(totalSec % 60).padStart(2, '0');
  return `${t('verify.tab2.lab.signedPrefix')}${mm}:${ss}`;
}

function startLabCountdown() {
  stopLabCountdown();
  if (!state.labOrder || !state.labOrder.expiresAt) return;
  state.labClockHandle = setInterval(() => {
    const elNode = document.getElementById('verify-lab-countdown');
    if (elNode && state.labOrder) {
      elNode.textContent = formatCountdownText(state.labOrder.expiresAt);
    }
  }, 1000);
}

async function submitLabOrder() {
  state.labLoading = true;
  state.labError = '';
  state.labTamperMode = 'clean';
  state.labVerifyResult = null;
  stopLabCountdown();
  render();

  try {
    const order = await createPayOrder({
      receiverVpa: state.labVpa,
      payeeName: state.labPayee,
      amount: state.labAmount,
      note: state.labNote,
      ref: state.labRef
    });
    state.labOrder = order;
    state.labVerifyResult = await verifyPayOrderToken(order.token, { demoMode: order.demoMode });
    startLabCountdown();
  } catch (err) {
    state.labError = err.message || 'Unable to create signed order.';
  } finally {
    state.labLoading = false;
    render();
  }
}

async function applyLabTamperToggle(mode) {
  if (!state.labOrder) return;
  state.labTamperMode = mode;
  state.labLoading = true;
  state.labError = '';
  render();

  try {
    const isExpire = mode === 'expire';
    const token = buildTamperedToken(state.labOrder, isExpire ? 'clean' : mode);
    state.labVerifyResult = await verifyPayOrderToken(token, {
      demoMode: state.labOrder.demoMode,
      forceExpired: isExpire
    });
  } catch (err) {
    state.labError = err.message || 'Verification failed.';
  } finally {
    state.labLoading = false;
    render();
  }
}

function renderTab2(panel) {
  panel.appendChild(buildHonestyCard('whileBadge', 'whileTitle', 'whileBody'));

  // Interactive Tamper Lab (works with backend OR offline Web Crypto fallback)
  const labBox = el('div', 'verify-tamper-lab');
  labBox.appendChild(el('h3', 'verify-qr-inspector-title', t('verify.tab2.lab.heading')));
  labBox.appendChild(el('p', 'verify-tab-explainer', t('verify.tab2.lab.sub')));

  const form = el('form', 'verify-form');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    submitLabOrder();
  });

  const grid = el('div', 'verify-input-grid');
  const fields = [
    { id: 'lab-vpa', key: 'vpaLabel', prop: 'labVpa', type: 'text' },
    { id: 'lab-payee', key: 'payeeLabel', prop: 'labPayee', type: 'text' },
    { id: 'lab-amt', key: 'amountLabel', prop: 'labAmount', type: 'number', step: '0.01', min: '0.01' },
    { id: 'lab-note', key: 'noteLabel', prop: 'labNote', type: 'text' },
    { id: 'lab-ref', key: 'refLabel', prop: 'labRef', type: 'text' }
  ];
  for (const f of fields) {
    const wrap = el('div', 'verify-field');
    const lbl = el('label', 'verify-label', t(`verify.tab2.lab.${f.key}`));
    lbl.setAttribute('for', f.id);
    const inp = el('input', 'verify-input');
    inp.id = f.id;
    inp.type = f.type;
    if (f.step) inp.step = f.step;
    if (f.min) inp.min = f.min;
    inp.value = state[f.prop];
    inp.addEventListener('input', (e) => { state[f.prop] = e.target.value; });
    wrap.appendChild(lbl);
    wrap.appendChild(inp);
    grid.appendChild(wrap);
  }
  form.appendChild(grid);

  const createBtn = el('button', 'learn-btn-primary', t('verify.tab2.lab.createBtn'));
  createBtn.type = 'submit';
  createBtn.disabled = state.labLoading;
  form.appendChild(createBtn);
  labBox.appendChild(form);

  if (state.labError) {
    labBox.appendChild(el('div', 'verify-error-box', state.labError));
  }

  if (state.labOrder) {
    const order = state.labOrder;
    const isDemo = Boolean(order.demoMode || state.labVerifyResult?.demoMode);
    if (isDemo) {
      labBox.appendChild(el('div', 'verify-lab-demo-banner', t('verify.tab2.lab.demoBanner')));
    }

    const countdownP = el('p', 'verify-lab-countdown', formatCountdownText(order.expiresAt));
    countdownP.id = 'verify-lab-countdown';
    labBox.appendChild(countdownP);

    const qrLayout = el('div', 'verify-qr-result');
    const qrVisual = el('div', 'verify-qr-visual');
    if (order.qrPngBase64) {
      const img = document.createElement('img');
      img.className = 'verify-qr-img';
      img.src = `data:image/png;base64,${order.qrPngBase64}`;
      img.alt = 'Demo Bank signed QR';
      img.width = 210;
      img.height = 210;
      qrVisual.appendChild(img);
    } else {
      const offlineBox = el('div', 'verify-lab-token-card');
      offlineBox.appendChild(el('span', 'verify-demo-pill', t('verify.demoNoMoney')));
      offlineBox.appendChild(el('code', 'verify-link-code', order.token));
      qrVisual.appendChild(offlineBox);
    }

    const payloadBox = el('div', 'verify-qr-info');
    payloadBox.appendChild(el('h4', 'verify-qr-subhead', t('verify.tab2.lab.payloadTitle')));
    const pGrid = el('div', 'verify-qr-fields-grid');
    const p = order.payload;
    for (const [k, v] of [['pa', p.pa], ['pn', p.pn], ['am', `INR ${p.am}`], ['tr', p.tr], ['tn', p.tn], ['ts', String(p.ts)]]) {
      const card = el('div', 'verify-qr-field-card');
      card.appendChild(el('span', 'verify-qr-field-lbl', k));
      card.appendChild(el('strong', 'verify-qr-field-val', v || '—'));
      pGrid.appendChild(card);
    }
    payloadBox.appendChild(pGrid);

    qrLayout.appendChild(qrVisual);
    qrLayout.appendChild(payloadBox);
    labBox.appendChild(qrLayout);

    // Tamper simulation toggles
    const toggleWrap = el('div', 'verify-lab-toggles');
    toggleWrap.appendChild(el('p', 'verify-try-hint', t('verify.tab2.lab.togglesTitle')));
    const btnRow = el('div', 'verify-samples-row');
    const toggleDefs = [
      { mode: 'clean', key: 'toggleClean' },
      { mode: 'swap_vpa', key: 'toggleSwapVpa' },
      { mode: 'change_amount', key: 'toggleAmount' },
      { mode: 'alter_ts', key: 'toggleTimestamp' },
      { mode: 'expire', key: 'toggleExpire' }
    ];
    for (const td of toggleDefs) {
      const btn = el('button', `verify-chip${state.labTamperMode === td.mode ? ' is-selected' : ''}`, t(`verify.tab2.lab.${td.key}`));
      btn.type = 'button';
      btn.disabled = state.labLoading;
      btn.addEventListener('click', () => applyLabTamperToggle(td.mode));
      btnRow.appendChild(btn);
    }
    toggleWrap.appendChild(btnRow);
    labBox.appendChild(toggleWrap);

    // Result panel (same shape every time: VALID / INVALID / EXPIRED)
    if (state.labVerifyResult) {
      const vr = state.labVerifyResult;
      const isExpired = !vr.valid && vr.reason === 'expired';
      const cardCls = vr.valid ? 'status-verified' : isExpired ? 'status-lookalike' : 'status-tampered';
      const resCard = el('div', `verify-verdict-card verify-lab-result ${cardCls}`);

      if (vr.valid) {
        resCard.appendChild(el('strong', 'verify-verdict-badge', t('verify.tab2.lab.validTitle')));
        resCard.appendChild(el('p', 'verify-verdict-reason', t('verify.tab2.lab.validBody')));
      } else if (isExpired) {
        resCard.appendChild(el('strong', 'verify-verdict-badge', t('verify.tab2.lab.expiredTitle')));
        resCard.appendChild(el('p', 'verify-verdict-reason', t('verify.tab2.lab.expiredBody')));
      } else {
        resCard.appendChild(el('strong', 'verify-verdict-badge', t('verify.tab2.lab.invalidTitle')));
        resCard.appendChild(el('p', 'verify-verdict-reason', t('verify.tab2.lab.invalidBody')));

        if (Array.isArray(vr.changedFields) && vr.changedFields.length > 0) {
          const tableWrap = el('div', 'verify-table-wrap');
          const table = el('table', 'verify-trail-table verify-diff-table');
          const thead = document.createElement('thead');
          const hr = document.createElement('tr');
          for (const ck of ['colField', 'colOriginal', 'colReceived']) {
            hr.appendChild(el('th', '', t(`verify.tab2.lab.${ck}`)));
          }
          thead.appendChild(hr);
          table.appendChild(thead);

          const tbody = document.createElement('tbody');
          for (const ch of vr.changedFields) {
            const tr = document.createElement('tr');
            tr.className = 'is-broken-row';
            tr.appendChild(el('td', '', ch.field));
            tr.appendChild(el('td', '', ch.original));
            tr.appendChild(el('td', '', ch.received));
            tbody.appendChild(tr);
          }
          table.appendChild(tbody);
          tableWrap.appendChild(table);
          resCard.appendChild(tableWrap);
        }
      }
      labBox.appendChild(resCard);
    }
  }

  panel.appendChild(labBox);

  // Production reality honesty card below the lab
  const prodCard = el('div', 'verify-honesty-card verify-lab-honesty');
  prodCard.setAttribute('role', 'note');
  prodCard.appendChild(el('span', 'verify-honesty-badge', t('verify.tab2.lab.honestyBadge')));
  prodCard.appendChild(el('p', 'verify-honesty-body', t('verify.tab2.lab.honestyBody')));
  panel.appendChild(prodCard);

  if (!state.merchantsLoaded) return;

  // Classic DemoPay Signed QR + Copy link + Tamper amount check (server-connected)
  const demoBox = el('div', 'verify-tamper-lab verify-demopay-box');
  demoBox.appendChild(el('p', 'verify-tab-explainer', t('verify.tab2.explainer')));

  const demoForm = el('form', 'verify-form');
  demoForm.addEventListener('submit', (e) => {
    e.preventDefault();
    generateSignedQr();
  });

  const demoGrid = el('div', 'verify-input-grid');
  const mField = el('div', 'verify-field');
  const mLbl = el('label', 'verify-label', t('verify.tab2.merchantLabel'));
  mLbl.setAttribute('for', 'verify-merchant-select');
  const mSel = el('select', 'verify-input verify-select');
  mSel.id = 'verify-merchant-select';
  for (const m of state.merchants) {
    const opt = el('option', '', `${m.name} (${m.upiId})`);
    opt.value = m.id;
    opt.selected = m.id === state.selectedMerchantId;
    mSel.appendChild(opt);
  }
  mSel.addEventListener('change', (e) => { state.selectedMerchantId = e.target.value; });
  mField.appendChild(mLbl);
  mField.appendChild(mSel);

  const aField = el('div', 'verify-field');
  const aLbl = el('label', 'verify-label', t('verify.tab2.amountLabel'));
  aLbl.setAttribute('for', 'verify-amount-input');
  const aInp = el('input', 'verify-input');
  aInp.id = 'verify-amount-input';
  aInp.type = 'number';
  aInp.step = '0.01';
  aInp.min = '0.01';
  aInp.max = '100000';
  aInp.value = state.amountInput;
  aInp.addEventListener('input', (e) => { state.amountInput = e.target.value; });
  aField.appendChild(aLbl);
  aField.appendChild(aInp);

  demoGrid.appendChild(mField);
  demoGrid.appendChild(aField);
  demoForm.appendChild(demoGrid);

  const genBtn = el('button', 'learn-btn-primary', t('verify.tab2.generateBtn'));
  genBtn.type = 'submit';
  genBtn.disabled = state.tab2Loading;
  demoForm.appendChild(genBtn);
  demoBox.appendChild(demoForm);

  if (state.tab2Error) {
    demoBox.appendChild(el('div', 'verify-error-box', state.tab2Error));
  }

  if (state.qrData) {
    const qr = state.qrData;
    const resolvedLink = resolvePaymentLinkOrigin(qr.paymentLink);

    const qrRes = el('div', 'verify-qr-result');
    const qrVis = el('div', 'verify-qr-visual');
    const qrImg = document.createElement('img');
    qrImg.className = 'verify-qr-img';
    qrImg.src = qr.qrDataUri;
    qrImg.alt = 'DemoPay signed QR';
    qrImg.width = 210;
    qrImg.height = 210;
    qrVis.appendChild(qrImg);

    const qrInfo = el('div', 'verify-qr-info');
    qrInfo.appendChild(el('p', 'verify-seal-line', t('verify.tab2.sealLine')));
    qrInfo.appendChild(el('span', 'verify-qr-field-lbl', t('verify.tab2.linkLabel')));
    qrInfo.appendChild(el('code', 'verify-link-code', resolvedLink));

    const qrActRow = el('div', 'verify-tab3-actions');
    const copyLinkBtn = el('button', 'verify-chip', state.tab2Copied ? t('verify.tab2.copied') : t('verify.tab2.copyBtn'));
    copyLinkBtn.type = 'button';
    copyLinkBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(resolvedLink);
        state.tab2Copied = true;
        render();
        setTimeout(() => { state.tab2Copied = false; render(); }, 1800);
      } catch {
        // ignore clipboard unavailability
      }
    });
    qrActRow.appendChild(copyLinkBtn);

    const custLink = el('a', 'learn-btn-secondary verify-open-customer', t('verify.tab2.openCustomerBtn'));
    custLink.href = resolvedLink;
    custLink.target = '_blank';
    custLink.rel = 'noopener noreferrer';
    qrActRow.appendChild(custLink);
    qrInfo.appendChild(qrActRow);

    qrRes.appendChild(qrVis);
    qrRes.appendChild(qrInfo);
    demoBox.appendChild(qrRes);

    // Tamper amount check box
    const tryBox = el('div', 'verify-try-box');
    tryBox.appendChild(el('h4', 'verify-try-title', t('verify.tab2.tryTitle')));
    tryBox.appendChild(el('p', 'verify-try-hint', t('verify.tab2.tryHint')));

    const tryRow = el('div', 'verify-try-row');
    const editWrap = el('div', 'verify-field');
    const editLbl = el('label', 'verify-label', t('verify.tab2.editAmountLabel'));
    editLbl.setAttribute('for', 'verify-tamper-amt');
    const editInp = el('input', 'verify-input');
    editInp.id = 'verify-tamper-amt';
    editInp.type = 'number';
    editInp.step = '0.01';
    editInp.min = '0.01';
    editInp.value = state.tamperAmountInput;
    editInp.addEventListener('input', (e) => { state.tamperAmountInput = e.target.value; });
    editWrap.appendChild(editLbl);
    editWrap.appendChild(editInp);

    const chkBtn = el('button', 'learn-btn-primary', t('verify.tab2.checkBtn'));
    chkBtn.type = 'button';
    chkBtn.disabled = state.tamperCheckLoading;
    chkBtn.addEventListener('click', runTamperCheck);
    tryRow.appendChild(editWrap);
    tryRow.appendChild(chkBtn);
    tryBox.appendChild(tryRow);

    if (state.tamperCheckResult) {
      const tcr = state.tamperCheckResult;
      const cr = tcr.checkResult || {};
      const st = String(cr.status || 'MALFORMED').toUpperCase();
      const cls = st === 'VALID' ? 'status-valid' : st === 'EXPIRED' ? 'status-lookalike' : 'status-tampered';
      const vCard = el('div', `verify-verdict-card ${cls}`);
      vCard.appendChild(el('strong', 'verify-verdict-badge', st));
      const msgKey = st === 'VALID' ? 'statusValid' : st === 'EXPIRED' ? 'statusExpired' : st === 'TAMPERED' ? 'statusTampered' : 'statusMalformed';
      vCard.appendChild(el('p', 'verify-verdict-reason', t(`verify.tab2.${msgKey}`)));

      const cmp = el('div', 'verify-amount-compare');
      cmp.appendChild(el('span', 'verify-cmp-orig', `${t('verify.tab2.originalLabel')}: ${tcr.originalRupees}`));
      cmp.appendChild(el('span', 'verify-cmp-recv', `${t('verify.tab2.receivedLabel')}: ${tcr.receivedRupees}`));
      vCard.appendChild(cmp);
      tryBox.appendChild(vCard);
    }

    demoBox.appendChild(tryBox);
  }

  panel.appendChild(demoBox);
}

// ── Tab 3: After payment (Hash-Chained Receipt Trail) ─────────────────────

async function confirmDemoPayment() {
  state.tab3Loading = true;
  state.tab3Message = '';
  state.trailCheckResult = null;
  render();

  try {
    let token = state.qrData;
    if (!token) {
      const mId = state.selectedMerchantId || 'ravi-stores';
      token = await apiJson('/api/verify/qr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ merchantId: mId, amountRupees: Number(state.amountInput) || 500 })
      });
      state.qrData = token;
    }

    const prevHash = state.trail.length > 0 ? state.trail[state.trail.length - 1].hash : null;
    const entry = await apiJson('/api/verify/receipt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        payload: token.payload,
        signature: token.signature,
        prevHash
      })
    });

    state.trail = [...state.trail, entry];
    writeStoredTrail(state.trail);
  } catch (err) {
    state.tab3Message = err.message;
  } finally {
    state.tab3Loading = false;
    render();
  }
}

function tamperEntryTwo() {
  state.trailCheckResult = null;
  if (state.trail.length < 2) {
    state.tab3Message = t('verify.tab3.needTwoForTamper');
    render();
    return;
  }
  const copy = state.trail.map((item) => ({ ...item }));
  const orig = Number(copy[1].amount) || 500;
  copy[1].amount = (orig + 1000).toFixed(2);
  state.trail = copy;
  state.tamperedIndex = 1;
  writeStoredTrail(state.trail);
  state.tab3Message = t('verify.tab3.tamperDone');
  render();
}

async function verifyTrail() {
  if (state.trail.length === 0) return;
  state.tab3Loading = true;
  state.tab3Message = '';
  render();

  try {
    state.trailCheckResult = await apiJson('/api/verify/trail/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entries: state.trail })
    });
  } catch (err) {
    state.tab3Message = err.message;
    state.trailCheckResult = null;
  } finally {
    state.tab3Loading = false;
    render();
  }
}

function clearTrail() {
  state.trail = [];
  state.tamperedIndex = null;
  state.trailCheckResult = null;
  state.tab3Message = '';
  writeStoredTrail([]);
  render();
}

async function submitEvidenceReceipt() {
  state.evError = '';
  try {
    const bundle = await createReceiptBundle({
      status: state.evStatus,
      rrn: state.evRrn,
      receiverVpa: state.evVpa,
      receiverName: state.evName,
      amount: state.evAmount,
      timestamp: state.evTimestamp,
      appUsed: state.evApp,
      notes: state.evNotes
    });
    state.evBundle = bundle;
    state.evVerifyJsonText = JSON.stringify(bundle, null, 2);
    state.evVerifyResult = null;
    render();
  } catch (err) {
    state.evError = err.message || 'Unable to generate receipt.';
    render();
  }
}

function downloadReceiptBundle(bundle) {
  if (!bundle) return;
  const jsonText = JSON.stringify(bundle, null, 2);
  const a = document.createElement('a');
  a.href = `data:application/json;charset=utf-8,${encodeURIComponent(jsonText)}`;
  const refPart = bundle.receipt?.rrn || 'receipt';
  a.download = `cybershield-receipt-${refPart.replace(/[^a-zA-Z0-9_-]/g, '')}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

function prepareFraudReportFromBundle(bundle) {
  if (!bundle || !bundle.receipt) return;
  savePreparedReport(bundle);
  renderPreparedReportRoot(bundle);
  if (window.history && typeof window.history.pushState === 'function') {
    const url = new URL(window.location.href);
    if (bundle.receipt.amount) url.searchParams.set('reportAmount', bundle.receipt.amount);
    if (bundle.receipt.rrn) url.searchParams.set('reportRef', bundle.receipt.rrn);
    url.hash = '#report';
    window.history.pushState({ ussView: 'report' }, '', url.toString());
  }
  const rep = document.getElementById('report');
  if (rep) rep.scrollIntoView({ behavior: 'smooth' });
}

async function runReceiptFileVerify() {
  state.evVerifyResult = await verifyReceiptBundleJson(state.evVerifyJsonText);
  render();
}

function renderEvidenceWorkspace(panel) {
  const box = el('div', 'verify-ev-box');
  box.appendChild(el('h3', 'verify-qr-inspector-title', t('verify.tab3.ev.heading')));
  box.appendChild(el('p', 'verify-tab-explainer', t('verify.tab3.ev.sub')));

  const form = el('form', 'verify-form');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    submitEvidenceReceipt();
  });

  const grid = el('div', 'verify-input-grid');

  // Amount (required)
  const amtF = el('div', 'verify-field');
  const amtL = el('label', 'verify-label', t('verify.tab3.ev.amountLabel'));
  amtL.setAttribute('for', 'ev-amount');
  const amtI = el('input', 'verify-input');
  amtI.id = 'ev-amount';
  amtI.type = 'number';
  amtI.step = '0.01';
  amtI.min = '0.01';
  amtI.required = true;
  amtI.value = state.evAmount;
  amtI.addEventListener('input', (e) => { state.evAmount = e.target.value; });
  amtF.appendChild(amtL);
  amtF.appendChild(amtI);

  // Timestamp (required)
  const tsF = el('div', 'verify-field');
  const tsL = el('label', 'verify-label', t('verify.tab3.ev.timestampLabel'));
  tsL.setAttribute('for', 'ev-ts');
  const tsI = el('input', 'verify-input');
  tsI.id = 'ev-ts';
  tsI.type = 'datetime-local';
  tsI.required = true;
  tsI.value = state.evTimestamp;
  tsI.addEventListener('input', (e) => { state.evTimestamp = e.target.value; });
  tsF.appendChild(tsL);
  tsF.appendChild(tsI);

  // Transaction status (optional)
  const stF = el('div', 'verify-field');
  const stL = el('label', 'verify-label', t('verify.tab3.ev.statusLabel'));
  stL.setAttribute('for', 'ev-status');
  const stSel = el('select', 'verify-input');
  stSel.id = 'ev-status';
  for (const [val, key] of [['completed', 'statusCompleted'], ['pending', 'statusPending'], ['failed', 'statusFailed']]) {
    const opt = el('option', '', t(`verify.tab3.ev.${key}`));
    opt.value = val;
    if (state.evStatus === val) opt.selected = true;
    stSel.appendChild(opt);
  }
  stSel.addEventListener('change', (e) => { state.evStatus = e.target.value; });
  stF.appendChild(stL);
  stF.appendChild(stSel);

  // RRN (optional)
  const rrnF = el('div', 'verify-field');
  const rrnL = el('label', 'verify-label', t('verify.tab3.ev.rrnLabel'));
  rrnL.setAttribute('for', 'ev-rrn');
  const rrnI = el('input', 'verify-input');
  rrnI.id = 'ev-rrn';
  rrnI.type = 'text';
  rrnI.placeholder = t('verify.tab3.ev.rrnPlaceholder');
  rrnI.value = state.evRrn;
  rrnI.addEventListener('input', (e) => { state.evRrn = e.target.value; });
  rrnF.appendChild(rrnL);
  rrnF.appendChild(rrnI);

  // Receiver VPA (optional)
  const vpaF = el('div', 'verify-field');
  const vpaL = el('label', 'verify-label', t('verify.tab3.ev.vpaLabel'));
  vpaL.setAttribute('for', 'ev-vpa');
  const vpaI = el('input', 'verify-input');
  vpaI.id = 'ev-vpa';
  vpaI.type = 'text';
  vpaI.placeholder = t('verify.tab3.ev.vpaPlaceholder');
  vpaI.value = state.evVpa;
  vpaI.addEventListener('input', (e) => { state.evVpa = e.target.value; });
  vpaF.appendChild(vpaL);
  vpaF.appendChild(vpaI);

  // Receiver name shown (optional)
  const nmF = el('div', 'verify-field');
  const nmL = el('label', 'verify-label', t('verify.tab3.ev.nameLabel'));
  nmL.setAttribute('for', 'ev-name');
  const nmI = el('input', 'verify-input');
  nmI.id = 'ev-name';
  nmI.type = 'text';
  nmI.placeholder = t('verify.tab3.ev.namePlaceholder');
  nmI.value = state.evName;
  nmI.addEventListener('input', (e) => { state.evName = e.target.value; });
  nmF.appendChild(nmL);
  nmF.appendChild(nmI);

  // App used (optional)
  const appF = el('div', 'verify-field');
  const appL = el('label', 'verify-label', t('verify.tab3.ev.appLabel'));
  appL.setAttribute('for', 'ev-app');
  const appI = el('input', 'verify-input');
  appI.id = 'ev-app';
  appI.type = 'text';
  appI.placeholder = t('verify.tab3.ev.appPlaceholder');
  appI.value = state.evApp;
  appI.addEventListener('input', (e) => { state.evApp = e.target.value; });
  appF.appendChild(appL);
  appF.appendChild(appI);

  // Notes (optional)
  const ntF = el('div', 'verify-field');
  const ntL = el('label', 'verify-label', t('verify.tab3.ev.notesLabel'));
  ntL.setAttribute('for', 'ev-notes');
  const ntI = el('input', 'verify-input');
  ntI.id = 'ev-notes';
  ntI.type = 'text';
  ntI.placeholder = t('verify.tab3.ev.notesPlaceholder');
  ntI.value = state.evNotes;
  ntI.addEventListener('input', (e) => { state.evNotes = e.target.value; });
  ntF.appendChild(ntL);
  ntF.appendChild(ntI);

  for (const field of [amtF, tsF, stF, rrnF, vpaF, nmF, appF, ntF]) grid.appendChild(field);
  form.appendChild(grid);

  const genBtn = el('button', 'learn-btn-primary', t('verify.tab3.ev.generateBtn'));
  genBtn.type = 'submit';
  form.appendChild(genBtn);
  box.appendChild(form);

  if (state.evError) {
    box.appendChild(el('div', 'verify-error-box', state.evError));
  }

  if (state.evBundle) {
    const { receipt, sha256 } = state.evBundle;
    const rc = el('div', 'verify-ev-receipt-card');
    rc.id = 'verify-printable-receipt';

    const fGrid = el('div', 'verify-qr-fields-grid');
    for (const [k, v] of [
      ['Amount', `Rs.${receipt.amount}`],
      ['Timestamp', receipt.timestamp],
      ['Status', receipt.status],
      ['RRN', receipt.rrn || '—'],
      ['Receiver VPA', receipt.receiverVpa || '—'],
      ['Receiver name', receipt.receiverName || '—'],
      ['App used', receipt.appUsed || '—'],
      ['Notes', receipt.notes || '—']
    ]) {
      const fc = el('div', 'verify-qr-field-card');
      fc.appendChild(el('span', 'verify-qr-field-lbl', k));
      fc.appendChild(el('strong', 'verify-qr-field-val', v));
      fGrid.appendChild(fc);
    }
    rc.appendChild(fGrid);

    const hashBox = el('div', 'verify-ev-hash-box');
    hashBox.appendChild(el('span', 'verify-qr-field-lbl', t('verify.tab3.ev.hashLabel')));
    hashBox.appendChild(el('code', 'verify-link-code', sha256));
    rc.appendChild(hashBox);

    const actions = el('div', 'verify-tab3-actions verify-ev-actions');
    const dlBtn = el('button', 'learn-btn-secondary', t('verify.tab3.ev.downloadBtn'));
    dlBtn.type = 'button';
    dlBtn.addEventListener('click', () => downloadReceiptBundle(state.evBundle));

    const printBtn = el('button', 'learn-btn-secondary', t('verify.tab3.ev.printBtn'));
    printBtn.type = 'button';
    printBtn.addEventListener('click', () => window.print());

    const prepBtn = el('button', 'learn-btn-primary', t('verify.tab3.ev.prepareReportBtn'));
    prepBtn.type = 'button';
    prepBtn.addEventListener('click', () => prepareFraudReportFromBundle(state.evBundle));

    actions.appendChild(dlBtn);
    actions.appendChild(printBtn);
    actions.appendChild(prepBtn);
    rc.appendChild(actions);
    box.appendChild(rc);
  }

  // Tamper-evidence verification ("Verify a receipt file")
  const verifyBox = el('div', 'verify-try-box verify-ev-verify-box');
  verifyBox.appendChild(el('h4', 'verify-try-title', t('verify.tab3.ev.verifyFileTitle')));
  verifyBox.appendChild(el('p', 'verify-try-hint', t('verify.tab3.ev.verifyFileSub')));

  const uploadRow = el('div', 'verify-qr-controls');
  const upLbl = el('label', 'verify-chip verify-file-label', t('verify.tab3.ev.uploadJsonLabel'));
  const upInp = document.createElement('input');
  upInp.type = 'file';
  upInp.accept = '.json,application/json';
  upInp.className = 'verify-file-input';
  upInp.addEventListener('change', (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      state.evVerifyJsonText = String(reader.result || '');
      runReceiptFileVerify();
    };
    reader.readAsText(file);
  });
  upLbl.appendChild(upInp);
  uploadRow.appendChild(upLbl);
  verifyBox.appendChild(uploadRow);

  const ta = document.createElement('textarea');
  ta.className = 'verify-input verify-ev-json-textarea';
  ta.rows = 5;
  ta.placeholder = t('verify.tab3.ev.pasteJsonPlaceholder');
  ta.value = state.evVerifyJsonText;
  ta.addEventListener('input', (e) => { state.evVerifyJsonText = e.target.value; });
  verifyBox.appendChild(ta);

  const chkBtn = el('button', 'learn-btn-secondary', t('verify.tab3.ev.verifyFileBtn'));
  chkBtn.type = 'button';
  chkBtn.addEventListener('click', runReceiptFileVerify);
  verifyBox.appendChild(chkBtn);

  if (state.evVerifyResult) {
    const res = state.evVerifyResult;
    const cls = res.status === 'UNCHANGED' ? 'status-verified' : 'status-tampered';
    const titleKey = res.status === 'UNCHANGED'
      ? 'unchangedTitle'
      : res.status === 'MODIFIED'
        ? 'modifiedTitle'
        : 'invalidJsonTitle';
    const card = el('div', `verify-verdict-card verify-ev-verify-card ${cls}`);
    card.appendChild(el('strong', 'verify-verdict-badge', t(`verify.tab3.ev.${titleKey}`)));
    card.appendChild(el('p', 'verify-verdict-reason', res.note));
    if (res.computedHash) {
      card.appendChild(el('code', 'verify-link-code', `Computed: ${res.computedHash}`));
    }
    verifyBox.appendChild(card);
  }
  box.appendChild(verifyBox);

  // Honest card
  const honestCard = el('div', 'verify-honesty-card verify-lab-honesty');
  honestCard.setAttribute('role', 'note');
  honestCard.appendChild(el('span', 'verify-honesty-badge', t('verify.tab3.ev.honestBadge')));
  honestCard.appendChild(el('p', 'verify-honesty-body', t('verify.tab3.ev.honestBody')));
  box.appendChild(honestCard);

  panel.appendChild(box);
}

function renderTab3(panel) {
  panel.appendChild(buildHonestyCard('afterBadge', 'afterTitle', 'afterBody'));
  renderEvidenceWorkspace(panel);
  if (!state.merchantsLoaded) return;
  panel.appendChild(el('p', 'verify-tab-explainer', t('verify.tab3.explainer')));

  const demoTagRow = el('div', 'verify-demo-row');
  demoTagRow.appendChild(el('span', 'verify-demo-pill', t('verify.demoNoMoney')));
  panel.appendChild(demoTagRow);

  const btnRow = el('div', 'verify-tab3-actions');

  const btnConfirm = el('button', 'learn-btn-primary', t('verify.tab3.confirmBtn'));
  btnConfirm.type = 'button';
  btnConfirm.disabled = state.tab3Loading;
  btnConfirm.addEventListener('click', confirmDemoPayment);

  const btnTamper = el('button', 'learn-btn-secondary', t('verify.tab3.tamperBtn'));
  btnTamper.type = 'button';
  btnTamper.disabled = state.tab3Loading;
  btnTamper.addEventListener('click', tamperEntryTwo);

  const btnVerify = el('button', 'learn-btn-secondary', t('verify.tab3.verifyBtn'));
  btnVerify.type = 'button';
  btnVerify.disabled = state.tab3Loading || state.trail.length === 0;
  btnVerify.addEventListener('click', verifyTrail);

  const btnReport = el('button', 'learn-btn-secondary verify-report-jump', t('verify.tab3.reportBtn'));
  btnReport.type = 'button';
  btnReport.addEventListener('click', () => {
    const rep = document.getElementById('report');
    if (rep) rep.scrollIntoView({ behavior: 'smooth' });
  });

  btnRow.appendChild(btnConfirm);
  btnRow.appendChild(btnTamper);
  btnRow.appendChild(btnVerify);
  btnRow.appendChild(btnReport);

  if (state.trail.length > 0) {
    const btnClear = el('button', 'learn-btn-link', t('verify.tab3.clearBtn'));
    btnClear.type = 'button';
    btnClear.addEventListener('click', clearTrail);
    btnRow.appendChild(btnClear);
  }
  panel.appendChild(btnRow);

  if (state.tab3Message) {
    panel.appendChild(el('p', 'verify-inline-note', state.tab3Message));
  }

  if (state.trailCheckResult) {
    const tc = state.trailCheckResult;
    const verdict = el('div', `verify-verdict-card ${tc.valid ? 'status-valid' : 'status-tampered'}`);
    const title = tc.valid
      ? t('verify.tab3.chainIntact')
      : t('verify.tab3.chainBroken', { index: (tc.brokenAtIndex ?? 0) + 1 });
    verdict.appendChild(el('strong', 'verify-verdict-badge', title));
    if (tc.reason) verdict.appendChild(el('p', 'verify-verdict-reason', tc.reason));
    panel.appendChild(verdict);
  }

  if (state.trail.length === 0) {
    panel.appendChild(el('p', 'verify-empty-trail', t('verify.tab3.emptyTrail')));
    return;
  }

  const tableWrap = el('div', 'verify-table-wrap');
  const table = el('table', 'verify-trail-table');
  const thead = document.createElement('thead');
  const headRow = document.createElement('tr');
  for (const colKey of ['colId', 'colMerchant', 'colAmount', 'colTime', 'colHash']) {
    headRow.appendChild(el('th', '', t(`verify.tab3.${colKey}`)));
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  state.trail.forEach((entry, idx) => {
    const tr = document.createElement('tr');
    if (state.trailCheckResult && !state.trailCheckResult.valid && state.trailCheckResult.brokenAtIndex === idx) {
      tr.classList.add('is-broken-row');
    } else if (state.tamperedIndex === idx) {
      tr.classList.add('is-edited-row');
    }

    tr.appendChild(el('td', '', entry.receiptId || ''));
    tr.appendChild(el('td', '', entry.merchant || ''));
    tr.appendChild(el('td', '', `Rs.${entry.amount || ''}`));
    const shortTime = (entry.timestamp || '').replace('T', ' ').slice(0, 19);
    tr.appendChild(el('td', '', shortTime));
    const shortHash = entry.hash ? `${entry.hash.slice(0, 12)}…` : '';
    tr.appendChild(el('td', 'verify-hash-cell', shortHash));
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  tableWrap.appendChild(table);
  panel.appendChild(tableWrap);
}

// ── Main Render ───────────────────────────────────────────────────────────

function render() {
  if (!verifyRoot) return;
  verifyRoot.replaceChildren();

  // Header
  const header = el('div', 'section-header');
  header.appendChild(el('span', 'section-tag', t('verify.tag')));
  const h2 = el('h2', 'section-heading', t('verify.title'));
  h2.id = 'verify-heading';
  header.appendChild(h2);
  header.appendChild(el('p', 'section-sub', t('verify.subtitle')));
  verifyRoot.appendChild(header);

  // Permanent Demo Banner
  const banner = el('div', 'verify-demo-banner');
  banner.setAttribute('role', 'note');
  banner.appendChild(el('strong', '', t('verify.demoBanner')));
  verifyRoot.appendChild(banner);

  // Always render the 3-tab Safety Check shell (works both online and offline)
  const shell = el('div', 'learn-card-shell verify-shell');

  const tabList = el('div', 'verify-tablist');
  tabList.setAttribute('role', 'tablist');

  const tabDefs = ['t1', 't2', 't3'];
  for (const key of tabDefs) {
    const active = state.activeTab === key;
    const btn = el('button', `verify-tab-btn${active ? ' is-active' : ''}`, t(`verify.tabs.${key}`));
    btn.type = 'button';
    btn.setAttribute('role', 'tab');
    btn.setAttribute('aria-selected', String(active));
    btn.id = `verify-tab-${key}`;
    btn.setAttribute('aria-controls', `verify-panel-${key}`);
    btn.addEventListener('click', () => {
      if (key !== 't1' && state.camActive) stopCameraScan(false);
      state.activeTab = key;
      render();
    });
    btn.addEventListener('keydown', (e) => {
      const idx = tabDefs.indexOf(key);
      if (e.key === 'ArrowRight') {
        state.activeTab = tabDefs[(idx + 1) % tabDefs.length];
        render();
        document.getElementById(`verify-tab-${state.activeTab}`)?.focus();
      } else if (e.key === 'ArrowLeft') {
        state.activeTab = tabDefs[(idx - 1 + tabDefs.length) % tabDefs.length];
        render();
        document.getElementById(`verify-tab-${state.activeTab}`)?.focus();
      }
    });
    tabList.appendChild(btn);
  }
  shell.appendChild(tabList);

  for (const key of tabDefs) {
    const active = state.activeTab === key;
    const panel = el('div', `verify-tabpanel${active ? '' : ' hidden'}`);
    panel.setAttribute('role', 'tabpanel');
    panel.id = `verify-panel-${key}`;
    panel.setAttribute('aria-labelledby', `verify-tab-${key}`);

    if (key === 't1') renderTab1(panel);
    else if (key === 't2') renderTab2(panel);
    else renderTab3(panel);

    shell.appendChild(panel);
  }

  verifyRoot.appendChild(shell);

  // "What this can and cannot do" card
  const limitsCard = el('div', 'learn-card-shell verify-limits-card');
  limitsCard.appendChild(el('h3', 'verify-limits-title', t('verify.limits.title')));
  const limitsGrid = el('div', 'verify-limits-grid');

  const canBox = el('div', 'verify-limit-col can-col');
  canBox.appendChild(el('h4', 'verify-limit-head', t('verify.limits.canTitle')));
  canBox.appendChild(el('p', 'verify-limit-body', t('verify.limits.canText')));

  const cannotBox = el('div', 'verify-limit-col cannot-col');
  cannotBox.appendChild(el('h4', 'verify-limit-head', t('verify.limits.cannotTitle')));
  cannotBox.appendChild(el('p', 'verify-limit-body', t('verify.limits.cannotText')));

  limitsGrid.appendChild(canBox);
  limitsGrid.appendChild(cannotBox);
  limitsCard.appendChild(limitsGrid);
  verifyRoot.appendChild(limitsCard);
}

// ── Boot & Global Presenter / Reset Hooks ─────────────────────────────────

function resolvePaymentLinkOrigin(rawLink) {
  try {
    const u = new URL(rawLink, window.location.origin);
    const isPageLocal = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
    const isLinkLocal = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
    if ((!isPageLocal && isLinkLocal) || (u.host === window.location.host && u.protocol !== window.location.protocol)) {
      return `${window.location.origin}${u.pathname}${u.search}${u.hash}`;
    }
    return u.href;
  } catch {
    return rawLink;
  }
}

window.USS = window.USS || {};
window.USS.verifyGenerateDemo = async (merchantId = 'ravi-stores', amount = 500) => {
  await initI18n();
  const verifySection = document.getElementById('verify');
  if (verifySection) verifySection.scrollIntoView({ behavior: 'smooth' });
  state.activeTab = 't2';
  state.selectedMerchantId = merchantId;
  state.amountInput = String(amount);
  state.labAmount = String(amount);
  if (state.merchantsLoaded) {
    await Promise.all([submitLabOrder(), generateSignedQr()]);
  } else {
    await submitLabOrder();
  }
};
window.USS.resetVerifyState = () => {
  stopLabCountdown();
  state.labOrder = null;
  state.labVerifyResult = null;
  state.labTamperMode = 'clean';
  state.labRef = generateOrderRef();
  state.trail = [];
  state.tamperedIndex = null;
  state.trailCheckResult = null;
  state.qrData = null;
  state.tamperCheckResult = null;
  state.tab1Result = null;
  state.tab1Error = '';
  state.tab2Error = '';
  state.tab3Message = '';
  render();
};

onServerStatusChange(async (status) => {
  if (status === 'ready' && !state.merchantsLoaded) {
    await loadMerchants();
  }
  render();
});

(async () => {
  await Promise.all([initI18n(), preloadDemoRegistry()]);
  renderPreparedReportRoot(loadPreparedReport());
  if (getServerStatus() === 'ready' && !state.merchantsLoaded) {
    await loadMerchants();
  }
  onLangChange(() => render());
  render();
})();

