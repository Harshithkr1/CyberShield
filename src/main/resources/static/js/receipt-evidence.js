/**
 * receipt-evidence.js – 100% client-side After-payment receipt hashing,
 * tamper-evidence verification, and Report prefill generator.
 * Makes zero network calls and never auto-submits any report.
 */

const REPORT_STORAGE_KEY = 'uss.preparedReport';

export function buildCanonicalReceipt(input) {
  const amountNum = Number(input?.amount);
  if (!Number.isFinite(amountNum) || amountNum <= 0) {
    throw new Error('Please enter a valid transaction amount greater than 0.');
  }
  const timestamp = String(input?.timestamp || '').trim();
  if (!timestamp) {
    throw new Error('Please provide the transaction date & time.');
  }

  const allowedStatus = new Set(['completed', 'pending', 'failed']);
  const status = allowedStatus.has(String(input?.status || '').toLowerCase())
    ? String(input.status).toLowerCase()
    : 'completed';

  return {
    version: 1,
    status,
    rrn: String(input?.rrn || '').trim(),
    receiverVpa: String(input?.receiverVpa || '').trim(),
    receiverName: String(input?.receiverName || '').trim(),
    amount: amountNum.toFixed(2),
    timestamp,
    appUsed: String(input?.appUsed || '').trim(),
    notes: String(input?.notes || '').trim()
  };
}

export function serializeCanonicalReceipt(receipt) {
  const ordered = {
    version: receipt.version ?? 1,
    status: String(receipt.status || 'completed'),
    rrn: String(receipt.rrn || ''),
    receiverVpa: String(receipt.receiverVpa || ''),
    receiverName: String(receipt.receiverName || ''),
    amount: String(receipt.amount || ''),
    timestamp: String(receipt.timestamp || ''),
    appUsed: String(receipt.appUsed || ''),
    notes: String(receipt.notes || '')
  };
  return JSON.stringify(ordered);
}

export async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(String(text || ''));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

export async function createReceiptBundle(input) {
  const receipt = buildCanonicalReceipt(input);
  const canonicalJson = serializeCanonicalReceipt(receipt);
  const sha256 = await sha256Hex(canonicalJson);
  return { receipt, sha256 };
}

export async function verifyReceiptBundleJson(rawJsonText) {
  let parsed;
  try {
    parsed = JSON.parse(String(rawJsonText || ''));
  } catch {
    return {
      status: 'INVALID',
      expectedHash: '',
      computedHash: '',
      receipt: null,
      note: 'Tamper-evident, not tamper-proof — edits are detectable, not impossible.'
    };
  }

  if (!parsed || typeof parsed !== 'object' || !parsed.receipt || typeof parsed.sha256 !== 'string') {
    return {
      status: 'INVALID',
      expectedHash: '',
      computedHash: '',
      receipt: null,
      note: 'Tamper-evident, not tamper-proof — edits are detectable, not impossible.'
    };
  }

  const canonical = serializeCanonicalReceipt(parsed.receipt);
  const computedHash = await sha256Hex(canonical);
  const expectedHash = parsed.sha256.trim().toLowerCase();
  const matched = expectedHash.length === 64 && expectedHash === computedHash;

  return {
    status: matched ? 'UNCHANGED' : 'MODIFIED',
    expectedHash,
    computedHash,
    receipt: parsed.receipt,
    note: 'Tamper-evident, not tamper-proof — edits are detectable, not impossible.'
  };
}

export function buildFraudReportData(receipt, sha256 = '') {
  const r = receipt || {};
  const when = r.timestamp || 'Not provided';
  const amt = r.amount ? `Rs.${r.amount}` : 'Not provided';
  const rrn = r.rrn || 'Not noted (check UPI app history)';
  const vpa = r.receiverVpa || 'Not noted';
  const name = r.receiverName || 'Not noted';
  const app = r.appUsed || 'UPI app';
  const status = r.status || 'completed';
  const notes = r.notes || 'Suspicious / unauthorized UPI payment';

  return {
    receipt: r,
    sha256,
    timeline: [
      `When: ${when}`,
      `Status: ${status}`,
      `Amount: ${amt}`,
      `App used: ${app}`,
      `RRN / Ref: ${rrn}`,
      `Receiver VPA: ${vpa}`,
      `Receiver name shown: ${name}`,
      sha256 ? `Receipt SHA-256: ${sha256}` : null
    ].filter(Boolean),
    call1930Script: [
      `1. State that you want to report a ${status} UPI fraud transaction of ${amt} that occurred at ${when}.`,
      `2. Read out payment app & RRN: App = ${app}, RRN / Transaction ID = ${rrn}.`,
      `3. Read out receiver details: UPI ID = ${vpa}, Name shown = ${name}.`,
      `4. Summary to read: "${notes}". Ask for a 1930 acknowledgement number immediately.`
    ],
    cybercrimeChecklist: [
      { field: 'Complaint Category', value: 'Online Financial Fraud → UPI / QR Code Scam' },
      { field: 'Date & Time of Incident', value: when },
      { field: 'Transaction Amount', value: amt },
      { field: 'Wallet / Bank / App Used', value: app },
      { field: 'Transaction ID / RRN', value: rrn },
      { field: 'Suspect UPI ID / VPA', value: vpa },
      { field: 'Suspect Display Name', value: name },
      { field: 'Incident Description / Notes', value: `${notes} (Status: ${status})` }
    ],
    chakshuReminder:
      'If the scammer also contacted you by phone call, SMS, or WhatsApp (e.g. fake KYC, courier, or digital arrest threat), report that phone number and message separately at sancharsaathi.gov.in (Chakshu) to help block fraud SIMs.'
  };
}

export function savePreparedReport(bundle) {
  try {
    localStorage.setItem(REPORT_STORAGE_KEY, JSON.stringify(bundle));
  } catch {
    // ignore storage errors
  }
}

export function loadPreparedReport() {
  try {
    const raw = localStorage.getItem(REPORT_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export function renderPreparedReportRoot(bundle) {
  const mount = typeof document !== 'undefined' ? document.getElementById('report-prepared-root') : null;
  if (!mount) return;
  mount.replaceChildren();

  if (!bundle || !bundle.receipt) {
    mount.classList.add('hidden');
    return;
  }

  const data = buildFraudReportData(bundle.receipt, bundle.sha256 || '');
  mount.classList.remove('hidden');

  const card = document.createElement('div');
  card.className = 'report-prepared-card';

  const badge = document.createElement('span');
  badge.className = 'report-tag';
  badge.textContent = 'Evidence Ready — Never Auto-Submitted';
  card.appendChild(badge);

  const h3 = document.createElement('h3');
  h3.className = 'report-card-name';
  h3.textContent = 'Prepared Fraud Report Summary';
  card.appendChild(h3);

  const makeListSection = (title, items) => {
    const sec = document.createElement('div');
    sec.className = 'report-prep-section';
    const sh = document.createElement('h4');
    sh.className = 'report-prep-subhead';
    sh.textContent = title;
    sec.appendChild(sh);
    const ul = document.createElement('ul');
    ul.className = 'report-prep-list';
    for (const item of items) {
      const li = document.createElement('li');
      li.textContent = item;
      ul.appendChild(li);
    }
    sec.appendChild(ul);
    return sec;
  };

  card.appendChild(makeListSection('Transaction Timeline & Details', data.timeline));
  card.appendChild(makeListSection('1930 Call Script (read in order)', data.call1930Script));
  card.appendChild(
    makeListSection(
      'cybercrime.gov.in Field Checklist',
      data.cybercrimeChecklist.map((c) => `${c.field}: ${c.value}`)
    )
  );

  const chakshuSec = document.createElement('div');
  chakshuSec.className = 'report-prep-section report-chakshu-reminder';
  const csH = document.createElement('h4');
  csH.className = 'report-prep-subhead';
  csH.textContent = 'Sanchar Saathi (Chakshu) Reminder';
  const csP = document.createElement('p');
  csP.className = 'report-prep-text';
  csP.textContent = data.chakshuReminder;
  chakshuSec.appendChild(csH);
  chakshuSec.appendChild(csP);
  card.appendChild(chakshuSec);

  const clearBtn = document.createElement('button');
  clearBtn.type = 'button';
  clearBtn.className = 'report-btn pill';
  clearBtn.textContent = 'Clear Prepared Summary';
  clearBtn.addEventListener('click', () => {
    savePreparedReport(null);
    mount.replaceChildren();
    mount.classList.add('hidden');
  });
  card.appendChild(clearBtn);

  mount.appendChild(card);
}

