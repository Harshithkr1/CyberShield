/**
 * test-qr.js – Static test sheet for QR name-match & field inspection.
 * Builds all nodes using document.createElement and textContent only.
 * Never creates clickable links from upi:// text or QR images.
 */

const TEST_CASES = [
  {
    title: 'TEST 1 MATCH',
    imgSrc: 'test-qr/test-1-match.png',
    qrText: 'upi://pay?pa=ravi.stores@demobank&pn=Ravi%20Kumar&am=250&cu=INR&tn=Groceries',
    typeName: 'Type in "Name shown on your payment app": Ravi Kumar',
    expected: 'Expected result: green MATCH'
  },
  {
    title: 'TEST 2 PARTIAL',
    imgSrc: 'test-qr/test-2-partial.png',
    qrText: 'upi://pay?pa=ravi.stores@demobank&pn=Ravi%20Kumar&am=250&cu=INR&tn=Groceries',
    typeName: 'Type in "Name shown on your payment app": Ravi Kishore',
    expected: 'Expected result: amber PARTIAL'
  },
  {
    title: 'TEST 3 MISMATCH',
    imgSrc: 'test-qr/test-3-mismatch.png',
    qrText: 'upi://pay?pa=qwe978xyz@demobank&pn=Zomato%20Outlet&am=1&cu=INR&tn=Refund',
    typeName: 'Type in "Name shown on your payment app": Ravi Kumar',
    expected: 'Expected result: red MISMATCH warning'
  },
  {
    title: 'TEST 4 NO NAME',
    imgSrc: 'test-qr/test-4-no-name.png',
    qrText: 'upi://pay?pa=shop123@demobank&cu=INR',
    typeName: 'Type in "Name shown on your payment app": (optional / blank)',
    expected: 'Expected result: amber "This QR does not declare a name", and a warning that the amount is missing'
  },
  {
    title: 'TEST 5 BAIT WORDS',
    imgSrc: 'test-qr/test-5-bait-words.png',
    qrText: 'upi://pay?pa=rewards.team@demobank&pn=Cashback%20Reward&tn=KYC%20refund&cu=INR',
    typeName: 'Type in "Name shown on your payment app": (optional / blank)',
    expected: 'Expected result: flags for bait words (cashback, KYC, refund) and a missing amount'
  }
];

const NAME_MATCH_CHECKS = [
  '"Ravi Kumar" vs "RAVI KUMAR" = MATCH',
  '"Smt. Lakshmi" vs "Lakshmi" = MATCH',
  '"Ravi Kumar" vs "R Kumar" = MATCH'
];

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

const root = document.getElementById('test-qr-root');
if (root) {
  const headerCard = el('section', 'learn-card-shell pay-demo-card');
  headerCard.appendChild(el('h1', 'pay-demo-title', 'QR Name-Match Test Sheet'));
  headerCard.appendChild(
    el(
      'p',
      'verify-demo-banner',
      'TEST QR CODES. Fictional names and IDs. Scan these ONLY with Cyber Shield, never with a payment app.'
    )
  );
  root.appendChild(headerCard);

  for (const item of TEST_CASES) {
    const card = el('section', 'learn-card-shell pay-demo-card');
    card.appendChild(el('h2', 'verify-qr-inspector-title', item.title));

    const img = document.createElement('img');
    img.src = item.imgSrc;
    img.alt = item.title;
    img.width = 280;
    img.height = 280;
    img.className = 'verify-qr-img';
    card.appendChild(img);

    card.appendChild(el('p', 'verify-qr-plain-text', item.qrText));
    card.appendChild(el('p', 'pay-demo-reason', item.typeName));
    card.appendChild(el('p', 'go-verdict-summary', item.expected));

    const nameNoteList = el('ul', 'go-reasons-list');
    for (const rule of NAME_MATCH_CHECKS) {
      nameNoteList.appendChild(el('li', 'go-reason-item', rule));
    }
    card.appendChild(nameNoteList);

    root.appendChild(card);
  }
}

