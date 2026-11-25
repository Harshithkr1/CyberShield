import fs from 'node:fs/promises';
import path from 'node:path';
import QRCode from 'qrcode';

const SAMPLES = [
  {
    file: 'clean-shop.png',
    uri: 'upi://pay?pa=ravi.stores@demobank&pn=Ravi%20Stores&am=250.00&cu=INR&tr=ORD1042&tn=Groceries%20bill'
  },
  {
    file: 'bait-word.png',
    uri: 'upi://pay?pa=rahul9845@ybl&pn=SBI%20KYC%20Refund%20Desk&am=1.00&cu=INR&tr=REF8821&tn=Claim%20Rs.10%20cashback%20bit.ly%2Fsbi-kyc'
  },
  {
    file: 'amount-blank.png',
    uri: 'upi://pay?pa=metro.bazaar@okaxis&pn=Metro%20Bazaar&cu=INR&tr=TXN3099&tn=Counter%20checkout'
  }
];

const TARGET_DIRS = [
  'src/main/resources/static/samples/qr',
  'docs/samples/qr'
];

for (const dir of TARGET_DIRS) {
  await fs.mkdir(dir, { recursive: true });
  for (const sample of SAMPLES) {
    const outPath = path.join(dir, sample.file);
    await QRCode.toFile(outPath, sample.uri, {
      type: 'png',
      width: 280,
      margin: 2,
      errorCorrectionLevel: 'M'
    });
    console.log('Generated:', outPath);
  }
}

