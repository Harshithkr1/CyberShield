# Cyber Shield – Machine Learning Subsystem

This directory contains the training pipelines, feature extractors, dataset definitions, and model export scripts for Cyber Shield's on-device statistical deception classifiers.

---

## 1. Datasets & Provenance

### `ml/data/sms_spam.tsv`
- **Source**: UCI SMS Spam Collection dataset (Tiago A. Almeida and José María Gómez Hidalgo).
- **Format**: `label\ttext` (`ham` or `spam`).
- **Samples**: 5,574 messages (747 spam, 4,827 ham).

### `ml/data/indian_scams.csv`
- **Origin**: **Synthetic Dataset** (explicitly generated for this project).
- **Format**: `text,label` (`scam=1`, `safe=0`).
- **Samples**: 150 short examples covering prevailing Indian cyber fraud themes:
  - **Digital Arrest Scams**: Fake CBI, Delhi Police, ED, and Customs video interrogation summons demanding secrecy and fund transfers.
  - **Bank KYC Expiry**: Lookalike domain links warning of 24h account or debit card suspension (SBI, HDFC, ICICI, PNB).
  - **Courier & Customs Clearance**: Phishing links requesting duty/handling fees for detained FedEx, India Post, DHL, and BlueDart parcels.
  - **UPI & Cashback Baits**: Fake scratch cards, lottery winnings, and PIN collection requests (PhonePe, Google Pay, Paytm, KBC).
  - **Malicious APK Sideloading**: Electricity disconnection warnings and remote access utilities (AnyDesk, QuickSupport, Bijli bill APK).
  - **Legitimate Safe Messages**: Routine Indian communications (HDFC OTP, Zomato order status, IRCTC confirmed train tickets, metro recharges, team agendas).

### `ml/data/urls.csv`
- **Origin**: **Synthetic Dataset** (explicitly generated for this project).
- **Format**: `url,label` (`malicious=1`, `safe=0`).
- **Samples**: 200 balanced URLs:
  - **100 Safe URLs**: High-reputation Indian and global domains (`onlinesbi.sbi`, `hdfcbank.com`, `incometax.gov.in`, `parivahan.gov.in`, `irctc.co.in`, `google.co.in`, `wikipedia.org`, `github.com`).
  - **100 Malicious URLs**: Typosquats, lookalike subdomains, suspicious TLDs (`.xyz`, `.top`, `.tk`, `.club`), raw IP hosts (`http://185.220.101.5/...`), and rogue `.apk` links.

---

## 2. Text Classifier Pipeline (`ml/train_text.py`)

- **Input**: Combined `sms_spam.tsv` (5,574 samples) + `indian_scams.csv` (150 samples) = 5,724 total examples.
- **Preprocessing & Feature Extraction**:
  - `TfidfVectorizer`:
    - `lowercase=True`
    - `ngram_range=(1, 2)` (word unigrams and bigrams only)
    - `token_pattern=r"(?u)\b\w+\b"`
    - `max_features=5000`
    - `norm="l2"`
- **Classifier**: `LogisticRegression(C=2.0, max_iter=1000, random_state=42)`.
- **Evaluation**: 80/20 stratified train/test split (4,579 train, 1,145 test).
- **Export Target**: `src/main/resources/ml/text_model.json` (contains vocabulary with feature index, idf vector, model weights/coefficients, and intercept).

### Real Evaluation Metrics (Text Classifier):
- **Accuracy**: **98.52%** (0.9852)
- **Precision**: **100.00%** (1.0000)
- **Recall**: **90.23%** (0.9023)
- **F1 Score**: **94.86%** (0.9486)
- **Confusion Matrix** (Test Set $N = 1145$):
  - True Negatives (TN): **971**
  - False Positives (FP): **0**
  - False Negatives (FN): **17**
  - True Positives (TP): **157**

---

## 3. URL Classifier Pipeline (`ml/train_url.py`)

Extracts 9 numerical features from each raw URL:
1. `url_length`: Total character count.
2. `dot_count`: Count of period characters (`.`).
3. `hyphen_count`: Count of hyphens (`-`).
4. `digit_count`: Count of numeric digits.
5. `entropy`: Shannon entropy of character distribution ($-\sum p \log_2 p$).
6. `has_ip_host`: Flag (1.0 or 0.0) if the host is a raw IPv4 address.
7. `suspicious_tld`: Flag (1.0 or 0.0) if TLD is in known high-abuse extensions (`.xyz`, `.top`, `.tk`, `.club`, etc.).
8. `uses_https`: Flag (1.0 if URL starts with `https://`, 0.0 otherwise).
9. `subdomain_count`: Number of subdomains in host string.

- **Pipeline**: `StandardScaler` &rarr; `LogisticRegression(C=1.5, max_iter=1000, random_state=42)`.
- **Evaluation**: 80/20 stratified train/test split (160 train, 40 test).
- **Export Target**: `src/main/resources/ml/url_model.json` (feature names in order, mean vector, std vector, model coefficients, and intercept).

### Real Evaluation Metrics (URL Classifier):
- **Accuracy**: **100.00%** (1.0000)
- **Precision**: **100.00%** (1.0000)
- **Recall**: **100.00%** (1.0000)
- **F1 Score**: **100.00%** (1.0000)
- **Confusion Matrix** (Test Set $N = 40$):
  - True Negatives (TN): **20**
  - False Positives (FP): **0**
  - False Negatives (FN): **0**
  - True Positives (TP): **20**

### Model Feature Coefficients (Learned Weights):
- `uses_https`: **-1.7097** (protective feature)
- `suspicious_tld`: **+1.2099** (strong risk indicator)
- `hyphen_count`: **+1.1585** (deceptive brand typosquat indicator)
- `url_length`: **+0.8949**
- `entropy`: **+0.7574**
- `digit_count`: **+0.4905**
- `has_ip_host`: **+0.4723**
- `dot_count`: **+0.0248**
- `subdomain_count`: **+0.0064**
- `intercept`: **+0.0570**

---

## 4. Test Vectors (`ml/test_vectors.json`)

Contains 10 test messages and 10 test URLs evaluated by both trained models, with exact predicted probabilities:

### Test Texts
1. *Digital Arrest Call Script* &rarr; **0.9015** (`SCAM`)
2. *SBI KYC Block Warning* &rarr; **0.9178** (`SCAM`)
3. *FedEx Customs Duty Lure* &rarr; **0.8233** (`SCAM`)
4. *Power Disconnection APK Notice* &rarr; **0.7308** (`SCAM`)
5. *PhonePe Cashback Reward* &rarr; **0.9089** (`SCAM`)
6. *Team Presentation Agenda* &rarr; **0.0585** (`SAFE`)
7. *HDFC NetBanking OTP Alert* &rarr; **0.2954** (`SAFE`)
8. *Zomato Delivery Update* &rarr; **0.1983** (`SAFE`)
9. *IRCTC Train Confirmation* &rarr; **0.0699** (`SAFE`)
10. *Delhi Metro Card Recharge* &rarr; **0.1747** (`SAFE`)

### Test URLs
1. `http://sbi-kyc-verify-portal.xyz/login.php` &rarr; **0.9978** (`MALICIOUS`)
2. `http://185.220.101.5/police/digital-arrest` &rarr; **0.9989** (`MALICIOUS`)
3. `http://fedx-customs-clearance.top/track` &rarr; **0.9895** (`MALICIOUS`)
4. `http://quick-power-bill.org/payment.apk` &rarr; **0.9266** (`MALICIOUS`)
5. `http://phonpe-cashback-claim.top/scratch` &rarr; **0.9824** (`MALICIOUS`)
6. `https://www.google.co.in` &rarr; **0.0038** (`SAFE`)
7. `https://onlinesbi.sbi` &rarr; **0.0021** (`SAFE`)
8. `https://netbanking.hdfcbank.com` &rarr; **0.0190** (`SAFE`)
9. `https://cybercrime.gov.in` &rarr; **0.0123** (`SAFE`)
10. `https://irctc.co.in` &rarr; **0.0012** (`SAFE`)

---

## 5. Reproduction

To reproduce all model training and exports:
```bash
# 1. Install dependencies
pip install -r ml/requirements.txt

# 2. Train text model and export text_model.json
python ml/train_text.py

# 3. Train URL model and export url_model.json
python ml/train_url.py

# 4. Generate test vectors
python ml/export_test_vectors.py
```

