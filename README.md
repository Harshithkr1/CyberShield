# Cyber Shield – UPI Scam Simulator

> **Check it. Learn it. Verify it.**
>
> Cyber Shield is a cybersecurity awareness and scam-simulation platform targeting phishing lures, UPI fraud, coercive "digital arrest" scripts, and malicious Android APKs. Built with a zero-connection safety guarantee: **Cyber Shield never opens, fetches, or probes any analysed URL.**

---

## Three Modules

1. **Check (`#check`, `POST /api/analyze`)**
   - Hybrid rule heuristics (`rules.json`, 4 Java detectors, English/Kannada/Hindi phrase coverage) + pure Java ML inference (`TextClassifier`, `UrlClassifier`).
   - Highlights matched triggers, computes a 0–100 risk score, offers non-verdict `"No strong red flags found. Still verify in your bank app."` guidance on `LOW` results, and bridges directly to **Learn** (`Practise this scam`, `Play your own message`).
2. **Learn (`#learn`, client-side with `static/data/scenarios.json`)**
   - Interactive 9-scenario UPI scam simulator in **English (`en`), Kannada (`kn`), and Hindi (`hi`)** that runs completely client-side even when the backend is off.
   - **Challenge mode** (20-second timer, tap red flags for `+2` pts, choose actions for `+10` pts, Demo Bank loss consequence, weak-spot practice) and **Simple mode** (`20px+` accessible typography, no timer, `"Trust it"` / `"Don't trust it"`, gentle feedback).
3. **Verify (`#verify`, `/api/verify/*`, `pay-demo.html`)**
   - **1 Before payment**: Verifies UPI IDs against 5 fictional `Demo Bank` merchants (`VERIFIED_DEMO`, `NAME_MISMATCH`, `LOOKALIKE` via Levenshtein distance `<= 2`, or `UNKNOWN`).
   - **2 During payment**: Generates HMAC-SHA256 signed DemoPay links and `300×300` ZXing QR PNGs (`https://.../pay-demo.html?p=...&s=...`, never real UPI deep links), plus an interactive tamper test and standalone customer verification page (`pay-demo.html`).
   - **3 After payment**: Issues SHA-256 hash-chained `DEMO-...` receipts stored locally in `uss.trail` (`localStorage`) with one-click trail verification and tamper demonstration.

---

## Table of Contents
1. [Architecture](#architecture)
2. [Machine Learning Pipeline & Parity](#machine-learning-pipeline--parity)
3. [How Scoring Works](#how-scoring-works)
4. [Requirements](#requirements)
5. [How to Run](#how-to-run)
6. [How to Retrain the Models](#how-to-retrain-the-models)
7. [How to Add or Edit Rules in `rules.json`](#how-to-add-or-edit-rules-in-rulesjson)
8. [API Specification](#api-specification)
9. [Running Tests](#running-tests)
10. [Known Limitations](#known-limitations)
11. [Disclaimer](#disclaimer)

---

## Architecture

Cyber Shield operates a hybrid dual-engine architecture: a deterministic heuristic rule engine coupled with pure Java statistical machine learning inference, with Python utilized strictly offline for model training.

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             Frontend Presentation Layer                          │
│   • index.html (Pure dark glass style, responsive to 360px, prefers-reduced-m.)  │
│   • js/vortex.js (Dynamic reactive WebGL/Canvas vortex with mood states)         │
│   • js/app.js (UI orchestration, localStorage ML memory, samples, shortcuts)     │
│   • js/ui.js (SVG gauge animation, threat highlights, 100% XSS-safe DOM writes)  │
│   • js/api.js (REST fetch wrapper with structured friendly error handling)       │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ HTTP POST /api/analyze { text, useMl }
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                            Spring Boot 3 REST Controller                         │
│   • AnalyzeController (Request validation: 1–5,000 chars, no stack traces leak)  │
│   • SecurityHeadersFilter (Strict CSP, X-Frame-Options, nosniff, ReferrerPolicy) │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              Core AnalyzerService                                │
│   • Coordinates Heuristic Detectors & Machine Learning Inference Classifiers     │
│   • Computes Hybrid Blend: 0.6 * ruleScore + 0.4 * mlScore                       │
│   • Enforces Critical Combination Floor (Critical rules never lowered by ML)    │
│   • Enforces Zero-Signal Safety Cap (finalScore capped at <= 49 if no signals)   │
└───────────────────┬──────────────────────────────────────────┬───────────────────┘
                    │                                          │
                    ▼                                          ▼
┌──────────────────────────────────────┐   ┌───────────────────────────────────────┐
│     Deterministic Heuristic Engine   │   │       Pure Java ML Inference Layer    │
│ • UrlDetector (Typosquat, TLDs, etc) │   │ • TextClassifier:                     │
│ • TextDetector (Urgency, OTP, KYC)   │   │   Replicates scikit-learn TF-IDF,     │
│ • DigitalArrestDetector (Extortion)  │   │   lowercase, Unicode regex, n-grams,  │
│ • MaliciousAppDetector (.apk, ADB)   │   │   L2-norm & Logistic Regression.      │
│ • ScoringEngine:                     │   │ • UrlFeatureExtractor:                │
│   - Span Deduplication               │   │   9 structural & entropy features.    │
│   - Diminishing Returns (δ = 80%)    │   │ • UrlClassifier:                      │
│   - Combination Attack Multipliers   │   │   StandardScaler + LogisticRegression.│
│   - Discrete Levels: Low/Med/High/Cri│   │ • Zero Python runtime dependency.     │
└───────────────────▲──────────────────┘   └───────────────────▲───────────────────┘
                    │                                          │
                    │                                          │ JSON deserialization
┌───────────────────┴──────────────────┐   ┌───────────────────┴───────────────────┐
│  src/main/resources/rules.json       │   │  src/main/resources/ml/*.json         │
│  Single editable source of truth:    │   │  • text_model.json (vocab, idf, w, b) │
│  Weights, brands, phrases, ML config │   │  • url_model.json (features, μ, σ, w) │
└──────────────────────────────────────┘   └───────────────────────────────────────┘
```

---

## Machine Learning Pipeline & Parity

The machine-learning pipeline trains on real and synthetic cybersecurity datasets and exports lightweight JSON parameter maps for pure Java execution at runtime.

### Real Training Metrics (Printed by Training Scripts)

#### 1. Text Scam Classifier (`ml/train_text.py`)
- **Dataset:** 5,724 combined text messages (5,574 samples from UCI SMS Spam Collection + 150 synthetic Indian scam samples covering digital arrest, KYC cutoff, UPI rewards, and fake electricity bills).
- **Vectorizer:** `TfidfVectorizer(lowercase=True, ngram_range=(1, 2), token_pattern=r"(?u)\b\w+\b", max_features=5000, norm="l2")`.
- **Classifier:** `LogisticRegression(C=2.0, max_iter=1000, random_state=42)`.
- **Evaluation (20% Stratified Test Split: 1,145 samples):**
  - **Accuracy:** `98.52%` (0.9852)
  - **Precision:** `100.00%` (1.0000)
  - **Recall:** `90.23%` (0.9023)
  - **F1 Score:** `94.86%` (0.9486)
  - **Confusion Matrix:** `TN: 971 | FP: 0 | FN: 17 | TP: 157`

#### 2. Malicious URL Classifier (`ml/train_url.py`)
- **Dataset:** **200 synthetic URLs** (`ml/data/urls.csv`: 100 synthetic safe URLs + 100 synthetic malicious URLs).
- **Features Extracted (in order):** `url_length`, `dot_count`, `hyphen_count`, `digit_count`, `entropy`, `has_ip_host`, `suspicious_tld`, `uses_https`, `subdomain_count`.
- **Scaler & Classifier:** `StandardScaler` + `LogisticRegression(C=1.5, max_iter=1000, random_state=42)`.
- **Evaluation (20% Stratified Test Split: 40 synthetic URLs):**
  - **Accuracy:** `100.00%` on the 40 synthetic split URLs (**no real-world accuracy claim** — synthetic dataset only).
  - **Precision / Recall / F1:** `100.00%` on the synthetic split (`TN: 20 | FP: 0 | FN: 0 | TP: 20`).

### Zero-Python Runtime Parity
The Java classifiers (`TextClassifier`, `UrlFeatureExtractor`, and `UrlClassifier`) replicate scikit-learn's floating-point math directly:
- **Maximum observed error vs Python across all 20 test vectors:** $\le 0.000047$ (well within the $\le 0.001$ tolerance).
- Zero external native libraries, Python bridges, or network calls required at runtime.

---

## How Scoring Works

### 1. Heuristic Rule Scoring
- **Positional Span Filtering:** Overlapping signal matches are deduplicated by span priority to prevent double-counting.
- **Diminishing Returns Formula:** Signal point values are sorted descending and combined with geometric decay ($\delta = 0.80$):
  $$\text{Composite Score} = \sum_{i=0}^{n-1} \text{Points}_i \times (0.80)^i$$
- **Combination Attack Overrides:**
  - *Authority Impersonation + Payment Demand + Secrecy Coercion:* Guaranteed minimum score of **85** (`CRITICAL`).
  - *OTP Solicitation + Urgency + Suspicious Link:* Guaranteed minimum score of **65** (`HIGH`).

### 2. Machine Learning Scoring
- When `useMl` is true:
  $$\text{mlScore} = \text{round}\Big(\max(\text{textProbability}, \text{urlProbability}) \times 100\Big)$$
  where $\text{urlProbability}$ is the highest probability among all URLs found in the text ($0$ if no URLs are present).

### 3. Hybrid Blend & Safeguards
- **Weighted Blending:**
  $$\text{finalScore} = \text{round}(0.6 \times \text{ruleScore} + 0.4 \times \text{mlScore})$$
  *(Weights and parameters are configured in `rules.json`).*
- **Safe Message Guardrail:** If no rule signals fired (`signals.isEmpty()`), the ML contribution is strictly capped so that $\text{finalScore} \le 49$. This ensures ML can never escalate a benign message to `High` or `Critical` on its own.
- **Critical Override Floor:** A message triggering a Critical rule combination can never be downgraded by ML: if `ruleLevel == RiskLevel.CRITICAL`, the final level remains `CRITICAL` and $\text{finalScore} \ge \text{ruleScore}$.
- **When `useMl` is false:** The app behaves identically to the standalone rule engine, returning `ml = null`.

### 4. Risk Level Thresholds
- **Low (`0 – 24`):** Benign communication or minor stylistic cues.
- **Medium (`25 – 49`):** Suspicious elements detected; exercise caution.
- **High (`50 – 74`):** Multiple high-risk signals; do not engage or click.
- **Critical (`75 – 100`):** Severe scam or coercive extortion threat; stop all contact immediately.

---

## Requirements

- **Java Development Kit (JDK):** Version **17** or higher (tested with Eclipse Temurin OpenJDK 17, 21, and 25 LTS).
- **Build Tool:** Apache Maven 3.8+ (or use bundled `./mvnw` / `mvnw.cmd`).
- **Python (Optional, for offline retraining only):** Python 3.10+ with `scikit-learn`, `pandas`, and `numpy`.

---

## How to Run

### 1. Verify Java Environment
```bash
# Check Java version (must be >= 17)
java -version
```

### 2. Run via Maven Wrapper
```bash
# Linux / macOS:
./mvnw spring-boot:run

# Windows (PowerShell):
.\mvnw.cmd spring-boot:run
```
Open `http://localhost:8080` (or `http://localhost:8080/?present=1` for the collapsible presenter shortcuts).

### 3. Live LAN / Mobile Hotspot Demo Script (Windows)
```powershell
.\run-demo.ps1
```
Builds `target/cybershield-0.0.1-SNAPSHOT.jar` if missing or stale, detects your laptop's LAN IPv4 address, sets `PUBLIC_BASE_URL=http://<lan-ip>:8080`, starts the server, and prints the mobile URL for phones on the same Wi-Fi/hotspot.

### 4. Build & Run Standalone Executable JAR
```bash
# Package into executable fat JAR
./mvnw clean package -DskipTests

# Run JAR with zero dependencies (no Python needed)
java -jar target/cybershield-0.0.1-SNAPSHOT.jar
```

### Environment Variables
| Variable | Default | Purpose / If Missing |
| :--- | :--- | :--- |
| `PORT` | `8080` | HTTP port bound by Spring Boot (`server.port=${PORT:8080}`). |
| `SIGNING_SECRET` | *(32 random bytes at startup)* | HMAC-SHA256 key for `/api/verify/*` DemoPay QR links and chained receipts. If missing, an ephemeral key is generated on startup (links signed before restart fail verification after restart). |
| `PUBLIC_BASE_URL` | *(derived from `X-Forwarded-Host` / `Host` header)* | Base URL used when generating signed `/pay-demo.html?p=...&s=...` links & QR codes (e.g. `http://192.168.1.42:8080` or `https://your-app.onrender.com`). If missing, inferred from the incoming request host. |
| `UPI_SIGNING_SECRET` | *(32 random bytes at startup)* | HMAC-SHA256 key for `/api/pay/order` and `/api/pay/verify` in Tamper Lab. If missing, an ephemeral key is generated with a `DEV ONLY` warning (resets on Render restarts). |
| `CORS_ALLOWED_ORIGIN` | *(empty — same-origin only)* | Comma-separated origins allowed for `/api/pay/**` CORS requests (e.g. a deployed static GitHub Pages origin). If missing, cross-origin `/api/pay/**` requests are blocked by browser CORS policy. |

---

## How to Retrain the Models

To retrain the ML classifiers and regenerate the inference JSON parameter maps:

1. Install Python dependencies:
   ```bash
   pip install -r ml/requirements.txt
   ```
2. Run text classifier training:
   ```bash
   python ml/train_text.py
   ```
   *Exports to `src/main/resources/ml/text_model.json`.*

3. Run URL classifier training:
   ```bash
   python ml/train_url.py
   ```
   *Exports to `src/main/resources/ml/url_model.json`.*

4. Regenerate validation test vectors:
   ```bash
   python ml/export_test_vectors.py
   ```
   *Exports to `ml/test_vectors.json`.*

5. Verify Java parity by re-running Maven tests:
   ```bash
   ./mvnw test
   ```

---

## How to Add or Edit Rules in `rules.json`

All heuristic data, keywords, thresholds, and weights live in [`src/main/resources/rules.json`](file:///d:/Cybershield/src/main/resources/rules.json). Changes take effect upon restarting the application.

### 1. Adding a Brand for Typosquatting & Impersonation Detection
```json
{
  "name": "Kotak",
  "officialDomains": ["kotak.com", "kotakbank.com"]
}
```

### 2. Adding Suspicious TLDs or URL Shorteners
```json
"suspiciousTlds": ["xyz", "top", "buzz", "club", "online", "live"],
"urlShorteners": ["bit.ly", "tinyurl.com", "t.co", "cutt.ly"]
```

### 3. Adding Phishing, Digital Arrest, or App Phrases
```json
"phishingPhrases": [
  "account deactivated within 24 hours",
  "complete kyc verification immediately"
],
"digitalArrestPhrases": [
  "under digital arrest",
  "central bureau of investigation cyber cell",
  "transfer funds to safe account"
],
"maliciousAppPhrases": [
  "install our electricity bill app",
  "download this apk"
]
```

### 4. Tuning Weights and Hybrid Parameters
```json
"scoringThresholds": { "low": 0, "medium": 25, "high": 50, "critical": 75 },
"mlScoring": {
  "ruleWeight": 0.6,
  "mlWeight": 0.4,
  "noSignalCap": 49
}
```

---

## API Specification

`POST /api/analyze` accepts JSON and returns the full threat report:

### Request
```json
{
  "text": "Dear SBI customer, your bank account KYC has expired. Update immediately at http://sbi-kyc-verify-portal.xyz to avoid disruption.",
  "useMl": true
}
```

### Response
```json
{
  "score": 62,
  "level": "HIGH",
  "summary": "Multiple high-risk signals detected. Do not click links or share data.",
  "scamType": "PHISHING",
  "signals": [
    {
      "id": "text.kycThreat",
      "category": "TEXT",
      "points": 14,
      "explanation": "Threat of account suspension or KYC expiration detected.",
      "matchedText": "KYC has expired",
      "start": 37,
      "end": 52
    },
    {
      "id": "url.suspiciousTld",
      "category": "URL",
      "points": 10,
      "explanation": "URL uses the suspicious top-level domain '.xyz'.",
      "matchedText": "http://sbi-kyc-verify-portal.xyz",
      "start": 91,
      "end": 124
    }
  ],
  "urls": [
    "http://sbi-kyc-verify-portal.xyz"
  ],
  "ml": {
    "textProbability": 0.9178,
    "urlProbability": 0.9978,
    "topWords": ["http", "your", "kyc", "xyz", "at http"],
    "ruleScore": 37,
    "mlScore": 99
  }
}
```

---

## Running Tests

Execute the full suite of **196 JUnit tests** covering detectors, scoring math, Check/Verify/Pay endpoints, ML parity, scenario/i18n validation, robustness, and security headers:

```bash
# Run all tests
./mvnw test

# Run MockMvc integration tests only
./mvnw test -Dtest=AnalyzeControllerIntegrationTest

# Run pure Java ML parity tests only
./mvnw test -Dtest=MlClassifierTest

# Run robustness & security header tests only
./mvnw test -Dtest=RobustnessTest
```

---

## Known Limitations

1. **Heuristic Estimate, Not a Guarantee:** Cyber Shield provides a statistical and heuristic risk estimate. It is not an absolute warranty that an unflagged message has no risk, nor that a flagged message is malicious.
2. **ML Training Data Limits:**
   - The **Text Classifier** was trained on 5,574 UCI SMS Spam messages plus 150 synthetic Indian scam examples (`ml/data/indian_scams.csv`), and has sparse coverage for regional scripts outside English.
   - The **URL Classifier** was trained on **200 synthetic URLs** (`ml/data/urls.csv`) and makes **no real-world accuracy claim** on unseen production domains.
3. **Rule Coverage:** Novel scam phrasing, homoglyphs, or zero-width obfuscation not yet covered in `rules.json` may score lower.
4. **No Live URL Reputation Checks:** In strict adherence to the zero-network-connection guarantee, Cyber Shield never connects to remote servers, follows HTTP redirects, or queries live DNS/WHOIS databases.
5. **Verify Simulator Scope:** Verify demonstrates cryptographic receiver checks, HMAC-signed QR payloads, and hash-chained receipts against 5 fictional `Demo Bank` merchants (`DEMO: no real money`). Real-world adoption requires issuance by a merchant's bank or payment service provider.

---

## Disclaimer

> **Cyber Shield provides a heuristic risk estimate, not a legal or security guarantee.**
>
> When in doubt, **never click links, never make payments, never install unsolicited APKs**, and always verify communications directly through official banking numbers or the National Cyber Crime Reporting Portal (**1930** / **[cybercrime.gov.in](https://cybercrime.gov.in)**).
