"""
train_url.py - Feature extraction and training for malicious URL detection.
Features extracted:
  1. url_length
  2. dot_count
  3. hyphen_count
  4. digit_count
  5. entropy
  6. has_ip_host
  7. suspicious_tld
  8. uses_https
  9. subdomain_count

Trains StandardScaler + LogisticRegression on ml/data/urls.csv.
Exports feature names in order, means, stds, coefficients, and intercept to src/main/resources/ml/url_model.json.
"""

import os
import json
import math
import re
import urllib.parse
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "site", "online", "work", "click", "buzz",
    "rest", "fit", "gq", "cf", "ga", "ml", "tk", "cc", "icu", "fun", "live", "vip"
}

FEATURE_NAMES = [
    "url_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "entropy",
    "has_ip_host",
    "suspicious_tld",
    "uses_https",
    "subdomain_count"
]

def calculate_entropy(text):
    if not text:
        return 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())

def extract_url_features(url):
    raw_url = str(url).strip()
    url_lower = raw_url.lower()

    # 1. URL Length
    url_length = len(raw_url)

    # 2. Dot Count
    dot_count = raw_url.count(".")

    # 3. Hyphen Count
    hyphen_count = raw_url.count("-")

    # 4. Digit Count
    digit_count = sum(c.isdigit() for c in raw_url)

    # 5. Shannon Entropy
    entropy = calculate_entropy(raw_url)

    # Parse host
    parsed = urllib.parse.urlparse(raw_url if "://" in raw_url else "http://" + raw_url)
    host = (parsed.netloc or "").split(":")[0].lower()

    # 6. Has IP Host flag
    is_ip = 1.0 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host) else 0.0

    # 7. Suspicious TLD flag
    tld = host.split(".")[-1] if "." in host else ""
    suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # 8. Uses HTTPS
    uses_https = 1.0 if url_lower.startswith("https://") else 0.0

    # 9. Subdomain Count
    host_parts = [p for p in host.split(".") if p]
    if len(host_parts) >= 3 and host_parts[-2] in ["co", "gov", "org", "net", "ac", "res", "gen"]:
        subdomain_count = max(0, len(host_parts) - 3)
    else:
        subdomain_count = max(0, len(host_parts) - 2)

    return [
        float(url_length),
        float(dot_count),
        float(hyphen_count),
        float(digit_count),
        float(entropy),
        float(is_ip),
        float(suspicious_tld),
        float(uses_https),
        float(subdomain_count)
    ]

def main():
    csv_path = os.path.join("ml", "data", "urls.csv")
    print(f"Loading URL dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    df = df.dropna(subset=["url", "label"])
    df["label"] = df["label"].astype(int)

    print(f"Loaded {len(df)} URLs (Safe: {sum(df['label'] == 0)}, Malicious: {sum(df['label'] == 1)})")

    # Extract features for all URLs
    X_list = [extract_url_features(u) for u in df["url"]]
    X = np.array(X_list)
    y = df["label"].values

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    # Standard Scaler
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Logistic Regression
    clf = LogisticRegression(C=1.5, max_iter=1000, random_state=42)
    clf.fit(X_train_scaled, y_train)

    # Evaluate on test set
    y_pred = clf.predict(X_test_scaled)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 50)
    print("        URL CLASSIFIER EVALUATION METRICS       ")
    print("=" * 50)
    print(f"Accuracy:  {acc:.4f} ({acc * 100:.2f}%)")
    print(f"Precision: {prec:.4f} ({prec * 100:.2f}%)")
    print(f"Recall:    {rec:.4f} ({rec * 100:.2f}%)")
    print(f"F1 Score:  {f1:.4f} ({f1 * 100:.2f}%)")
    print("\nConfusion Matrix:")
    print(f"  TN: {cm[0, 0]:<5} | FP: {cm[0, 1]:<5}")
    print(f"  FN: {cm[1, 0]:<5} | TP: {cm[1, 1]:<5}")
    print("=" * 50)

    # Feature Importance (Weights)
    print("\nFeature Coefficients (Model Weights):")
    for name, weight in zip(FEATURE_NAMES, clf.coef_[0]):
        print(f"  {name:<18}: {weight:+.4f}")
    print(f"  {'intercept':<18}: {clf.intercept_[0]:+.4f}")

    # Retrain on full dataset
    print("\nFitting final model on complete dataset (200 URLs)...")
    X_full_scaled = scaler.fit_transform(X)
    clf.fit(X_full_scaled, y)

    # Export to src/main/resources/ml/url_model.json
    out_dir = os.path.join("src", "main", "resources", "ml")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "url_model.json")

    model_data = {
        "model_type": "StandardScaler + LogisticRegression",
        "features": FEATURE_NAMES,
        "means": [round(val, 6) for val in scaler.mean_.tolist()],
        "stds": [round(val, 6) for val in scaler.scale_.tolist()],
        "coefficients": [round(val, 6) for val in clf.coef_[0].tolist()],
        "intercept": round(float(clf.intercept_[0]), 6),
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "confusion_matrix": cm.tolist()
        }
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(model_data, f, indent=2)

    print(f"Exported URL model to {out_path} ({os.path.getsize(out_path)} bytes)")

if __name__ == "__main__":
    main()

