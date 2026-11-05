"""
train_text.py - Train SMS & Indian Scam Text Classifier using TfidfVectorizer + LogisticRegression.
Combines ml/data/sms_spam.tsv and ml/data/indian_scams.csv.
Exports vocabulary, idf, coefficients, and intercept to src/main/resources/ml/text_model.json.
"""

import os
import json
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def load_data():
    # 1. Load SMS Spam Collection TSV (label\ttext)
    sms_path = os.path.join("ml", "data", "sms_spam.tsv")
    print(f"Loading SMS spam data from {sms_path}...")
    sms_df = pd.read_csv(sms_path, sep="\t", header=None, names=["label_str", "text"], quoting=3, on_bad_lines="skip")
    sms_df = sms_df.dropna(subset=["text", "label_str"])
    sms_df["label"] = sms_df["label_str"].str.strip().str.lower().map({"spam": 1, "ham": 0})
    sms_df = sms_df.dropna(subset=["label"])
    sms_df["label"] = sms_df["label"].astype(int)
    sms_df = sms_df[["text", "label"]]
    print(f"Loaded {len(sms_df)} rows from SMS spam dataset (Spam: {sum(sms_df['label'] == 1)}, Ham: {sum(sms_df['label'] == 0)})")

    # 2. Load Indian Scams CSV (text,label)
    scam_path = os.path.join("ml", "data", "indian_scams.csv")
    print(f"Loading Indian scams data from {scam_path}...")
    scam_df = pd.read_csv(scam_path)
    scam_df = scam_df.dropna(subset=["text", "label"])
    scam_df["label"] = scam_df["label"].astype(int)
    print(f"Loaded {len(scam_df)} rows from Indian scams dataset (Scam: {sum(scam_df['label'] == 1)}, Safe: {sum(scam_df['label'] == 0)})")

    # 3. Combine datasets
    combined_df = pd.concat([sms_df, scam_df], ignore_index=True)
    combined_df["text"] = combined_df["text"].astype(str)
    print(f"Total combined dataset: {len(combined_df)} examples (Positive: {sum(combined_df['label'] == 1)}, Negative: {sum(combined_df['label'] == 0)})")
    return combined_df

def main():
    df = load_data()
    X = df["text"].values
    y = df["label"].values

    # Train / Test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\nTrain set: {len(X_train)} samples | Test set: {len(X_test)} samples")

    # Vectorizer parameters strictly as specified:
    # lowercase, word unigrams and bigrams only, token_pattern r"(?u)\b\w+\b", max_features 5000, l2 norm
    vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        token_pattern=r"(?u)\b\w+\b",
        max_features=5000,
        norm="l2"
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Train Logistic Regression
    clf = LogisticRegression(C=2.0, max_iter=1000, random_state=42)
    clf.fit(X_train_vec, y_train)

    # Evaluate on test set
    y_pred = clf.predict(X_test_vec)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)

    print("\n" + "=" * 50)
    print("       TEXT CLASSIFIER EVALUATION METRICS       ")
    print("=" * 50)
    print(f"Accuracy:  {acc:.4f} ({acc * 100:.2f}%)")
    print(f"Precision: {prec:.4f} ({prec * 100:.2f}%)")
    print(f"Recall:    {rec:.4f} ({rec * 100:.2f}%)")
    print(f"F1 Score:  {f1:.4f} ({f1 * 100:.2f}%)")
    print("\nConfusion Matrix:")
    print(f"  TN: {cm[0, 0]:<5} | FP: {cm[0, 1]:<5}")
    print(f"  FN: {cm[1, 0]:<5} | TP: {cm[1, 1]:<5}")
    print("=" * 50)

    # Retrain on full dataset for maximum vocabulary and parameter coverage
    print("\nFitting final model on complete dataset (5724 samples)...")
    X_full_vec = vectorizer.fit_transform(X)
    clf.fit(X_full_vec, y)

    # Export to src/main/resources/ml/text_model.json
    # vocabulary with index, idf, coefficients, intercept
    out_dir = os.path.join("src", "main", "resources", "ml")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "text_model.json")

    vocab = vectorizer.vocabulary_  # dict: term -> index
    idf = vectorizer.idf_.tolist()  # list of float idf values
    coefficients = clf.coef_[0].tolist()  # list of float weights
    intercept = float(clf.intercept_[0])

    model_data = {
        "model_type": "TfidfVectorizer + LogisticRegression",
        "lowercase": True,
        "ngram_range": [1, 2],
        "token_pattern": r"(?u)\b\w+\b",
        "norm": "l2",
        "max_features": 5000,
        "vocabulary_size": len(vocab),
        "vocabulary": {str(k): int(v) for k, v in vocab.items()},
        "idf": [round(val, 6) for val in idf],
        "coefficients": [round(val, 6) for val in coefficients],
        "intercept": round(intercept, 6),
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

    print(f"Exported text model to {out_path} ({os.path.getsize(out_path)} bytes)")

if __name__ == "__main__":
    main()

