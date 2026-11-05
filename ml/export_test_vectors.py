"""
export_test_vectors.py - Generates ml/test_vectors.json containing 10 test texts
and 10 test URLs along with their Python-predicted probabilities.
"""

import os
import json
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from train_url import extract_url_features, FEATURE_NAMES

def main():
    # 1. Load trained text model JSON
    text_model_path = os.path.join("src", "main", "resources", "ml", "text_model.json")
    with open(text_model_path, "r", encoding="utf-8") as f:
        text_model = json.load(f)

    vocab = text_model["vocabulary"]
    idf = np.array(text_model["idf"])
    text_coefs = np.array(text_model["coefficients"])
    text_intercept = text_model["intercept"]

    # Reconstruct vectorizer and classifier
    text_vectorizer = TfidfVectorizer(
        lowercase=True,
        ngram_range=(1, 2),
        token_pattern=r"(?u)\b\w+\b",
        max_features=5000,
        norm="l2"
    )
    # Set vocabulary and idf
    text_vectorizer.vocabulary_ = vocab
    text_vectorizer.idf_ = idf

    text_clf = LogisticRegression()
    text_clf.classes_ = np.array([0, 1])
    text_clf.coef_ = np.array([text_coefs])
    text_clf.intercept_ = np.array([text_intercept])

    # 10 test texts
    test_texts = [
        "This is Officer R. K. Verma from Central Bureau of Investigation. You are under digital arrest. Stay on video call and transfer funds to safe account for verification.",
        "Dear SBI user, your bank account KYC has expired. Your debit card will be blocked within 24 hours. Update immediately at http://sbi-kyc-verify-portal.xyz",
        "Your FedEx courier parcel #FDX-99821 is on hold at customs clearance. Pay customs duty fee of Rs 49 to release package: http://fedx-customs-clearance.top/track",
        "Urgent notice from Power Grid: Electricity connection will be disconnected tonight. Install our electricity bill app: http://quick-power-bill.org/payment.apk",
        "PhonePe: Congratulations! You have won Rs 2999 scratch card cashback in your wallet. Claim money directly to bank: http://phonepe-rewards.xyz",
        "Hi Rohit, please find the attached presentation slides and agenda for tomorrow's project review at 3 PM in the conference room. Let me know if you have additions.",
        "Dear customer, your OTP for login to HDFC Bank NetBanking is 591823. Valid for 10 minutes. Do not share OTP with anyone including bank staff.",
        "Your Zomato order from Biryani Blues has been picked up by delivery partner Amit and will arrive in approximately 25 minutes.",
        "IRCTC Train Ticket Confirmed: PNR #2458912344, Train 12951 Mumbai Rajdhani, Coach B3 Berth 45 (LB). Journey Date: 12-Nov-2026.",
        "Delhi Metro smart card recharge of Rs 200 was successful. Current balance is Rs 340. Thank you for using DMRC services."
    ]

    text_results = []
    for t in test_texts:
        vec = text_vectorizer.transform([t])
        prob_scam = float(text_clf.predict_proba(vec)[0, 1])
        pred = int(prob_scam >= 0.5)
        text_results.append({
            "text": t,
            "predicted_probability": round(prob_scam, 4),
            "prediction": pred,
            "label_name": "SCAM" if pred == 1 else "SAFE"
        })

    # 2. Load trained URL model JSON
    url_model_path = os.path.join("src", "main", "resources", "ml", "url_model.json")
    with open(url_model_path, "r", encoding="utf-8") as f:
        url_model = json.load(f)

    url_means = np.array(url_model["means"])
    url_stds = np.array(url_model["stds"])
    url_coefs = np.array(url_model["coefficients"])
    url_intercept = url_model["intercept"]

    url_scaler = StandardScaler()
    url_scaler.mean_ = url_means
    url_scaler.scale_ = url_stds

    url_clf = LogisticRegression()
    url_clf.classes_ = np.array([0, 1])
    url_clf.coef_ = np.array([url_coefs])
    url_clf.intercept_ = np.array([url_intercept])

    # 10 test URLs
    test_urls = [
        "http://sbi-kyc-verify-portal.xyz/login.php",
        "http://185.220.101.5/police/digital-arrest",
        "http://fedx-customs-clearance.top/track",
        "http://quick-power-bill.org/payment.apk",
        "http://phonpe-cashback-claim.top/scratch",
        "https://www.google.co.in",
        "https://onlinesbi.sbi",
        "https://netbanking.hdfcbank.com",
        "https://cybercrime.gov.in",
        "https://irctc.co.in"
    ]

    url_results = []
    for u in test_urls:
        feats = np.array([extract_url_features(u)])
        feats_scaled = url_scaler.transform(feats)
        prob_malicious = float(url_clf.predict_proba(feats_scaled)[0, 1])
        pred = int(prob_malicious >= 0.5)
        url_results.append({
            "url": u,
            "predicted_probability": round(prob_malicious, 4),
            "prediction": pred,
            "label_name": "MALICIOUS" if pred == 1 else "SAFE"
        })

    out_data = {
        "description": "Validation test vectors with Python-predicted probabilities for text and URL classifiers",
        "texts": text_results,
        "urls": url_results
    }

    out_file = os.path.join("ml", "test_vectors.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(out_data, f, indent=2)

    print(f"Exported test vectors to {out_file}")

if __name__ == "__main__":
    main()

