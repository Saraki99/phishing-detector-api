"""
Generate a phishing URL dataset for training.
Creates a balanced CSV with legitimate and phishing URLs.
"""

import pandas as pd
import sys
from pathlib import Path
import random

# Fix file
sys.path.insert(0, str(Path(__file__).parent))

from api.feature_extractor import extract_features


def generate_dataset(output_path="data/phishing_urls.csv"):

    print("[*] Generating phishing URL dataset...")

    legitimate_urls = [
        "https://www.google.com/search?q=python+programming",
        "https://github.com/tensorflow/tensorflow",
        "https://stackoverflow.com/questions/123456/python-list",
        "https://www.wikipedia.org/wiki/Machine_learning",
    ]

    phishing_urls = [
        "http://paypal-secure-login.tk/update/account/verify?id=abc123",
        "http://google-account-verify.tk/signin/auth",
        "http://amazon-verify-account.xyz/signin/",
        "http://bank-of-america-secure.ml/online-banking/login",
        "http://netflix-account-verify.xyz/billing/update",
    ]

    urls = []
    labels = []

    # Legitimate URLs
    for url in legitimate_urls:
        urls.append(url)
        labels.append(0)

        if random.random() > 0.5:
            urls.append(url + "?ref=home&utm_source=google")
            labels.append(0)

    # Phishing URLs
    for url in phishing_urls:
        urls.append(url)
        labels.append(1)

        if random.random() > 0.5:
            noise = ''.join(random.choices('abcdef0123456789', k=8))
            urls.append(url + "&token=" + noise)
            labels.append(1)

    # Create DataFrame
    df = pd.DataFrame({
        "url": urls,
        "label": labels
    })

    # Shuffle dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Create output folder if needed
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    # Save CSV
    df.to_csv(output_path, index=False)

    print(f"[✓] Dataset saved: {output_path}")
    print(f"Total URLs: {len(df)}")
    print(f"Legitimate: {len(df[df['label'] == 0])}")
    print(f"Phishing: {len(df[df['label'] == 1])}")

    return df


if __name__  == "__main__":
    generate_dataset()
