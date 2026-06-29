
import pandas as pd
import requests
import io
from pathlib import Path

# Setup data directory
Path("data").mkdir(exist_ok=True)

# Target list lengths
TARGET_LEGIT = 150000
TARGET_PHISHING = 100000

# ---------------------------------------------------------
# 1. DOWNLOAD LEGITIMATE SITES (Tranco Top List)
# ---------------------------------------------------------
print("[*] Downloading Legitimate domains from Tranco...")
# Tranco supplies a fresh daily CSV of the top 1 million global domains
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

try:
    # Read zipped CSV directly into Pandas to save memory and local storage
    legit_df = pd.read_csv(TRANCO_URL, compression='zip', header=None, names=['rank', 'domain'])
    
    # Take what we need up to our target
    legit_domains = legit_df['domain'].head(TARGET_LEGIT * 2).dropna().tolist()
    
    # Convert domains to proper URLs since an AI needs lexical features like http/https
    legit_urls = []
    for idx, domain in enumerate(legit_domains):
        # Alternate prefixes evenly to teach your model that both http and https are valid
        prefix = "https://" if idx % 2 == 0 else "http://"
        legit_urls.append(f"{prefix}{domain}/")
        if len(legit_urls) >= TARGET_LEGIT:
            break
            
    print(f"[✓] Collected {len(legit_urls)} Legitimate URLs.")
except Exception as e:
    print(f"[!] Error fetching Tranco: {e}")
    legit_urls = []

# ---------------------------------------------------------
# 2. DOWNLOAD PHISHING SITES (OpenPhish + PhishTank)
# ---------------------------------------------------------
print("[*] Gathering Phishing URLs from threat feeds...")
phishing_urls = set()

# Feed A: OpenPhish Public Community Feed
OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
try:
    res = requests.get(OPENPHISH_URL, timeout=15)
    if res.status_code == 200:
        urls = [u.strip() for u in res.text.splitlines() if u.strip().startswith("http")]
        phishing_urls.update(urls)
        print(f"    -> Added {len(urls)} live URLs from OpenPhish")
except Exception as e:
    print(f"    -> Skipping OpenPhish due to error: {e}")

# Feed B: PhishTank Verified Archive (Aggregated Community Feed)
# PhishTank directly limits aggressive automated queries; pulling from a rolling Github mirror is highly reliable
PHISHTANK_MIRROR = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
try:
    res = requests.get(PHISHTANK_MIRROR, timeout=15)
    if res.status_code == 200:
        urls = [u.strip() for u in res.text.splitlines() if u.strip().startswith("http")]
        phishing_urls.update(urls)
        print(f"    -> Added URLs from PhishTank Active Mirror. Current unique total: {len(phishing_urls)}")
except Exception as e:
    print(f"    -> Skipping PhishTank Mirror due to error: {e}")

# Convert set back to list and trim to our target limit
phishing_urls = list(phishing_urls)[:TARGET_PHISHING]
print(f"[✓] Collected {len(phishing_urls)} Phishing URLs.")

# ---------------------------------------------------------
# 3. MERGE, BALANCING & EXPORT
# ---------------------------------------------------------
if len(legit_urls) == 0 or len(phishing_urls) == 0:
    print("[!] Critical Failure: One or both datasets failed to populate. Halting compile.")
else:
    print("[*] Assembling and shuffling unified dataset...")
    
    # Construct Pandas DataFrame
    df = pd.DataFrame({
        "url": legit_urls + phishing_urls,
        "label": [0] * len(legit_urls) + [1] * len(phishing_urls)
    })
    
    # Drop structural duplicates
    df.drop_duplicates(subset=['url'], inplace=True)
    
    # Shuffle completely so the AI doesn't pick up on ordering patterns
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

# Save output
    output_path = "data/big_urls.csv"
    df.to_csv(output_path, index=False)
    
    print("\n" + "="*40)
    print(f"[✓] DATASET COMPILE COMPLETE!")
    print(f"    Destination: {output_path}")
    print(f"    Total Rows:  {len(df)}")
    print(f"    Legit (0):   {len(df[df['label'] == 0])}")
    print(f"    Phish (1):   {len(df[df['label'] == 1])}")
    print("="*40)
