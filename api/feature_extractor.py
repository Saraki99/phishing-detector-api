
"""
Feature Extractor - Converts raw URLs into numerical features
for the machine learning model.
"""

import re
import math
from urllib.parse import urlparse


# Suspicious TLDs commonly used by phishers
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.club', '.work', '.loan', '.click', '.download',
    '.review', '.bid', '.date', '.win'
]

# Keywords that appear in phishing URLs
SENSITIVE_WORDS = [
    'login', 'signin', 'verify', 'secure', 'update',
    'confirm', 'account', 'paypal', 'bank', 'ebay',
    'amazon', 'apple', 'google', 'microsoft',
    'netflix', 'password', 'credential',
    'authenticate', 'wallet', 'payment',
    'invoice', 'bonus', 'free', 'winner',
    'prize', 'refund', 'security'
]

# Known URL shortener domains
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
    'ow.ly', 'is.gd', 'buff.ly', 'adf.ly',
    'shorturl.at', 'cutt.ly', 'rb.gy',
    'tiny.cc', 'tr.im', 'bit.do', 'soo.gd',
    'gg.gg'
]

# Well-known brands targeted by phishers
BRAND_NAMES = [
    'paypal', 'google', 'facebook', 'apple',
    'amazon', 'microsoft', 'netflix',
    'instagram', 'twitter', 'linkedin',
    'whatsapp', 'bank', 'chase',
    'wellsfargo', 'hsbc', 'barclays',
    'dropbox', 'adobe'
]


def compute_entropy(text):
    """
    Calculate Shannon entropy of a string.
    Higher entropy often means more random-looking text.
    """
    if not text:
        return 0.0

    probabilities = [text.count(c) / len(text) for c in set(text)]
    entropy = -sum(p * math.log2(p) for p in probabilities)
    return round(entropy, 4)


def extract_features(url):
    """
    Extract numerical features from a URL.
    Returns a dictionary of feature_name -> value.
    """

    url = str(url).strip().lower()
    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    parts = hostname.split(".")

    if len(parts) >= 2:
        tld = "." + parts[-1]
        domain_name = parts[-2]
        subdomain_parts = parts[:-2]
    else:
        tld = ""
        domain_name = hostname
        subdomain_parts = []

    subdomain = ".".join(subdomain_parts)

    features = {}

    # Basic URL features
    features["url_length"] = len(url)
    features["hostname_length"] = len(hostname)
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    features["fragment_length"] = len(fragment)

    # Character counts
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = url.count("-")
    features["num_slashes"] = url.count("/")
    features["num_question_marks"] = url.count("?")
    features["num_equals"] = url.count("=")
    features["num_at_sign"] = url.count("@")
    features["num_ampersands"] = url.count("&")
    features["num_hashes"] = url.count("#")
    features["num_underscores"] = url.count("_")
    features["num_percent"] = url.count("%")

    # Character composition
    features["num_digits"] = sum(c.isdigit() for c in url)
    features["num_letters"] = sum(c.isalpha() for c in url)

    total_chars = max(len(url), 1)

    features["digit_ratio"] = round(
        features["num_digits"] / total_chars, 4
    )

    features["letter_ratio"] = round(
        features["num_letters"] / total_chars, 4
    )

    features["special_char_ratio"] = round(
        (
            total_chars
            - features["num_digits"]
            - features["num_letters"]
        ) / total_chars,
        4
    )

    # Domain features
    features["domain_length"] = len(domain_name)
    features["subdomain_length"] = len(subdomain)
    features["num_subdomains"] = len(subdomain_parts)

    features["has_ip_address"] = int(
        bool(
            re.match(
                r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
                hostname
            )
        )
    )

    features["has_https"] = int(parsed.scheme == "https")

    features["is_suspicious_tld"] = int(
        tld in SUSPICIOUS_TLDS
    )

    features["has_port"] = int(parsed.port is not None)

# Path analysis
    path_tokens = [
        token
        for token in re.split(r"[\/\-_.?=&]", path)
        if token
    ]

    features["num_path_tokens"] = len(path_tokens)

    features["longest_token_length"] = max(
        [len(t) for t in path_tokens],
        default=0
    )

    features["avg_token_length"] = round(
        sum(len(t) for t in path_tokens)
        / max(len(path_tokens), 1),
        4
    )

    features["path_entropy"] = compute_entropy(path)

    # Sensitive keywords
    features["num_sensitive_words"] = sum(
        1 for word in SENSITIVE_WORDS
        if word in url
    )

    # URL shortener
    features["is_shortened_url"] = int(
        hostname in URL_SHORTENERS
    )

    # Entropy
    features["domain_entropy"] = compute_entropy(
        domain_name
    )

    features["full_domain_entropy"] = compute_entropy(
        hostname
    )

    # Risk score
    features["url_complexity_score"] = (
        features["url_length"]
        + features["num_subdomains"] * 10
        + features["num_percent"] * 5
        + features["num_sensitive_words"] * 15
        + features["num_at_sign"] * 50
    )

    # TLD in path
    known_tlds = [
        ".com", ".org", ".net",
        ".io", ".co", ".uk",
        ".de", ".ru"
    ]

    features["tld_in_path"] = int(
        any(tld_item in path for tld_item in known_tlds)
    )

    # Brand impersonation
    features["brand_in_domain"] = int(
        any(
            brand in domain_name
            for brand in BRAND_NAMES
        )
    )

    # Special characters
    special_chars = set(
        re.findall(r"[^a-zA-Z0-9]", url)
    )

    features["unique_special_chars"] = len(
        special_chars
    )

    # Repeated characters
    repeats = re.findall(
        r"([a-zA-Z0-9])\1{2,}",
        url
    )

    features["consecutive_char_repeat"] = len(
        repeats
    )

    # Double slash in path
    features["double_slash_in_path"] = int(
        "//" in path
    )

    # Numeric domain
    features["numeric_domain"] = int(
        domain_name.isdigit()
    )

    return features


def get_feature_names():
    """
    Return numerical feature names.
    """
    dummy = extract_features("http://example.com")
    return [
        key
        for key in dummy.keys()
        if key != "tld"
    ]
