
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
    '.club', '.work', '.loan', '.click', '.download', '.review',
    '.bid', '.date', '.men', '.win', '.trade', '.webcam', '.science',
    '.racing', '.party', '.accountant', '.faith', '.men', '.download',
    '.rapid', '.review', '.loan', '.win', '.bid'
]

# Keywords that appear in phishing URLs
SENSITIVE_WORDS = [
    'login', 'signin', 'verify', 'secure', 'update',
    'confirm', 'account', 'paypal', 'bank', 'ebay', 'amazon',
    'apple', 'google', 'microsoft', 'netflix', 'password',
    'credential', 'authenticate', 'wallet', 'payment', 'invoice',
    'bonus', 'free', 'winner', 'prize', 'refund', 'security'
]

# Known URL shortener domains
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'shorturl.at', 'cutt.ly', 'rb.gy',
    'tiny.cc', 'tr.im', 'bit.do', 'soo.gd', 'gg.gg'
]

# Well-known brand names targeted by phishers
BRAND_NAMES = [
    'paypal', 'google', 'facebook', 'apple', 'amazon',
    'microsoft', 'netflix', 'instagram', 'twitter',
    'linkedin', 'whatsapp', 'bank', 'secure', 'chase',
    'wellsfargo', 'hsbc', 'barclays', 'dropbox', 'adobe'
]


def compute_entropy(text):
    """
    Calculate Shannon entropy of a string.
    High entropy = random-looking = more suspicious.
    """
    if not text:
        return 0.0
    text = str(text)
    prob = [text.count(c) / len(text) for c in set(text)]
    entropy = -sum(p * math.log2(p) for p in prob)
    return round(entropy, 4)


def extract_features(url):
    """
    Extract 30+ numerical features from a URL.
    Returns a dictionary of feature_name -> value.
    All values are numbers (int or float) for ML model input.
    """
    url = str(url).strip().lower()
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment
    full_url = url

    # ──────────────────────────────────────────────
    # 1. Basic structural features
    # ──────────────────────────────────────────────
    features = {
        'url_length': len(full_url),
        'hostname_length': len(hostname),
        'path_length': len(path),
        'query_length': len(query),
        'fragment_length': len(fragment),
    }

    # ──────────────────────────────────────────────
    # 2. Special character counts
    # ──────────────────────────────────────────────
    features['num_dots'] = full_url.count('.')
    features['num_hyphens'] = full_url.count('-')
    features['num_slashes'] = full_url.count('/')
    features['num_question_marks'] = full_url.count('?')
    features['num_equals'] = full_url.count('=')
    features['num_at_sign'] = full_url.count('@')
    features['num_ampersands'] = full_url.count('&')
    features['num_hashes'] = full_url.count('#')
    features['num_underscores'] = full_url.count('_')
    features['num_tildes'] = full_url.count('~')
    features['num_percent'] = full_url.count('%')
    features['num_exclamation'] = full_url.count('!')
    features['num_stars'] = full_url.count('*')

    # ──────────────────────────────────────────────
    # 3. Character composition
    # ──────────────────────────────────────────────
    features['num_digits'] = sum(c.isdigit() for c in full_url)
    features['num_letters'] = sum(c.isalpha() for c in full_url)
    total_chars = max(len(full_url), 1)
    features['digit_ratio'] = round(features['num_digits'] / total_chars, 4)
    features['letter_ratio'] = round(features['num_letters'] / total_chars, 4)
    features['special_char_ratio'] = round(
        (total_chars - features['num_digits'] - features['num_letters']) / total_chars, 4
    )

# ──────────────────────────────────────────────
    # 4. Domain-level features
    # ──────────────────────────────────────────────
    # Parse domain parts
    parts = hostname.split('.')
    if len(parts) >= 2:
        tld = '.' + str(parts[-1])
        domain_name = str(parts[-2]) if len(parts) >= 2 else ''
        subdomain_parts = parts[:-2] if len(parts) > 2 else []
        subdomain = '.'.join(subdomain_parts)
    else:
        tld = ''
        domain_name = hostname
        subdomain = ''
        subdomain_parts = []

    features['tld'] = tld
    features['domain_length'] = len(domain_name)
    features['num_subdomains'] = len(subdomain_parts)
    features['subdomain_length'] = len(subdomain)

    # IP address as hostname?
    features['has_ip_address'] = 1 if re.match(
        r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname
    ) else 0

    # HTTPS?
    features['has_https'] = 1 if parsed.scheme == 'https' else 0

    # Suspicious TLD?
    features['is_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0

    # Port number in URL?
    features['has_port'] = 1 if parsed.port else 0

    # ──────────────────────────────────────────────
    # 5. Path token analysis
    # ──────────────────────────────────────────────
    path_tokens = [t for t in re.split(r'[/\-_.?=&]', path) if t]
    features['num_path_tokens'] = len(path_tokens)
    features['longest_token_length'] = max([len(t) for t in path_tokens], default=0)
    features['avg_token_length'] = round(
        sum(len(t) for t in path_tokens) / max(len(path_tokens), 1), 4
    )
    features['path_entropy'] = compute_entropy(path)

    # ──────────────────────────────────────────────
    # 6. Sensitive word detection
    # ──────────────────────────────────────────────
    features['num_sensitive_words'] = sum(
        1 for word in SENSITIVE_WORDS if word in full_url
    )

    # ──────────────────────────────────────────────
    # 7. URL shortener check
    # ──────────────────────────────────────────────
    features['is_shortened_url'] = 1 if hostname in URL_SHORTENERS else 0

    # ──────────────────────────────────────────────
    # 8. Domain entropy (random-looking = suspicious)
    # ──────────────────────────────────────────────
    features['domain_entropy'] = compute_entropy(domain_name)
    features['full_domain_entropy'] = compute_entropy(hostname)

    # ──────────────────────────────────────────────
    # 9. Composite risk score
    # ──────────────────────────────────────────────
    features['url_complexity_score'] = (
        features['url_length'] +
        features['num_subdomains'] * 10 +
        features['num_percent'] * 5 +
        features['num_sensitive_words'] * 15 +
        features['num_at_sign'] * 50 +
        features['num_exclamation'] * 20
    )

    # ──────────────────────────────────────────────
    # 10. TLD in path (deception technique)
    # ──────────────────────────────────────────────
    known_tlds = ['.com', '.org', '.net', '.io', '.co', '.uk', '.de', '.ru']
    features['tld_in_path'] = 1 if any(t in path for t in known_tlds) else 0

    # ──────────────────────────────────────────────
    # 11. Brand impersonation in domain
    # ──────────────────────────────────────────────
    features['brand_in_domain'] = 1 if any(
        brand in domain_name for brand in BRAND_NAMES
    ) else 0

    # ──────────────────────────────────────────────
    # 12. Unique special character types
    # ──────────────────────────────────────────────
    special_chars = set(re.findall(r'[^a-zA-Z0-9]', full_url))
    features['unique_special_chars'] = len(special_chars)

    # ──────────────────────────────────────────────
    # 13. Repeated characters (suspicious)
    # ──────────────────────────────────────────────
    features['consecutive_char_repeat'] = 0
    repeats = re.findall(r'([a-zA-Z0-9])\1{2,}', full_url)
    features['consecutive_char_repeat'] = len(repeats)

# ──────────────────────────────────────────────
    # 14. Check for double slash in path
    # ──────────────────────────────────────────────
    features['double_slash_in_path'] = 1 if '//' in path else 0

    # ──────────────────────────────────────────────
    # 15. Numeric domain (e.g., 123456.com is suspicious)
    # ──────────────────────────────────────────────
    features['numeric_domain'] = 1 if domain_name.isdigit() else 0

    return features


def get_feature_names():
    """Return list of numerical feature names (excludes 'tld')."""
    dummy = extract_features("http://example.com")
    return [k for k in dummy.keys() if k != 'tld']
