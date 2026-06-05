# ============================================================
# email_parser.py
# Email parsing and feature extraction module
# Parses raw email JSON from the browser extension and
# extracts structured features for downstream analysis
# ============================================================

import re
import os
import sys
from urllib.parse import urlparse
from bs4 import BeautifulSoup

# Ensure Support_Files is in the path for importing config.py
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Support_Files'))

try:
    from config import PHISHING_KEYWORDS, SUBJECT_KEYWORDS
except ImportError:
    # Fallbacks in case config is not accessible during testing
    PHISHING_KEYWORDS = [
        'click', 'verify', 'account', 'password', 'urgent',
        'bank', 'login', 'update', 'confirm', 'secure',
        'winner', 'prize', 'free', 'offer', 'limited',
        'suspend', 'validate', 'expire', 'immediate', 'alert'
    ]
    SUBJECT_KEYWORDS = [
        'urgent', 'verify', 'suspended', 'winner',
        'congratulations', 'alert', 'confirm', 'free'
    ]


def parse_email(data):
    """
    Parses raw email JSON from the browser extension and extracts structured features.
    
    Args:
        data (dict): JSON payload from app.py /analyze endpoint containing:
            - subject (str)
            - body (str)
            - sender (str)
            - receiver (str)
            - headers (dict)
            - urls (list of strings)
            
    Returns:
        dict: Parsed email object.
    """
    subject = data.get('subject', '').strip()
    raw_body = data.get('body', '').strip()
    sender = data.get('sender', '').strip()
    receiver = data.get('receiver', '').strip()
    headers_input = data.get('headers', {})
    raw_urls = data.get('urls', [])

    # 1. Clean HTML from body if tags are present
    has_html_tags = int(bool(re.search(r'<[^>]+>', raw_body)))
    if has_html_tags:
        try:
            soup = BeautifulSoup(raw_body, 'html.parser')
            body = soup.get_text()
        except Exception:
            body = raw_body
    else:
        body = raw_body

    # Clean up excessive whitespace in body
    body = re.sub(r'\s+', ' ', body).strip()

    # 2. Normalize sender address
    sender_email = extract_email_address(sender)

    # 3. Parse and enrich URLs
    parsed_urls = []
    # Deduplicate raw URLs
    seen_urls = set()
    for url in raw_urls:
        if not url:
            continue
        url_clean = url.strip()
        if url_clean not in seen_urls:
            seen_urls.add(url_clean)
            parsed_urls.append(enrich_url(url_clean))

    # 4. Extract Auth Headers and Security Info
    headers = parse_headers(headers_input, sender_email)

    # 5. Extract Text Features
    text_features = extract_text_features(subject, body, has_html_tags)

    # 6. Generate Flags
    flags = generate_flags(headers, parsed_urls, text_features)

    return {
        'sender': sender_email,
        'subject': subject,
        'body': body,
        'urls': parsed_urls,
        'flags': flags,
        'text_features': text_features,
        'headers': headers
    }


def extract_email_address(email_str):
    """
    Extracts raw email address from sender format (e.g. "John Doe <john@example.com>")
    """
    if not email_str:
        return ""
    # Try angle bracket pattern first
    match = re.search(r'<([^>]+)>', email_str)
    if match:
        return match.group(1).strip()
    # Fall back to matching standard email pattern
    match = re.search(r'[\w\.-]+@[\w\.-]+', email_str)
    if match:
        return match.group(0).strip()
    return email_str.strip()


def enrich_url(url_str):
    """
    Computes local metadata fields for an extracted URL
    """
    parsed_url_str = url_str
    if not url_str.startswith(('http://', 'https://')):
        # Prepend http:// to ensure urlparse parses it correctly
        parsed_url_str = 'http://' + url_str

    try:
        parsed = urlparse(parsed_url_str)
        domain = parsed.netloc.split(':')[0]  # strip port if any
        path = parsed.path
        query = parsed.query
    except Exception:
        domain = ""
        path = ""
        query = ""

    has_https = url_str.lower().startswith('https://')
    
    # Check if domain is an IP address
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    has_ip = bool(re.match(ip_pattern, domain))

    return {
        'raw': url_str,
        'domain': domain,
        'path': path,
        'query': query,
        'has_https': has_https,
        'has_ip': has_ip
    }


def parse_headers(headers_input, sender_email):
    """
    Normalizes security and authentication headers
    """
    spf_raw = str(headers_input.get('received-spf', headers_input.get('spf', ''))).lower()
    dkim_raw = str(headers_input.get('dkim-signature', headers_input.get('dkim', ''))).lower()
    dmarc_raw = str(headers_input.get('authentication-results', headers_input.get('dmarc', ''))).lower()

    # Extract originating IP from received headers
    received = headers_input.get('received', '')
    originating_ip = None
    if received:
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', received)
        if ip_match:
            originating_ip = ip_match.group(0)

    # Check for Reply-To mismatch
    reply_to_raw = headers_input.get('reply-to', '')
    reply_to_email = extract_email_address(reply_to_raw)
    reply_to_mismatch = False
    if sender_email and reply_to_email:
        reply_to_mismatch = (sender_email.lower() != reply_to_email.lower())

    def normalize_status(raw_val):
        if not raw_val:
            return 'unknown'
        for status in ['pass', 'fail', 'neutral', 'softfail', 'none']:
            if status in raw_val:
                return status
        return 'unknown'

    return {
        'spf': normalize_status(spf_raw),
        'dkim': normalize_status(dkim_raw),
        'dmarc': normalize_status(dmarc_raw),
        'originating_ip': originating_ip,
        'reply_to_mismatch': reply_to_mismatch
    }


def extract_text_features(subject, body, has_html_tags):
    """
    Extracts features from subject and body matching training configurations
    """
    body_lower = body.lower()
    
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in body_lower)
    
    subject_lower = subject.lower()
    suspicious_subject = int(any(kw in subject_lower for kw in SUBJECT_KEYWORDS))
    
    exclamation_count = body.count('!')
    
    capital_ratio = 0.0
    if len(body) > 0:
        capital_ratio = sum(1 for c in body if c.isupper()) / len(body)
        
    return {
        'keyword_count': keyword_count,
        'suspicious_subject': suspicious_subject,
        'exclamation_count': exclamation_count,
        'capital_ratio': capital_ratio,
        'has_html': has_html_tags
    }


def generate_flags(headers, parsed_urls, text_features):
    """
    Generates human-readable warnings and flags based on parsed details
    """
    flags = []
    
    if headers.get('spf') == 'fail':
        flags.append("Failed SPF authentication check")
    if headers.get('dkim') == 'fail':
        flags.append("Failed DKIM authentication check")
    if headers.get('dmarc') == 'fail':
        flags.append("Failed DMARC authentication check")
        
    if headers.get('reply_to_mismatch'):
        flags.append("Reply-To mismatch detected (sender domain differs from reply path)")
        
    if headers.get('originating_ip'):
        flags.append(f"Originating server IP identified: {headers['originating_ip']}")
        
    # URL flags
    has_non_https = any(not u.get('has_https') for u in parsed_urls)
    has_ip_as_domain = any(u.get('has_ip') for u in parsed_urls)
    
    if has_non_https:
        flags.append("Email contains links using insecure HTTP connections")
    if has_ip_as_domain:
        flags.append("Email contains links using raw IP addresses instead of domain names")
    if len(parsed_urls) > 5:
        flags.append(f"High density of links in email body ({len(parsed_urls)} URLs)")
        
    # Text flags
    if text_features.get('keyword_count', 0) >= 5:
        flags.append(f"High concentration of common phishing keywords ({text_features['keyword_count']})")
    if text_features.get('suspicious_subject'):
        flags.append("Subject line contains urgency or security alerts")
    if text_features.get('capital_ratio', 0) > 0.3:
        flags.append(f"High percentage of uppercase text ({text_features['capital_ratio']:.0%}), suggesting urgency")
    if text_features.get('has_html'):
        flags.append("Email body contains HTML formatting (possible link masking)")
        
    return flags
