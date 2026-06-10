# ============================================================
# ml_classifier.py
# Loads trained LightGBM models and runs predictions
# Uses both email model and URL model to produce
# a unified phishing probability score
# ============================================================

import re
import json
import numpy as np
import pandas as pd
import scipy.sparse as sp
import joblib
import lightgbm as lgb
from config import (
    EMAIL_MODEL_PATH,
    URL_MODEL_PATH,
    TFIDF_VECTORIZER_PATH,
    SCALER_PATH,
    URL_FEATURE_NAMES_PATH,
    MODEL_METADATA_PATH,
    ML_THRESHOLD,
    PHISHING_KEYWORDS,
    SUBJECT_KEYWORDS
)
from transformer_classifier import (
    predict_transformer
)

from xai_engine import (
    explain_keywords,
    explain_url_risk,
    build_confidence_breakdown,
    explain_model_features,
    generate_shap_explanation
)

# ──────────────────────────────────────────────────────────
# MODEL LOADER
# Loaded once at startup — not on every request
# ──────────────────────────────────────────────────────────

_email_model    = None
_url_model      = None
_tfidf          = None
_scaler         = None
_url_feat_names = None
_metadata       = None


def load_models():
    """
    Loads all models and vectorizers from disk
    Called once when app.py starts
    """
    global _email_model, _url_model, _tfidf
    global _scaler, _url_feat_names, _metadata

    print("[ml_classifier] Loading models...")

    try:
        _email_model    = joblib.load(EMAIL_MODEL_PATH)
        print(f"  Email model loaded     : {EMAIL_MODEL_PATH}")
    except Exception as e:
        print(f"  ERROR loading email model : {e}")
        raise

    try:
        _url_model      = joblib.load(URL_MODEL_PATH)
        print(f"  URL model loaded       : {URL_MODEL_PATH}")
    except Exception as e:
        print(f"  ERROR loading URL model   : {e}")
        raise

    try:
        _tfidf          = joblib.load(TFIDF_VECTORIZER_PATH)
        print(f"  TF-IDF loaded          : {TFIDF_VECTORIZER_PATH}")
    except Exception as e:
        print(f"  ERROR loading TF-IDF      : {e}")
        raise

    try:
        _scaler         = joblib.load(SCALER_PATH)
        print(f"  Scaler loaded          : {SCALER_PATH}")
    except Exception as e:
        print(f"  ERROR loading scaler      : {e}")
        raise

    try:
        _url_feat_names = joblib.load(URL_FEATURE_NAMES_PATH)
        print(f"  URL feature names loaded : {URL_FEATURE_NAMES_PATH}")
    except Exception as e:
        print(f"  ERROR loading feature names : {e}")
        raise

    try:
        with open(MODEL_METADATA_PATH, 'r') as f:
            _metadata   = json.load(f)
        print(f"  Metadata loaded        : {MODEL_METADATA_PATH}")
    except Exception as e:
        print(f"  ERROR loading metadata    : {e}")
        raise

    print("[ml_classifier] All models loaded successfully")

# ──────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ──────────────────────────────────────────────────────────


def run_ml_classifier(parsed_email):
    """
    Main function called by app.py
    Accepts parsed email object from email_parser.py
    Returns ML scores for email, transformer and URL models
    """

    if _email_model is None:
        raise RuntimeError(
            "Models not loaded. Call load_models() first."
        )

    results = {
        'email_phishing_probability': 0.0,
        'transformer_probability': 0.0,
        'ensemble_probability': 0.0,
        'url_phishing_probability': 0.0,
        'email_prediction': 0,
        'url_prediction': 0,
        'combined_probability': 0.0,
        'combined_prediction': 0,
        'email_model_used': True,
        'url_model_used': False,
        'model_info': {},
        'error': None
    }

    # ── Run Email + Transformer Models ──────────────────────
    try:

        email_prob = predict_email(
            parsed_email
        )

        subject = parsed_email.get(
            'subject',
            ''
        )

        body = parsed_email.get(
            'body',
            ''
        )

        transformer_text = (
            subject + ' ' + body
        )

        transformer_prob = (
            predict_transformer(
                transformer_text
            )
        )

        results[
            'email_phishing_probability'
        ] = round(
            email_prob,
            4
        )

        results[
            'transformer_probability'
        ] = round(
            transformer_prob,
            4
        )

        results[
            'email_prediction'
        ] = int(
            email_prob >= ML_THRESHOLD
        )

        # Ensemble score
        ensemble_prob = (
            0.7 * email_prob +
            0.3 * transformer_prob
        )

        results[
            'ensemble_probability'
        ] = round(
            ensemble_prob,
            4
        )

    except Exception as e:

        results[
            'error'
        ] = (
            f"Email model error: {str(e)}"
        )

        print(
            f"[ml_classifier] Email model error: {e}"
        )

    # ── Run URL Model ───────────────────────────────────────
    urls = parsed_email.get(
        'urls',
        []
    )

    if urls:

        try:

            url_prob = predict_url(
                urls[0]
            )

            results[
                'url_phishing_probability'
            ] = round(
                url_prob,
                4
            )

            results[
                'url_prediction'
            ] = int(
                url_prob >= ML_THRESHOLD
            )

            results[
                'url_model_used'
            ] = True

        except Exception as e:

            results[
                'error'
            ] = (
                f"URL model error: {str(e)}"
            )

            print(
                f"[ml_classifier] URL model error: {e}"
            )

    else:

        results[
            'url_phishing_probability'
        ] = 0.0

        results[
            'url_model_used'
        ] = False

    # ── Existing Combined Score ─────────────────────────────
    results[
        'combined_probability'
    ] = calculate_combined_score(
        results[
            'email_phishing_probability'
        ],
        results[
            'url_phishing_probability'
        ],
        results[
            'url_model_used'
        ]
    )

    results[
        'combined_prediction'
    ] = int(
        results[
            'combined_probability'
        ] >= ML_THRESHOLD
    )

    # ── Model Metadata ──────────────────────────────────────
    results[
        'model_info'
    ] = build_model_info(
        results
    )

        # ── XAI Explanations ─────────────────────────

    subject = parsed_email.get(
        'subject',
        ''
    )

    body = parsed_email.get(
        'body',
        ''
    )

    keyword_explanation = explain_keywords(
        subject,
        body,
        PHISHING_KEYWORDS
    )

    url_risks = []

    urls = parsed_email.get(
        'urls',
        []
    )

    if urls:
        try:
            url_features = extract_url_features(
                urls[0]
            )

            url_risks = explain_url_risk(
                url_features
            )

        except Exception:
            pass

    # ── SHAP Explanation ───────────────────────

    shap_explanation = {
        "status": "unavailable"
    }

    try:

        feature_vector = get_email_feature_vector(
            parsed_email
        )

        feature_names = (
            _email_model
            .feature_name()
        )

        shap_explanation = (
            generate_shap_explanation(
                _email_model,
                feature_vector,
                feature_names
            )
        )

    except Exception as e:

         shap_explanation = {
            "error": str(e)
        }

    results['explanation'] = {

        'keywords': keyword_explanation,

        'url_risks': url_risks,

        'feature_importance':
            explain_model_features(
                _email_model,
                _tfidf
            ),

        'shap':
            shap_explanation,

        'confidence_breakdown':
            build_confidence_breakdown(
                results[
                    'email_phishing_probability'
                ],
                results[
                    'url_phishing_probability'
                ],
                results[
                    'combined_probability'
                ]
            )
    }

    print(
        f"[ml_classifier] "
        f"Email prob: {results['email_phishing_probability']:.4f} | "
        f"URL prob: {results['url_phishing_probability']:.4f} | "
        f"Combined: {results['combined_probability']:.4f}"
    )

    return results
   
    print(
        f"[ml_classifier] "
        f"Email: {results['email_phishing_probability']:.4f} | "
        f"Transformer: {results['transformer_probability']:.4f} | "
        f"Ensemble: {results['ensemble_probability']:.4f} | "
        f"URL: {results['url_phishing_probability']:.4f} | "
        f"Combined: {results['combined_probability']:.4f}"
    )

    return results

# ──────────────────────────────────────────────────────────
# EMAIL MODEL PREDICTION
# ──────────────────────────────────────────────────────────

def predict_email(parsed_email):
    """
    Prepares email features and runs the LightGBM email model
    Mirrors the exact feature engineering from the notebook
    """
    subject = parsed_email.get('subject', '')
    body    = parsed_email.get('body', '')

    # ── Step 1: Clean text (mirrors notebook pipeline) ────
    cleaned_text = clean_text_for_ml(subject, body)

    # ── Step 2: TF-IDF features ───────────────────────────
    tfidf_features = _tfidf.transform([cleaned_text]).astype('float32')

    # ── Step 3: Hand-crafted features ─────────────────────
    hand_features  = extract_hand_features(subject, body, parsed_email)
    hand_sparse    = sp.csr_matrix(
        np.array(hand_features).reshape(1, -1).astype('float32')
    )

    # ── Step 4: Stack into combined feature matrix ────────
    combined = sp.hstack([tfidf_features, hand_sparse]).astype('float32')

    # ── Step 5: Predict ───────────────────────────────────
    prob = _email_model.predict(combined)

    # LightGBM returns array — extract scalar
    return float(prob[0]) if hasattr(prob, '__len__') else float(prob)

def get_email_feature_vector(parsed_email):

    subject = parsed_email.get(
        'subject',
        ''
    )

    body = parsed_email.get(
        'body',
        ''
    )

    cleaned_text = clean_text_for_ml(
        subject,
        body
    )

    tfidf_features = (
        _tfidf
        .transform([cleaned_text])
        .astype('float32')
    )

    hand_features = (
        extract_hand_features(
            subject,
            body,
            parsed_email
        )
    )

    hand_sparse = sp.csr_matrix(
        np.array(
            hand_features
        ).reshape(1, -1)
        .astype('float32')
    )

    combined = sp.hstack(
        [
            tfidf_features,
            hand_sparse
        ]
    ).astype('float32')

    return combined

def clean_text_for_ml(subject, body):
    """
    Exact replication of cleaning pipeline used in notebook
    Subject repeated twice to give it more weight
    """
    text = subject + ' ' + subject + ' ' + body
    text = text.lower()
    text = re.sub(r'http\S+|www\S+',    ' urltoken ',   text)
    text = re.sub(r'[\w\.-]+@[\w\.-]+', ' emailtoken ', text)
    text = re.sub(r'\d+',               ' numtoken ',   text)
    text = re.sub(r'[^a-z\s]',          ' ',            text)
    text = re.sub(r'\s+',               ' ',            text).strip()
    return text


def extract_hand_features(subject, body, parsed_email):
    """
    Extracts the exact 13 hand-crafted features
    used during training in the notebook
    Order must match exactly
    """
    urls    = parsed_email.get('urls', [])
    feats   = parsed_email.get('text_features', {})

    # 1. url_count
    url_count = len(urls)

    # 2. email_count
    email_count = len(re.findall(r'[\w\.-]+@[\w\.-]+', body))

    # 3. num_count
    num_count = len(re.findall(r'\d+', body))

    # 4. body_length
    body_length = len(body)

    # 5. subject_length
    subject_length = len(subject)

    # 6. word_count
    words      = body.split()
    word_count = len(words)

    # 7. avg_word_length
    avg_word_length = (
        sum(len(w) for w in words) / len(words)
        if words else 0.0
    )

    # 8. exclamation_count
    exclamation_count = body.count('!')

    # 9. question_count
    question_count = body.count('?')

    # 10. capital_ratio
    capital_ratio = (
        sum(1 for c in body if c.isupper()) / max(len(body), 1)
    )

    # 11. keyword_count
    body_lower    = body.lower()
    keyword_count = sum(
        1 for kw in PHISHING_KEYWORDS
        if kw in body_lower
    )

    # 12. suspicious_subject
    subject_lower      = subject.lower()
    suspicious_subject = int(
        any(kw in subject_lower for kw in SUBJECT_KEYWORDS)
    )

    # 13. has_html
    has_html = int(
        bool(re.search(r'<[^>]+>', body))
    )

    # Return in exact same order as notebook
    return [
        url_count,
        email_count,
        num_count,
        body_length,
        subject_length,
        word_count,
        avg_word_length,
        exclamation_count,
        question_count,
        capital_ratio,
        keyword_count,
        suspicious_subject,
        has_html
    ]

# ──────────────────────────────────────────────────────────
# URL MODEL PREDICTION
# ──────────────────────────────────────────────────────────

def predict_url(url_obj):
    """
    Prepares URL features and runs the LightGBM URL model
    Mirrors the exact feature engineering from the notebook
    """
    # ── Step 1: Build URL feature dict ────────────────────
    url_features = extract_url_features(url_obj)

    # ── Step 2: Build DataFrame with correct column order ─
    url_df = pd.DataFrame([url_features])

    # Align columns to training feature names
    # Fill missing columns with 0
    for col in _url_feat_names:
        if col not in url_df.columns:
            url_df[col] = 0

    # Keep only training columns in correct order
    url_df = url_df[_url_feat_names]

    # ── Step 3: Scale features ────────────────────────────
    # Use same scaler fitted during training
    url_scaled = _scaler.transform(url_df).astype('float32')

    # ── Step 4: Predict ───────────────────────────────────
    prob = _url_model.predict(url_scaled)

    return float(prob[0]) if hasattr(prob, '__len__') else float(prob)


def extract_url_features(url_obj):
    """
    Extracts URL features matching the training dataset
    Maps parsed URL object fields to dataset column names
    """
    domain  = url_obj.get('domain', '')
    path    = url_obj.get('path', '')
    query   = url_obj.get('query', '')
    raw_url = url_obj.get('raw', '')

    return {
        'NumDots'                           : domain.count('.'),
        'SubdomainLevel'                    : max(len(domain.split('.')) - 2, 0),
        'PathLevel'                         : len([p for p in path.split('/') if p]),
        'UrlLength'                         : len(raw_url),
        'NumDash'                           : raw_url.count('-'),
        'NumDashInHostname'                 : domain.count('-'),
        'AtSymbol'                          : int('@' in raw_url),
        'TildeSymbol'                       : int('~' in raw_url),
        'NumUnderscore'                     : raw_url.count('_'),
        'NumPercent'                        : raw_url.count('%'),
        'NumQueryComponents'                : len(query.split('&')) if query else 0,
        'NumAmpersand'                      : raw_url.count('&'),
        'NumHash'                           : raw_url.count('#'),
        'NumNumericChars'                   : sum(c.isdigit() for c in raw_url),
        'NoHttps'                           : int(not url_obj.get('has_https', True)),
        'RandomString'                      : int(has_random_string(domain)),
        'IpAddress'                         : int(url_obj.get('has_ip', False)),
        'DomainInSubdomains'                : int(has_domain_in_subdomains(domain)),
        'DomainInPaths'                     : int(has_domain_in_path(path)),
        'HostnameLength'                    : len(domain),
        'PathLength'                        : len(path),
        'QueryLength'                       : len(query),
        'DoubleSlashInPath'                 : int('//' in path),
        'NumSensitiveWords'                 : count_sensitive_words(raw_url),
        'EmbeddedBrandName'                 : int(has_brand_name(raw_url)),
        'PctExtHyperlinks'                  : 0.0,
        'PctExtResourceUrls'                : 0.0,
        'ExtFavicon'                        : 0,
        'InsecureForms'                     : 0,
        'RelativeFormAction'                : 0,
        'ExtFormAction'                     : 0,
        'AbnormalFormAction'                : 0,
        'PctNullSelfRedirectHyperlinks'     : 0.0,
        'FrequentDomainNameMismatch'        : 0,
        'FakeLinkInStatusBar'               : 0,
        'RightClickDisabled'                : 0,
        'PopUpWindow'                       : 0,
        'SubmitInfoToEmail'                 : 0,
        'IframeOrFrame'                     : 0,
        'MissingTitle'                      : 0,
        'ImagesOnlyInForm'                  : 0,
        'SubdomainLevelRT'                  : max(len(domain.split('.')) - 2, 0),
        'UrlLengthRT'                       : int(len(raw_url) > 75),
        'PctExtResourceUrlsRT'              : 0,
        'AbnormalExtFormActionR'            : 0,
        'ExtMetaScriptLinkRT'               : 0,
        'PctExtNullSelfRedirectHyperlinksRT': 0,
        # Interaction features added in Section 5
        'url_x_subdomain'                   : (
            len(raw_url) * max(len(domain.split('.')) - 2, 0)
        ),
        'nohttps_x_sensitive'               : (
            int(not url_obj.get('has_https', True)) *
            count_sensitive_words(raw_url)
        ),
        'ip_x_urllength'                    : (
            int(url_obj.get('has_ip', False)) * len(raw_url)
        )
    }

# ──────────────────────────────────────────────────────────
# URL FEATURE HELPERS
# ──────────────────────────────────────────────────────────

def has_random_string(domain):
    """
    Detects if domain contains a random-looking string
    (consonant clusters longer than 4 chars)
    """
    consonants = re.findall(r'[bcdfghjklmnpqrstvwxyz]{5,}', domain.lower())
    return len(consonants) > 0


def has_domain_in_subdomains(domain):
    """
    Checks if a known brand domain appears in subdomains
    """
    brands  = [
        'paypal', 'google', 'amazon', 'apple',
        'microsoft', 'facebook', 'netflix', 'ebay'
    ]
    parts   = domain.split('.')
    subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    return any(brand in subdomain.lower() for brand in brands)


def has_domain_in_path(path):
    """
    Checks if a domain-like pattern appears in URL path
    """
    return bool(re.search(r'[a-z0-9\-]+\.(com|net|org|gov)', path.lower()))


def count_sensitive_words(url):
    """
    Counts sensitive phishing-related words in URL
    """
    sensitive = [
        'secure', 'account', 'update', 'login',
        'verify', 'bank', 'confirm', 'password',
        'signin', 'payment', 'billing', 'support'
    ]
    url_lower = url.lower()
    return sum(1 for w in sensitive if w in url_lower)


def has_brand_name(url):
    """
    Checks if a known brand name is embedded in the URL
    """
    brands = [
        'paypal', 'google', 'amazon', 'apple',
        'microsoft', 'facebook', 'netflix', 'ebay',
        'instagram', 'twitter', 'linkedin', 'dropbox'
    ]
    url_lower = url.lower()
    return any(brand in url_lower for brand in brands)


# ──────────────────────────────────────────────────────────
# SCORE COMBINATION
# ──────────────────────────────────────────────────────────

def calculate_combined_score(email_prob, url_prob, url_model_used):
    """
    Combines email and URL model probabilities
    Email model gets higher weight as it has more context
    If no URLs — email model score used directly
    """
    if not url_model_used:
        return email_prob

    # Weighted average — email model 60%, URL model 40%
    combined = (email_prob * 0.6) + (url_prob * 0.4)
    return round(combined, 4)


# ──────────────────────────────────────────────────────────
# MODEL INFO
# ──────────────────────────────────────────────────────────

def build_model_info(results):
    """
    Builds a human-readable model info dict
    shown in the extension popup
    """
    email_prob  = results['email_phishing_probability']
    url_prob    = results['url_phishing_probability']
    combined    = results['combined_probability']

    return {
        'email_model': {
            'probability'   : email_prob,
            'prediction'    : 'Phishing' if results['email_prediction'] else 'Legitimate',
            'confidence'    : get_confidence_label(email_prob),
            'type'          : _metadata.get('email_model', {}).get('type', 'LightGBM'),
            'trained_f1'    : _metadata.get('email_model', {}).get('f1_score', 'N/A')
        },
        'url_model': {
            'probability'   : url_prob,
            'prediction'    : 'Phishing' if results['url_prediction'] else 'Legitimate',
            'confidence'    : get_confidence_label(url_prob),
            'type'          : _metadata.get('url_model', {}).get('type', 'LightGBM'),
            'trained_f1'    : _metadata.get('url_model', {}).get('f1_score', 'N/A'),
            'applicable'    : results['url_model_used']
        },
        'combined': {
            'probability'   : combined,
            'prediction'    : 'Phishing' if results['combined_prediction'] else 'Legitimate',
            'confidence'    : get_confidence_label(combined),
            'weights'       : '60% email + 40% URL' if results['url_model_used'] else '100% email'
        }
    }


def get_confidence_label(probability):
    """
    Converts a probability into a confidence label
    """
    if probability >= 0.90:
        return 'Very High'
    elif probability >= 0.75:
        return 'High'
    elif probability >= 0.50:
        return 'Medium'
    elif probability >= 0.25:
        return 'Low'
    else:
        return 'Very Low'


