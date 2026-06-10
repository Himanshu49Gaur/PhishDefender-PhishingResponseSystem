import os

# Flask settings
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
FLASK_DEBUG = True

# Threat score thresholds
THRESHOLD_MALICIOUS = 80
THRESHOLD_SUSPICIOUS = 50

# Report output directory
REPORT_OUTPUT_DIR = "reports"

# VirusTotal
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VIRUSTOTAL_IP_SCAN = "https://www.virustotal.com/api/v3/ip_addresses"

# AbuseIPDB
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# ML Model Paths
EMAIL_MODEL_PATH = "../TrainedModel/email_model.pkl"
URL_MODEL_PATH = "../TrainedModel/url_model.pkl"

TFIDF_VECTORIZER_PATH = "../TrainedModel/tfidf_vectorizer.pkl"
SCALER_PATH = "../TrainedModel/scaler.pkl"
URL_FEATURE_NAMES_PATH = "../TrainedModel/url_feature_names.pkl"
MODEL_METADATA_PATH = "../TrainedModel/model_metadata.json"

# ML Settings
ML_THRESHOLD = 0.75

# Keyword Lists
PHISHING_KEYWORDS = [
    "verify",
    "update",
    "login",
    "password",
    "account",
    "security",
    "urgent",
    "banking"
]

SUBJECT_KEYWORDS = [
    "urgent",
    "action required",
    "verify account",
    "security alert",
    "password reset"
]

# Report Settings
REPORT_TITLE = "PhishDefender Analysis Report"
REPORT_AUTHOR = "PhishDefender"