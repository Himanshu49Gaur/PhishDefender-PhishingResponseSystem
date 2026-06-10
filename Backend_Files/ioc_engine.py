import sqlite3
import uuid
from urllib.parse import urlparse

from ioc_storage import (
    create_campaign,
    get_campaign
)


def find_related_emails(domain):
    conn = sqlite3.connect("iocs.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM email_iocs
    WHERE domain = ?
    """, (domain,))

    results = cursor.fetchall()

    conn.close()

    return results


def calculate_campaign_score(sender, domain, ip_address, urls):
    conn = sqlite3.connect("iocs.db")
    cursor = conn.cursor()

    score = 0

    # Domain reuse
    cursor.execute(
        "SELECT COUNT(*) FROM email_iocs WHERE domain = ?",
        (domain,)
    )

    if cursor.fetchone()[0] >= 2:
        score += 40

    # Sender reuse
    cursor.execute(
        "SELECT COUNT(*) FROM email_iocs WHERE sender = ?",
        (sender,)
    )

    if cursor.fetchone()[0] >= 2:
        score += 20

    # IP reuse
    cursor.execute(
        "SELECT COUNT(*) FROM email_iocs WHERE ip_address = ?",
        (ip_address,)
    )

    if cursor.fetchone()[0] >= 2:
        score += 20

    # URL reuse
    cursor.execute(
        "SELECT urls FROM email_iocs"
    )

    stored_urls = cursor.fetchall()

    for row in stored_urls:
        if any(url in row[0] for url in urls):
            score += 20
            break

    conn.close()

    return min(score, 100)


def generate_campaign_id():
    return f"CAM-{str(uuid.uuid4())[:8].upper()}"


def get_campaign_severity(score):
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"


def calculate_confidence_score(score):
    if score >= 80:
        return 95

    if score >= 60:
        return 85

    if score >= 40:
        return 70

    return 50


def detect_campaign(sender, domain, ip_address, urls):
    score = calculate_campaign_score(
        sender,
        domain,
        ip_address,
        urls
    )

    if score < 40:
        return {
            "campaign_detected": False,
            "campaign_id": None,
            "campaign_score": score,
            "severity": "low",
            "confidence_score": calculate_confidence_score(score)
        }

    existing = get_campaign(domain)

    if existing:
        campaign_id = existing[0]
    else:
        campaign_id = create_campaign(
            domain,
            score
        )

    return {
        "campaign_detected": True,
        "campaign_id": campaign_id,
        "campaign_score": score,
        "severity": get_campaign_severity(score),
        "confidence_score": calculate_confidence_score(score)
    }


def detect_campaign_from_analysis(parsed_email, rules_result):
    urls = parsed_email.get("urls", [])

    sender = parsed_email.get(
        "sender",
        "unknown"
    )

    ip_address = (
        parsed_email
        .get("headers", {})
        .get("originating_ip", "unknown")
    )

    if not urls:
        return {
            "campaign_detected": False,
            "campaign_id": None,
            "campaign_score": 0,
            "severity": "low",
            "confidence_score": 50
        }

    try:
        domain = urlparse(
            urls[0]
        ).netloc
    except Exception:
        domain = "unknown"

    return detect_campaign(
        sender,
        domain,
        ip_address,
        urls
    )

