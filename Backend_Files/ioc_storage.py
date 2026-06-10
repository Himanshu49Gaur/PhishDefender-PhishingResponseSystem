import sqlite3
import json
from datetime import datetime
from urllib.parse import urlparse


def init_db():
    conn = sqlite3.connect("iocs.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS email_iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        domain TEXT,
        ip_address TEXT,
        urls TEXT,
        verdict TEXT,
        threat_score REAL,
        timestamp TEXT
    )
    """)
    
    cursor.execute("""
CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT UNIQUE,
    domain TEXT UNIQUE,
    campaign_score INTEGER,
    created_at TEXT
)
""")
    

    conn.commit()
    conn.close()

    print("[IOC] Database initialized")


def save_scan(sender, domain, ip_address, urls, verdict, threat_score):
    conn = sqlite3.connect("iocs.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO email_iocs (
        sender,
        domain,
        ip_address,
        urls,
        verdict,
        threat_score,
        timestamp
    )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        sender,
        domain,
        ip_address,
        json.dumps(urls),
        verdict,
        threat_score,
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()

    print(f"[IOC] Stored scan for {sender}")


def get_all_scans():
    conn = sqlite3.connect("iocs.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM email_iocs")

    results = cursor.fetchall()

    conn.close()

    return results


def save_analysis(parsed_email, rules_result):
    urls = parsed_email.get("urls", [])

    sender = parsed_email.get("sender", "unknown")

    domain = "unknown"

    ip_address = (
    parsed_email
    .get("headers", {})
    .get("originating_ip", "unknown")
)

    if urls:
        try:
            domain = urlparse(urls[0]).netloc
        except Exception:
            pass

    save_scan(
        sender=sender,
        domain=domain,
        ip_address=ip_address,
        urls=urls,
        verdict=rules_result["verdict"],
        threat_score=rules_result["total_score"]
    )


if __name__ == "__main__":
    init_db()
    print(get_all_scans())

def create_campaign(domain, campaign_score):
    import uuid

    campaign_id = f"CAM-{str(uuid.uuid4())[:8].upper()}"

    conn = sqlite3.connect("iocs.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO campaigns (
        campaign_id,
        domain,
        campaign_score,
        created_at
    )
    VALUES (?, ?, ?, datetime('now'))
    """, (
        campaign_id,
        domain,
        campaign_score
    ))

    conn.commit()
    conn.close()

    return campaign_id

def get_campaign(domain):
    conn = sqlite3.connect("iocs.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT campaign_id
    FROM campaigns
    WHERE domain = ?
    """, (domain,))

    result = cursor.fetchone()

    conn.close()

    return result


