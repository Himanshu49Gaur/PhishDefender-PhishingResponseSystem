# ============================================================
# app.py
# Flask backend server — main entry point
# Receives email data from browser extension
# Orchestrates all modules and returns unified result
# ============================================================
from ioc_storage import init_db, save_analysis
from ioc_engine import detect_campaign_from_analysis
import os
import json
import traceback
from datetime import datetime
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

from config import (
    FLASK_HOST,
    FLASK_PORT,
    FLASK_DEBUG,
    THRESHOLD_MALICIOUS,
    THRESHOLD_SUSPICIOUS,
    REPORT_OUTPUT_DIR
)
from email_parser      import parse_email
from threat_intel      import run_threat_intelligence
from ml_classifier     import run_ml_classifier, load_models
from rules_engine      import run_rules_engine
from report_generator  import generate_report

# ──────────────────────────────────────────────────────────
# APP INITIALIZATION
# ──────────────────────────────────────────────────────────

app = Flask(__name__)

init_db()

# Allow requests from Chrome extension
CORS(app, resources={
    r"/*": {
        "origins": [
            "chrome-extension://*",
            "http://localhost:*",
            "http://127.0.0.1:*"
        ]
    }
})

# ──────────────────────────────────────────────────────────
# LOAD MODELS ON STARTUP
# ──────────────────────────────────────────────────────────

print("=" * 55)
print("Phishing Detector — Backend Server")
print("=" * 55)

try:
    load_models()
    print("[app] Models loaded successfully")
except Exception as e:
    print(f"[app] CRITICAL — Model loading failed: {e}")
    raise

# ──────────────────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────────────────

@app.route('/ping', methods=['GET'])
def ping():
    """
    Health check endpoint
    Called by extension on startup to confirm server is running
    """
    return jsonify({
        'status'    : 'ok',
        'message'   : 'Phishing Detector backend is running',
        'timestamp' : datetime.now().isoformat()
    }), 200


@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Main analysis endpoint
    Called by background.js with raw email data
    Runs full pipeline and returns unified threat result
    """
    print("\n" + "=" * 55)
    print(f"[app] /analyze called at {datetime.now().strftime('%H:%M:%S')}")

    # ── Validate request ──────────────────────────────────
    if not request.is_json:
        return jsonify({
            'error': 'Request must be JSON'
        }), 400

    data = request.get_json()

    if not data:
        return jsonify({
            'error': 'Empty request body'
        }), 400

    # ── Validate required fields ──────────────────────────
    required = ['subject', 'body']
    missing  = [f for f in required if f not in data]
    if missing:
        return jsonify({
            'error'  : f'Missing required fields: {missing}',
            'fields' : missing
        }), 400

    try:
        # ── Step 1: Parse email ───────────────────────────
        print("[app] Step 1 — Parsing email...")
        parsed_email = parse_email(data)
        print(f"  Sender  : {parsed_email.get('sender', 'N/A')}")
        print(f"  Subject : {parsed_email.get('subject', '')[:60]}")
        print(f"  URLs    : {len(parsed_email.get('urls', []))}")
        print(f"  Flags   : {len(parsed_email.get('flags', []))}")

        # ── Step 2: Run ML classifier ─────────────────────
        print("[app] Step 2 — Running ML classifier...")
        ml_scores = run_ml_classifier(parsed_email)
        print(
            f"  Email prob  : {ml_scores['email_phishing_probability']:.4f}"
        )
        print(
            f"  URL prob    : {ml_scores['url_phishing_probability']:.4f}"
        )
        print(
            f"  Combined    : {ml_scores['combined_probability']:.4f}"
        )

        # ── Step 3: Run threat intelligence ──────────────
        print("[app] Step 3 — Running threat intelligence...")
        threat_intel = run_threat_intelligence(parsed_email)
        print(
            f"  Malicious URLs : {threat_intel['malicious_url_count']}"
        )
        print(
            f"  Malicious IPs  : {threat_intel['malicious_ip_count']}"
        )
        print(
            f"  IOCs found     : {len(threat_intel.get('iocs', []))}"
        )

        # ── Step 4: Run rules engine ──────────────────────
        print("[app] Step 4 — Running rules engine...")
        rules_result = run_rules_engine(
            parsed_email,
            threat_intel,
            ml_scores
        )

        save_analysis(
          parsed_email,
          rules_result
        )

        campaign_result = detect_campaign_from_analysis(
            parsed_email,
            rules_result
        )
        print(f"  Verdict     : {rules_result['verdict'].upper()}")
        print(f"  Score       : {rules_result['total_score']}/100")
        print(
            f"  Rules fired : "
            f"{len(rules_result['triggered_rules'])}"
        )

        # ── Step 5: Generate report if malicious ─────────
        report_path = None
        if rules_result['verdict'] in ('malicious', 'suspicious'):
            print("[app] Step 5 — Generating incident report...")
            try:
                report_path = generate_report(
                    parsed_email,
                    threat_intel,
                    ml_scores,
                    rules_result
                )
                print(f"  Report saved : {report_path}")
            except Exception as report_err:
                print(f"  Report error : {report_err}")
                report_path = None

        # ── Build response ────────────────────────────────
        response = build_response(
            parsed_email,
            ml_scores,
            threat_intel,
            rules_result,
            report_path,
            campaign_result
        )

        print(f"[app] Analysis complete — {rules_result['verdict'].upper()}")
        print("=" * 55)

        return jsonify(response), 200

    except Exception as e:
        print(f"[app] ERROR during analysis: {e}")
        traceback.print_exc()
        return jsonify({
            'error'     : 'Internal server error during analysis',
            'detail'    : str(e)
        }), 500

@app.route('/metrics', methods=['GET'])
def metrics():

    from metrics import scan_metrics

    return jsonify({
        "urls_scanned": scan_metrics["urls_scanned"],
        "cache_hits": scan_metrics["cache_hits"],
        "cache_misses": scan_metrics["cache_misses"]
    })

@app.route('/report/<filename>', methods=['GET'])
def download_report(filename):
    """
    Report download endpoint
    Called by extension popup to download PDF report
    """
    # Sanitize filename — prevent path traversal
    filename    = os.path.basename(filename)
    report_path = os.path.join(REPORT_OUTPUT_DIR, filename)

    if not os.path.exists(report_path):
        return jsonify({
            'error': f'Report not found: {filename}'
        }), 404

    try:
        return send_file(
            report_path,
            mimetype        = 'application/pdf',
            as_attachment   = True,
            download_name   = filename
        )
    except Exception as e:
        return jsonify({
            'error': f'Failed to serve report: {str(e)}'
        }), 500


@app.route('/reports', methods=['GET'])
def list_reports():
    """
    Lists all generated reports
    Called by extension popup to show report history
    """
    try:
        if not os.path.exists(REPORT_OUTPUT_DIR):
            return jsonify({'reports': []}), 200

        reports = []
        for fname in sorted(
            os.listdir(REPORT_OUTPUT_DIR),
            reverse=True
        ):
            if fname.endswith('.pdf'):
                fpath = os.path.join(REPORT_OUTPUT_DIR, fname)
                fsize = os.path.getsize(fpath)
                reports.append({
                    'filename'  : fname,
                    'size_kb'   : round(fsize / 1024, 1),
                    'created'   : datetime.fromtimestamp(
                        os.path.getctime(fpath)
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                    'download_url': f'/report/{fname}'
                })

        return jsonify({'reports': reports}), 200

    except Exception as e:
        return jsonify({
            'error': f'Failed to list reports: {str(e)}'
        }), 500


@app.route('/status', methods=['GET'])
def status():
    """
    Detailed status endpoint
    Returns server status and model info
    """
    return jsonify({
        'status'        : 'running',
        'timestamp'     : datetime.now().isoformat(),
        'models_loaded' : True,
        'endpoints'     : [
            'GET  /ping',
            'POST /analyze',
            'GET  /report/<filename>',
            'GET  /reports',
            'GET  /status'
        ],
        'thresholds'    : {
            'malicious' : THRESHOLD_MALICIOUS,
            'suspicious': THRESHOLD_SUSPICIOUS
        },
        'reports_dir'   : REPORT_OUTPUT_DIR
    }), 200



# Ensure reports directory exists
os.makedirs(REPORT_OUTPUT_DIR, exist_ok=True)
print(f"[app] Reports directory ready : {REPORT_OUTPUT_DIR}")
print(f"[app] Server starting on      : http://{FLASK_HOST}:{FLASK_PORT}")
print("=" * 55)

@app.route('/campaigns', methods=['GET'])
def get_campaigns():
    import sqlite3

    conn = sqlite3.connect("iocs.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT campaign_id, domain, campaign_score
        FROM campaigns
        ORDER BY campaign_score DESC
    """)

    campaigns = []

    for campaign_id, domain, score in cursor.fetchall():
        campaigns.append({
            "campaign_id": campaign_id,
            "domain": domain,
            "campaign_score": score
        })

    conn.close()

    return jsonify(campaigns), 200

@app.route('/campaign/<domain>', methods=['GET'])
def campaign_details(domain):
    import sqlite3

    conn = sqlite3.connect("iocs.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT sender,
               domain,
               urls,
               verdict,
               threat_score,
               timestamp
        FROM email_iocs
        WHERE domain = ?
    """, (domain,))

    rows = cursor.fetchall()

    conn.close()

    emails = []

    for row in rows:
        emails.append({
            "sender": row[0],
            "domain": row[1],
            "urls": row[2],
            "verdict": row[3],
            "threat_score": row[4],
            "timestamp": row[5]
        })

    return jsonify({
        "domain": domain,
        "email_count": len(emails),
        "emails": emails
    }), 200

@app.route('/campaign/<domain>/graph', methods=['GET'])
def campaign_graph(domain):
    import sqlite3
    from campaign_graph import generate_campaign_graph
    from flask import send_file

    conn = sqlite3.connect("iocs.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT sender
        FROM email_iocs
        WHERE domain = ?
    """, (domain,))

    rows = cursor.fetchall()

    conn.close()

    emails = []

    for row in rows:
        emails.append({
            "sender": row[0]
        })

    graph_file = generate_campaign_graph(
        domain,
        emails
    )

    return send_file(
        graph_file,
        mimetype='image/png'
    )

# ──────────────────────────────────────────────────────────
# RESPONSE BUILDER
# ──────────────────────────────────────────────────────────

def build_response(
    parsed_email,
    ml_scores,
    threat_intel,
    rules_result,
    report_path,
    campaign_result
):
    """
    Builds the final JSON response sent back to
    the browser extension
    """
    verdict     = rules_result.get('verdict', 'unknown')
    score       = rules_result.get('total_score', 0)
    report_url  = None

    if report_path:
        filename    = os.path.basename(report_path)
        report_url  = f"http://{FLASK_HOST}:{FLASK_PORT}/report/{filename}"

    return {

        # ── Core result ───────────────────────────────────
        'verdict'               : verdict,
        'threat_score'          : score,
        'campaign': campaign_result,
        'summary'               : rules_result.get('summary', ''),
        'timestamp'             : datetime.now().isoformat(),

        # ── Email metadata ────────────────────────────────
        'email'                 : {
            'sender'            : parsed_email.get('sender', ''),
            'subject'           : parsed_email.get('subject', ''),
            'url_count'         : len(parsed_email.get('urls', [])),
            'flags'             : parsed_email.get('flags', []),
            'text_features'     : parsed_email.get('text_features', {})
        },

        # ── ML scores ─────────────────────────────────────
        'ml'                    : {
            'email_probability' : ml_scores.get(
                'email_phishing_probability', 0
            ),
            'url_probability'   : ml_scores.get(
                'url_phishing_probability', 0
            ),
            'combined_probability': ml_scores.get(
                'combined_probability', 0
            ),
            'model_info'        : ml_scores.get('model_info', {})
        },

        # ── Threat intelligence ───────────────────────────
        'threat_intel'          : {
            'malicious_url_count': threat_intel.get(
                'malicious_url_count', 0
            ),
            'malicious_ip_count' : threat_intel.get(
                'malicious_ip_count', 0
            ),
            'url_results'        : threat_intel.get('url_results', []),
            'ip_results'         : threat_intel.get('ip_results', []),
            'threat_score'       : threat_intel.get('threat_score', 0)
        },

        # ── Rules engine ──────────────────────────────────
        'rules'                 : {
            'triggered'         : rules_result.get(
                'triggered_rules', []
            ),
            'score_breakdown'   : rules_result.get(
                'score_breakdown', {}
            ),
            'actions'           : rules_result.get('actions', [])
        },

        # ── IOCs ──────────────────────────────────────────
        'iocs'                  : rules_result.get('iocs', []),

        # ── Header analysis ───────────────────────────────
        'headers'               : {
            'spf'               : parsed_email.get(
                'headers', {}
            ).get('spf', 'unknown'),
            'dkim'              : parsed_email.get(
                'headers', {}
            ).get('dkim', 'unknown'),
            'dmarc'             : parsed_email.get(
                'headers', {}
            ).get('dmarc', 'unknown'),
            'originating_ip'    : parsed_email.get(
                'headers', {}
            ).get('originating_ip', None),
            'reply_to_mismatch' : parsed_email.get(
                'headers', {}
            ).get('reply_to_mismatch', False)
        },

        # ── Report ────────────────────────────────────────
        'report'                : {
            'generated'         : report_path is not None,
            'download_url'      : report_url,
            'filename'          : os.path.basename(report_path)
                                  if report_path else None
        }
    }

# ──────────────────────────────────────────────────────────
# ERROR HANDLERS
# ──────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({
        'error'     : 'Endpoint not found',
        'available' : [
            'GET  /ping',
            'POST /analyze',
            'GET  /report/<filename>',
            'GET  /reports',
            'GET  /status'
        ]
    }), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({
        'error': 'Method not allowed for this endpoint'
    }), 405


@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        'error' : 'Internal server error',
        'detail': str(e)
    }), 500


# ──────────────────────────────────────────────────────────
# RUN SERVER
# ──────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(
        host    = FLASK_HOST,
        port    = FLASK_PORT,
        debug   = FLASK_DEBUG
    )

