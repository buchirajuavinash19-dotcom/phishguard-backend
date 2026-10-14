import os
import re
import sqlite3
import base64
import ipaddress
import whois

from datetime import date, datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)

DB_PATH = os.getenv("DB_PATH", "scans.db")
GOOGLE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
TIMEOUT = 12

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "https://buchirajuavinash19-dotcom.github.io"
            ],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type"]
        }
    }
)


# ---------------- DATABASE ----------------

def now_utc():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                result TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                risk_score INTEGER
            )
        """)

        columns = {
            row[1]
            for row in conn.execute(
                "PRAGMA table_info(scan_history)"
            ).fetchall()
        }

        if "risk_score" not in columns:
            conn.execute(
                "ALTER TABLE scan_history "
                "ADD COLUMN risk_score INTEGER"
            )


def save_history(url, result, risk_score=None):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("""
            INSERT INTO scan_history
                (url, result, checked_at, risk_score)
            VALUES (?, ?, ?, ?)
        """, (url, result, now_utc(), risk_score))

        return cursor.lastrowid


# ---------------- URL VALIDATION ----------------

def normalize_url(value):
    value = value.strip()

    if not value:
        return ""

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    return value


def valid_url(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname

        return (
            parsed.scheme in ("http", "https")
            and bool(host)
            and not any(c.isspace() for c in url)
            and not any(ord(c) < 32 for c in url)
            and len(host) <= 253
        )
    except (ValueError, TypeError):
        return False


# ---------------- RISK ANALYSIS ----------------

def risk_level(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def analyze_url(value):
    url = normalize_url(value)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    indicators = []
    score = 0

    if not valid_url(url):
        indicators.append("Invalid URL format")
        score = 50
    else:
        if parsed.scheme != "https":
            indicators.append("URL does not use HTTPS")
            score += 15

        try:
            ipaddress.ip_address(host)
            indicators.append("URL uses an IP address")
            score += 30
        except ValueError:
            pass

        if "xn--" in host:
            indicators.append(
                "Domain contains an internationalized label"
            )
            score += 25

        if "@" in url:
            indicators.append("URL contains an @ symbol")
            score += 25

        words = (
            "login", "verify", "account", "password",
            "secure", "update", "wallet", "signin"
        )

        found = [
            word for word in words
            if word in url.lower()
        ]

        if found:
            indicators.append(
                "Potentially suspicious keywords: "
                + ", ".join(found[:4])
            )
            score += 10

        if len(host) > 40:
            indicators.append("Unusually long domain name")
            score += 10

    score = min(score, 100)

    return {
        "type": "url",
        "input": url,
        "url": url,
        "risk_score": score,
        "risk_level": risk_level(score),
        "is_phishing": score >= 50,
        "indicators": indicators
    }


# ---------------- GOOGLE SAFE BROWSING ----------------

def google_check(url):
    if not GOOGLE_API_KEY:
        return {"status": "not_configured"}

    if not valid_url(url):
        return {"status": "skipped_invalid_url"}

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/"
        "threatMatches:find"
    )

    payload = {
        "client": {
            "clientId": "phishguard-ai",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(
            endpoint,
            params={"key": GOOGLE_API_KEY},
            json=payload,
            timeout=TIMEOUT
        )

        if response.status_code != 200:
            return {
                "status": "error",
                "http_status": response.status_code
            }

        matches = response.json().get("matches", [])

        return {
            "status": "flagged" if matches else "no_match",
            "matches": [
                {
                    "threat_type": item.get("threatType"),
                    "platform": item.get("platformType")
                }
                for item in matches
            ]
        }

    except (requests.RequestException, ValueError):
        return {"status": "unavailable"}


# ---------------- VIRUSTOTAL ----------------

def virustotal_check(url):
    if not VT_API_KEY:
        return {"status": "not_configured"}

    if not valid_url(url):
        return {"status": "skipped_invalid_url"}

    url_id = base64.urlsafe_b64encode(
        url.encode("utf-8")
    ).decode("ascii").rstrip("=")

    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=TIMEOUT
        )

        if response.status_code == 404:
            return {"status": "not_found"}

        if response.status_code == 429:
            return {"status": "rate_limited"}

        if response.status_code != 200:
            return {
                "status": "error",
                "http_status": response.status_code
            }

        attributes = (
            response.json()
            .get("data", {})
            .get("attributes", {})
        )

        stats = attributes.get("last_analysis_stats", {})

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)

        return {
            "status": (
                "flagged"
                if malicious > 0 or suspicious > 0
                else "analyzed"
            ),
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0)
        }

    except (requests.RequestException, ValueError, TypeError):
        return {"status": "unavailable"}


# ---------------- COMPLETE URL SCAN ----------------

def full_url_scan(value):
    analysis = analyze_url(value)
    url = analysis["url"]

    google = google_check(url)
    vt = virustotal_check(url)

    analysis["live_checks"] = {
        "google_safe_browsing": google,
        "virustotal": vt
    }

    indicators = analysis["indicators"][:]
    score = analysis["risk_score"]

    malicious = int(vt.get("malicious", 0) or 0)
    suspicious = int(vt.get("suspicious", 0) or 0)

    if google.get("status") == "flagged":
        score = max(score, 85)
        indicators.append(
            "Google Safe Browsing reported a threat match"
        )

    if malicious >= 3:
        score = max(score, 75)
        indicators.append(
            f"VirusTotal reports {malicious} malicious detections"
        )
    elif malicious > 0:
        score = max(score, 40)
        indicators.append(
            f"VirusTotal reports {malicious} malicious detection(s); "
            "independent verification is recommended"
        )

    if suspicious > 0:
        score = max(score, 35)
        indicators.append(
            f"VirusTotal reports {suspicious} suspicious detection(s)"
        )

    score = min(score, 100)

    if google.get("status") == "flagged" or malicious >= 3:
        result = "Phishing"
    elif score >= 15:
        result = "Suspicious"
    else:
        result = "Safe"

    if not indicators:
        indicators.append(
            "No suspicious indicators found by available checks. "
            "This does not guarantee the URL is safe."
        )

    analysis["risk_score"] = score
    analysis["risk_level"] = risk_level(score)
    analysis["is_phishing"] = result == "Phishing"
    analysis["indicators"] = indicators
    analysis["result"] = result
    analysis["note"] = (
        "Live-check statuses are shown separately. "
        "A low-risk result does not guarantee safety. "
        "A VirusTotal detection count is a signal, not proof."
    )

    return analysis


# ---------------- BASIC EMAIL ANALYSIS ----------------

def analyze_email(email):
    sender = str(email.get("sender", "unknown@example.com"))
    subject = str(email.get("subject", ""))
    body = str(email.get("body", ""))
    content = (subject + " " + body).lower()

    indicators = []
    score = 0

    phrases = (
        "verify your account", "reset your password",
        "urgent action", "account suspended",
        "claim your prize", "send your password",
        "bank details"
    )

    matches = [
        phrase for phrase in phrases
        if phrase in content
    ]

    if matches:
        indicators.append(
            "Potentially suspicious email wording: "
            + ", ".join(matches[:3])
        )
        score += 30

    if re.search(r"https?://", body, re.IGNORECASE):
        indicators.append("Email body contains a URL to check")
        score += 15

    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+", sender
    ):
        indicators.append("Sender address format appears invalid")
        score += 15

    score = min(score, 100)

    return {
        "type": "email",
        "input": sender,
        "sender": sender,
        "risk_score": score,
        "risk_level": risk_level(score),
        "is_phishing": score >= 50,
        "result": (
            "Phishing" if score >= 50
            else "Suspicious" if score >= 15
            else "Safe"
        ),
        "indicators": indicators or [
            "No basic suspicious indicators found. "
            "This does not prove the email is genuine."
        ]
    }


# ---------------- WHOIS LOOKUP ----------------

@app.post("/api/whois")
def whois_lookup():
    data = request.get_json(silent=True) or {}
    value = data.get("domain", "")

    if not isinstance(value, str) or not value.strip():
        return jsonify({
            "error": "Please enter a domain name."
        }), 400

    value = value.strip()

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    try:
        parsed = urlparse(value)
        domain = (parsed.hostname or "").lower().rstrip(".")

        if (
            not domain
            or "." not in domain
            or len(domain) > 253
            or any(
                not label or len(label) > 63
                for label in domain.split(".")
            )
            or any(
                not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label
                )
                for label in domain.split(".")
            )
        ):
            return jsonify({
                "error": "Enter a valid domain, such as example.com."
            }), 400

        try:
            ipaddress.ip_address(domain)
            return jsonify({
                "error": "Please enter a domain name, not an IP address."
            }), 400
        except ValueError:
            pass

        info = whois.whois(domain)

        def format_value(value):
            if value is None:
                return "Not available"

            if isinstance(value, (datetime, date)):
                return value.isoformat()

            if isinstance(value, (list, set, tuple)):
                return ", ".join(
                    format_value(item) for item in value
                )

            return str(value)

        return jsonify({
            "domain": domain,
            "registrar": format_value(info.registrar),
            "creation_date": format_value(info.creation_date),
            "expiration_date": format_value(info.expiration_date),
            "updated_date": format_value(info.updated_date),
            "name_servers": format_value(info.name_servers),
            "status": format_value(info.status),
            "emails": format_value(info.emails)
        }), 200

    except Exception:
        return jsonify({
            "error": (
                "WHOIS lookup failed. The domain registry may be "
                "unavailable or the domain may not provide this data."
            )
        }), 502


# ---------------- API ROUTES ----------------

@app.get("/")
def home():
    return jsonify({
        "message": "PhishGuard AI Backend is running"
    })


@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "google_key_configured": bool(GOOGLE_API_KEY),
        "virustotal_key_configured": bool(VT_API_KEY)
    })


@app.post("/api/scan")
def scan_url():
    data = request.get_json(silent=True) or {}
    value = data.get("url", "")

    if not isinstance(value, str) or not value.strip():
        return jsonify({
            "error": "Please enter a URL"
        }), 400

    normalized = normalize_url(value)

    if not valid_url(normalized):
        return jsonify({
            "error": "Please enter a valid URL"
        }), 400

    analysis = full_url_scan(normalized)

    record_id = save_history(
        analysis["url"],
        analysis["result"],
        analysis["risk_score"]
    )

    analysis["id"] = record_id
    analysis["checked_at"] = now_utc()

    return jsonify(analysis)


@app.post("/api/scan/batch")
def scan_batch():
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])
    emails = data.get("emails", [])

    if not isinstance(urls, list) or not isinstance(emails, list):
        return jsonify({
            "error": "URLs and emails must be lists"
        }), 400

    if len(urls) + len(emails) == 0:
        return jsonify({
            "error": "Please provide at least one URL or email"
        }), 400

    if len(urls) + len(emails) > 100:
        return jsonify({
            "error": "Maximum 100 entries per batch"
        }), 400

    results = []

    for value in urls:
        if not isinstance(value, str) or not value.strip():
            continue

        normalized = normalize_url(value)

        if not valid_url(normalized):
            results.append({
                "type": "url",
                "input": value,
                "url": value,
                "result": "Invalid",
                "risk_score": 0,
                "risk_level": "UNKNOWN",
                "indicators": ["Invalid URL format"]
            })
            continue

        entry = full_url_scan(normalized)

        record_id = save_history(
            entry["url"],
            entry["result"],
            entry["risk_score"]
        )

        entry["id"] = record_id
        results.append(entry)

    for email in emails:
        if isinstance(email, dict):
            results.append(analyze_email(email))

    return jsonify({
        "total": len(results),
        "batch_id": datetime.now(timezone.utc).strftime(
            "%Y%m%d%H%M%S"
        ),
        "scanned_at": now_utc(),
        "results": results,
        "note": (
            "Live checks can be unavailable or rate-limited. "
            "Review each result and its indicators."
        )
    })


@app.get("/api/history")
def history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT id, url, result, checked_at, risk_score
            FROM scan_history
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

    return jsonify({
        "history": [dict(row) for row in rows]
    })


# ---------------- STARTUP ----------------

init_db()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000))
    )
    
