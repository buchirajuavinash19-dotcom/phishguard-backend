
import os
import re
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)

DB_PATH = os.getenv("DB_PATH", "scans.db")

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


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                result TEXT NOT NULL,
                checked_at TEXT NOT NULL
            )
        """)


def normalize_url(value):
    value = value.strip()

    if not value:
        return ""

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    return value


def analyze_url(value):
    url = normalize_url(value)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    indicators = []
    score = 0

    if parsed.scheme != "https":
        indicators.append("URL does not use HTTPS")
        score += 15

    if not host:
        indicators.append("Invalid or missing domain")
        score += 50

    if host and re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        indicators.append("URL uses an IP address instead of a domain")
        score += 30

    if "xn--" in host:
        indicators.append("Domain contains an internationalized domain label")
        score += 25

    if "@" in url:
        indicators.append("URL contains an @ symbol")
        score += 25

    suspicious_words = (
        "login", "verify", "account", "password",
        "secure", "update", "wallet", "signin"
    )

    found_words = [word for word in suspicious_words if word in url.lower()]
    if found_words:
        indicators.append(
            "Contains potentially suspicious keywords: "
            + ", ".join(found_words[:4])
        )
        score += 10

    if len(host) > 40:
        indicators.append("Unusually long domain name")
        score += 10

    score = min(score, 100)

    if score >= 50:
        risk_level = "CRITICAL"
    elif score >= 30:
        risk_level = "HIGH"
    elif score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "type": "url",
        "input": url,
        "url": url,
        "risk_level": risk_level,
        "risk_score": score,
        "is_phishing": score >= 50,
        "indicators": indicators or [
            "No basic suspicious indicators found; this does not prove the URL is safe"
        ]
    }


def analyze_email(email):
    sender = str(email.get("sender", "unknown@example.com"))
    subject = str(email.get("subject", ""))
    body = str(email.get("body", ""))
    content = (subject + " " + body).lower()

    indicators = []
    score = 0

    suspicious_phrases = (
        "verify your account",
        "reset your password",
        "urgent action",
        "account suspended",
        "claim your prize",
        "send your password",
        "bank details"
    )

    matches = [phrase for phrase in suspicious_phrases if phrase in content]
    if matches:
        indicators.append(
            "Potentially suspicious email wording: "
            + ", ".join(matches[:3])
        )
        score += 30

    if re.search(r"https?://", body, re.IGNORECASE):
        indicators.append("Email body contains a URL that should be checked")
        score += 15

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sender):
        indicators.append("Sender address format appears invalid")
        score += 15

    score = min(score, 100)

    if score >= 50:
        risk_level = "CRITICAL"
    elif score >= 30:
        risk_level = "HIGH"
    elif score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "type": "email",
        "input": sender,
        "sender": sender,
        "risk_level": risk_level,
        "risk_score": score,
        "is_phishing": score >= 50,
        "indicators": indicators or [
            "No basic suspicious indicators found; this does not prove the email is genuine"
        ]
    }


@app.get("/")
def home():
    return jsonify({
        "message": "PhishGuard AI Backend is running"
    })


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/api/scan")
def scan_url():
    data = request.get_json(silent=True) or {}
    value = data.get("url", "")

    if not isinstance(value, str) or not value.strip():
        return jsonify({"error": "Please enter a URL"}), 400

    url = normalize_url(value)
    analysis = analyze_url(url)

    if analysis["risk_score"] >= 50:
        result = "Phishing"
    elif analysis["risk_score"] >= 15:
        result = "Suspicious"
    else:
        result = "Safe"

    checked_at = now_utc()

    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("""
            INSERT INTO scan_history (url, result, checked_at)
            VALUES (?, ?, ?)
        """, (url, result, checked_at))
        record_id = cursor.lastrowid

    return jsonify({
        "id": record_id,
        "url": url,
        "result": result,
        "checked_at": checked_at,
        "risk_score": analysis["risk_score"],
        "risk_level": analysis["risk_level"],
        "indicators": analysis["indicators"],
        "note": "Basic heuristic analysis only; not verified against live threat databases."
    })


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
            "error": "Maximum 100 entries are allowed per batch"
        }), 400

    results = []

    for value in urls:
        if not isinstance(value, str) or not value.strip():
            continue

        url = normalize_url(value)
        entry = analyze_url(url)
        results.append(entry)

        if entry["risk_score"] >= 50:
            saved_result = "Phishing"
        elif entry["risk_score"] >= 15:
            saved_result = "Suspicious"
        else:
            saved_result = "Safe"

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO scan_history (url, result, checked_at)
                VALUES (?, ?, ?)
            """, (url, saved_result, now_utc()))

    for email in emails:
        if not isinstance(email, dict):
            continue
        results.append(analyze_email(email))

    return jsonify({
        "total": len(results),
        "batch_id": datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"),
        "scanned_at": now_utc(),
        "results": results,
        "note": "Basic heuristic analysis only; live threat databases are not checked by this endpoint."
    })


@app.get("/api/history")
def history():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT id, url, result, checked_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT 100
        """).fetchall()

    return jsonify({
        "history": [dict(row) for row in rows]
    })


init_db()
    
