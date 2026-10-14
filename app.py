import os
import sqlite3
from datetime import datetime, timezone

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)

frontend_origin = os.getenv("FRONTEND_ORIGIN", "")
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

DB_PATH = os.getenv("DB_PATH", "scans.db")


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
    url = data.get("url", "")

    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "Please enter a URL"}), 400

    url = url.strip()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = data.get(
        "result",
        "Demo check only - not verified safe"
    )

    if result not in ("Safe", "Suspicious", "Phishing"):
        result = "Demo check only - not verified safe"

    checked_at = datetime.now(timezone.utc).isoformat()

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
        "checked_at": checked_at
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
