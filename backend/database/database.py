"""
SQLite Database Layer for Phishing Scan Records and Analytics.
Provides persistent storage, thread-safe connections, and aggregated dashboard metrics.
Enforces retention cleanup and space hygiene (omits bulky base64 data URIs from database persistence).
"""
import json
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from backend.config import BACKEND_DIR

logger = logging.getLogger(__name__)

DB_PATH = BACKEND_DIR / "data" / "phishing_scans.db"


def get_db_connection() -> sqlite3.Connection:
    """Creates a connection to the SQLite database with dictionary row factory."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes SQLite database schema and tables."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            hostname TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            classification TEXT NOT NULL,
            risk_score REAL NOT NULL,
            confidence REAL NOT NULL,
            url_score REAL NOT NULL,
            visual_score REAL NOT NULL,
            text_score REAL NOT NULL,
            html_score REAL NOT NULL,
            explanation TEXT NOT NULL,
            full_data TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_scan(scan_data: Dict[str, Any]) -> int:
    """
    Saves a completed scan result to SQLite and returns the assigned scan ID.
    Omit raw base64 screenshot payloads to prevent SQLite storage bloat.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    now_iso = datetime.utcnow().isoformat() + "Z"

    explanation_str = json.dumps(scan_data.get("explanation", []))

    # Strip large base64 screenshot payload before saving to database
    saveable_data = dict(scan_data)
    saveable_data.pop("screenshot_preview", None)
    full_data_str = json.dumps(saveable_data)

    cursor.execute("""
        INSERT INTO scans (
            url, hostname, timestamp, classification,
            risk_score, confidence, url_score, visual_score,
            text_score, html_score, explanation, full_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_data.get("url", ""),
        scan_data.get("hostname", ""),
        now_iso,
        scan_data.get("classification", "UNKNOWN"),
        float(scan_data.get("risk_score", 0.0)),
        float(scan_data.get("confidence", 0.0)),
        float(scan_data.get("sub_scores", {}).get("url_score", 0.0)),
        float(scan_data.get("sub_scores", {}).get("visual_score", 0.0)),
        float(scan_data.get("sub_scores", {}).get("text_score", 0.0)),
        float(scan_data.get("sub_scores", {}).get("html_score", 0.0)),
        explanation_str,
        full_data_str
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def get_all_scans(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Retrieves recent scans ordered by timestamp descending."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, url, hostname, timestamp, classification, risk_score,
               confidence, url_score, visual_score, text_score, html_score, explanation
        FROM scans
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """, (limit, offset))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        try:
            exp_list = json.loads(r["explanation"])
            summary = exp_list[0] if exp_list else "Analysis complete."
        except Exception:
            summary = "Analysis complete."

        results.append({
            "id": r["id"],
            "url": r["url"],
            "hostname": r["hostname"],
            "timestamp": r["timestamp"],
            "classification": r["classification"],
            "risk_score": r["risk_score"],
            "confidence": r["confidence"],
            "url_score": r["url_score"],
            "visual_score": r["visual_score"],
            "text_score": r["text_score"],
            "html_score": r["html_score"],
            "explanation_summary": summary
        })
    return results


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves full analysis payload for a specific scan ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, full_data FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None

    try:
        data = json.loads(row["full_data"])
        data["id"] = row["id"]
        return data
    except Exception as exc:
        logger.error(f"Failed deserializing scan data #{scan_id}: {exc}")
        return None


def delete_scan_by_id(scan_id: int) -> bool:
    """Deletes a scan entry from history."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def cleanup_expired_scans(max_age_days: int = 30) -> int:
    """
    Deletes scan records older than max_age_days to maintain retention hygiene.
    """
    cutoff = (datetime.utcnow() - timedelta(days=max_age_days)).isoformat() + "Z"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted


def get_dashboard_stats() -> Dict[str, Any]:
    """Computes aggregated metrics from historical scan database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT classification, risk_score FROM scans")
    rows = cursor.fetchall()
    conn.close()

    total = len(rows)
    if total == 0:
        return {
            "total_scans": 0,
            "phishing_count": 0,
            "safe_count": 0,
            "suspicious_count": 0,
            "average_risk_score": 0.0,
            "detection_rate": 0.0
        }

    phishing_count = sum(1 for r in rows if r["classification"] == "PHISHING")
    safe_count = sum(1 for r in rows if r["classification"] == "SAFE")
    suspicious_count = sum(1 for r in rows if r["classification"] == "SUSPICIOUS")
    avg_risk = sum(r["risk_score"] for r in rows) / total
    detection_rate = round((phishing_count + suspicious_count) / total * 100, 1)

    return {
        "total_scans": total,
        "phishing_count": phishing_count,
        "safe_count": safe_count,
        "suspicious_count": suspicious_count,
        "average_risk_score": round(avg_risk, 3),
        "detection_rate": detection_rate
    }
