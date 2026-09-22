import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "scans.db")

def get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initialize database tables for scan feature persistence and novel candidates."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_features (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                features_json TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS novel_candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                features_json TEXT NOT NULL,
                max_confidence REAL NOT NULL
            )
        """)
        conn.commit()

def save_scan_features(target_url: str, features: Dict[str, Any]) -> int:
    """Store the extracted feature blob for a recon scan."""
    init_db()
    now = datetime.utcnow().isoformat()
    features_json = json.dumps(features)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scan_features (target_url, timestamp, features_json) VALUES (?, ?, ?)",
            (target_url, now, features_json)
        )
        conn.commit()
        return cursor.lastrowid

def save_novel_candidate(target_url: str, features: Dict[str, Any], max_confidence: float) -> int:
    """
    Store uncatalogued/novel stack feature vectors where all classifier confidences
    fell below threshold for offline clustering (e.g. HDBSCAN/SVD).
    """
    init_db()
    now = datetime.utcnow().isoformat()
    features_json = json.dumps(features)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO novel_candidates (target_url, timestamp, features_json, max_confidence) VALUES (?, ?, ?, ?)",
            (target_url, now, features_json, float(max_confidence))
        )
        conn.commit()
        return cursor.lastrowid

def get_novel_candidates(limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve novel candidates for offline analysis."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, target_url, timestamp, features_json, max_confidence FROM novel_candidates ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        rows = cursor.fetchall()
        return [
            {
                "id": row["id"],
                "target_url": row["target_url"],
                "timestamp": row["timestamp"],
                "features": json.loads(row["features_json"]),
                "max_confidence": row["max_confidence"]
            }
            for row in rows
        ]
