import sqlite3
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from proxyvet.core.models import IPSignalData, VerdictResult

class CacheManager:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    ip TEXT NOT NULL,
                    source TEXT NOT NULL,
                    data TEXT NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    PRIMARY KEY (ip, source)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    composite_score REAL NOT NULL,
                    reasons TEXT NOT NULL,
                    signals TEXT NOT NULL,
                    checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def get_cached_signal(self, ip: str, source: str, ttl_hours: int) -> Optional[IPSignalData]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT data, updated_at FROM cache WHERE ip = ? AND source = ?", (ip, source)
            )
            row = cursor.fetchone()
            if not row:
                return None
            data_str, updated_at_str = row
            updated_at = datetime.fromisoformat(updated_at_str)
            if datetime.now(timezone.utc) - updated_at > timedelta(hours=ttl_hours):
                return None
            return IPSignalData.model_validate_json(data_str)

    def save_cached_signal(self, signal: IPSignalData):
        with self._get_conn() as conn:
            data_str = signal.model_dump_json()
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """
                INSERT OR REPLACE INTO cache (ip, source, data, updated_at)
                VALUES (?, ?, ?, ?)
                """, (signal.ip, signal.source, data_str, now)
            )

    def get_history(self, ip: str) -> List[dict]:
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT verdict, composite_score, reasons, signals, checked_at FROM history WHERE ip = ? ORDER BY checked_at DESC",
                (ip,)
            )
            results = []
            for row in cursor.fetchall():
                results.append({
                    "verdict": row[0],
                    "composite_score": row[1],
                    "reasons": json.loads(row[2]),
                    "signals": json.loads(row[3]),
                    "checked_at": row[4]
                })
            return results

    def save_history(self, result: VerdictResult):
        with self._get_conn() as conn:
            reasons_str = json.dumps(result.reasons)
            signals_str = json.dumps([sig.model_dump() for sig in result.signals])
            conn.execute(
                """
                INSERT INTO history (ip, verdict, composite_score, reasons, signals, checked_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (result.ip, result.verdict.value, result.composite_score, reasons_str, signals_str, result.checked_at.isoformat())
            )
