import contextlib
import sqlite3
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List
from pydantic import ValidationError
from proxyvet.core.models import IPSignalData, VerdictResult

class CacheManager:
    def __init__(self, db_path: str):
        self.db_path = db_path

    @contextlib.contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

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
            try:
                updated_at = datetime.fromisoformat(updated_at_str)
            except ValueError:
                return None

            if updated_at.tzinfo is None:
                updated_at = updated_at.replace(tzinfo=timezone.utc)
            else:
                updated_at = updated_at.astimezone(timezone.utc)

            if datetime.now(timezone.utc) - updated_at > timedelta(hours=ttl_hours):
                return None

            try:
                return IPSignalData.model_validate_json(data_str)
            except ValidationError:
                return None

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
                checked_at_val = row[4]
                if checked_at_val:
                    try:
                        dt = datetime.fromisoformat(checked_at_val)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        else:
                            dt = dt.astimezone(timezone.utc)
                        checked_at_val = dt.isoformat()
                    except ValueError:
                        try:
                            dt = datetime.strptime(checked_at_val, "%Y-%m-%d %H:%M:%S")
                            dt = dt.replace(tzinfo=timezone.utc)
                            checked_at_val = dt.isoformat()
                        except ValueError:
                            pass
                results.append({
                    "verdict": row[0],
                    "composite_score": row[1],
                    "reasons": json.loads(row[2]),
                    "signals": json.loads(row[3]),
                    "checked_at": checked_at_val
                })
            return results

    def save_history(self, result: VerdictResult):
        with self._get_conn() as conn:
            reasons_str = json.dumps(result.reasons)
            signals_str = json.dumps([sig.model_dump() for sig in result.signals])
            
            checked_at_utc = result.checked_at
            if checked_at_utc.tzinfo is None:
                checked_at_utc = checked_at_utc.replace(tzinfo=timezone.utc)
            else:
                checked_at_utc = checked_at_utc.astimezone(timezone.utc)
            checked_at_str = checked_at_utc.isoformat()
            
            conn.execute(
                """
                INSERT INTO history (ip, verdict, composite_score, reasons, signals, checked_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (result.ip, result.verdict.value, result.composite_score, reasons_str, signals_str, checked_at_str)
            )
