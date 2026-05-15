"""
Event Store
-----------
탐지된 시그널을 SQLite에 저장한다. 대시보드에서 조회용.
"""

import json
import sqlite3
import threading
from pathlib import Path
from typing import List

from scoring import Signal, Severity


SCHEMA = """
CREATE TABLE IF NOT EXISTS signals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   REAL    NOT NULL,
    detector    TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    weight      INTEGER NOT NULL,
    severity    TEXT    NOT NULL,
    message     TEXT    NOT NULL,
    metadata    TEXT    NOT NULL,
    score_after INTEGER NOT NULL,
    level_after TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_signals_timestamp ON signals(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_signals_severity  ON signals(severity);
"""


class EventStore:
    def __init__(self, db_path: str = "detector.db"):
        self.path = Path(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as c:
            c.executescript(SCHEMA)

    def record(self, signal: Signal, score_after: int, level_after: Severity) -> None:
        with self._lock, self._connect() as c:
            c.execute(
                """INSERT INTO signals
                   (timestamp, detector, name, weight, severity, message, metadata,
                    score_after, level_after)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    signal.timestamp,
                    signal.detector,
                    signal.name,
                    signal.weight,
                    signal.severity.value,
                    signal.message,
                    json.dumps(signal.metadata, default=str),
                    score_after,
                    level_after.value,
                ),
            )

    def recent(self, limit: int = 100) -> List[dict]:
        with self._lock, self._connect() as c:
            rows = c.execute(
                "SELECT * FROM signals ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["metadata"] = json.loads(d["metadata"])
            except json.JSONDecodeError:
                d["metadata"] = {}
            out.append(d)
        return out

    def stats(self) -> dict:
        with self._lock, self._connect() as c:
            total = c.execute("SELECT COUNT(*) FROM signals").fetchone()[0]
            by_detector = {
                r["detector"]: r["n"]
                for r in c.execute(
                    "SELECT detector, COUNT(*) AS n FROM signals GROUP BY detector"
                )
            }
            by_severity = {
                r["severity"]: r["n"]
                for r in c.execute(
                    "SELECT severity, COUNT(*) AS n FROM signals GROUP BY severity"
                )
            }
        return {"total": total, "by_detector": by_detector, "by_severity": by_severity}
