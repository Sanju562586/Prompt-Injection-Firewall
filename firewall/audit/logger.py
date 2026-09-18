"""
Audit Logger — SQLite-backed
Records every scan result in a local SQLite database.

Schema (table: audit_log):
  id             INTEGER PRIMARY KEY
  request_id     TEXT
  timestamp      TEXT (ISO 8601 UTC)
  scan_type      TEXT  — "input" | "output" | "rag"
  decision       TEXT  — "BLOCK" | "WARN" | "ALLOW"
  attack_category TEXT
  score          REAL
  reason         TEXT
  latency_ms     REAL
  text_snippet   TEXT  — first 120 chars only (privacy)

Usage:
  from firewall.audit.logger import AuditLogger
  logger = AuditLogger()
  logger.log(scan_result, scan_type="input")
  entries = logger.query(limit=50)
"""

from __future__ import annotations
import sqlite3
import os
from datetime import datetime
from pathlib import Path
from firewall.models import ScanResult, AuditEntry, Decision, AttackCategory

# Default DB path — can be overridden via FIREWALL_DB_PATH env var
DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "audit.db"


class AuditLogger:
    """Thread-safe SQLite audit logger."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path or os.environ.get("FIREWALL_DB_PATH", DEFAULT_DB_PATH))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create the audit_log table if it doesn't exist."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id      TEXT,
                    timestamp       TEXT NOT NULL,
                    scan_type       TEXT NOT NULL,
                    decision        TEXT NOT NULL,
                    attack_category TEXT NOT NULL,
                    score           REAL NOT NULL,
                    reason          TEXT,
                    latency_ms      REAL,
                    text_snippet    TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_decision  ON audit_log(decision)")
            conn.commit()

    def log(self, result: ScanResult, scan_type: str = "input") -> None:
        """Insert a scan result into the audit log."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                    (request_id, timestamp, scan_type, decision, attack_category,
                     score, reason, latency_ms, text_snippet)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.request_id,
                    datetime.utcnow().isoformat(),
                    scan_type,
                    result.decision.value,
                    result.attack_category.value,
                    result.score,
                    result.reason,
                    result.latency_ms,
                    result.text_snippet,
                ),
            )
            conn.commit()

    def query(
        self,
        limit: int = 100,
        offset: int = 0,
        decision: str | None = None,
        attack_category: str | None = None,
    ) -> list[AuditEntry]:
        """Retrieve audit log entries with optional filters."""
        sql    = "SELECT * FROM audit_log"
        params: list = []
        where  = []

        if decision:
            where.append("decision = ?")
            params.append(decision.upper())
        if attack_category:
            where.append("attack_category = ?")
            params.append(attack_category)

        if where:
            sql += " WHERE " + " AND ".join(where)

        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params += [limit, offset]

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [
            AuditEntry(
                id=row["id"],
                request_id=row["request_id"],
                timestamp=datetime.fromisoformat(row["timestamp"]),
                scan_type=row["scan_type"],
                decision=Decision(row["decision"]),
                attack_category=AttackCategory(row["attack_category"]),
                score=row["score"],
                reason=row["reason"],
                latency_ms=row["latency_ms"],
                text_snippet=row["text_snippet"],
            )
            for row in rows
        ]

    def stats(self) -> dict:
        """Return aggregate statistics for the dashboard."""
        with self._connect() as conn:
            total   = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='BLOCK'").fetchone()[0]
            warned  = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='WARN'").fetchone()[0]
            by_cat  = conn.execute(
                "SELECT attack_category, COUNT(*) as cnt FROM audit_log GROUP BY attack_category ORDER BY cnt DESC"
            ).fetchall()

        return {
            "total":      total,
            "blocked":    blocked,
            "warned":     warned,
            "allowed":    total - blocked - warned,
            "by_category": {row["attack_category"]: row["cnt"] for row in by_cat},
        }
