"""
Database manager for SQLite audit storage.
Handles table schemas, indexing, connection lifecycle, and aggregation queries.
"""

from __future__ import annotations
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional
from audit.models import AuditEntry, Decision, AttackCategory, RiskLevel, ScanResult

DEFAULT_DB_PATH = Path(__file__).parent.parent / "data" / "audit.db"


class AuditDatabase:
    """Thread-safe SQLite database manager for audit logs."""

    def __init__(self, db_path: str | Path | None = None):
        if db_path is None:
            db_path = os.environ.get("FIREWALL_DB_PATH", DEFAULT_DB_PATH)
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager yielding a connected sqlite3 instance, guaranteed to close on exit."""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        """Initialize SQLite schema, handle migrations, and create indices."""
        with self.connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id      TEXT,
                    timestamp       TEXT NOT NULL,
                    scan_type       TEXT NOT NULL,
                    decision        TEXT NOT NULL,
                    attack_category TEXT NOT NULL,
                    score           REAL NOT NULL,
                    risk_level      TEXT DEFAULT 'LOW',
                    reason          TEXT,
                    latency_ms      REAL,
                    text_snippet    TEXT
                )
            """)
            # Migration check: ensure risk_level exists if table was created previously
            cursor = conn.execute("PRAGMA table_info(audit_log)")
            columns = [row["name"] for row in cursor.fetchall()]
            if "risk_level" not in columns:
                conn.execute("ALTER TABLE audit_log ADD COLUMN risk_level TEXT DEFAULT 'LOW'")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision  ON audit_log(decision)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_category  ON audit_log(attack_category)")
            conn.commit()

    def insert(self, result: ScanResult, scan_type: str = "input") -> int:
        """Insert a scan result into audit_log and return the record ID."""
        risk_val = getattr(result.risk_level, "value", str(result.risk_level))
        with self.connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO audit_log
                    (request_id, timestamp, scan_type, decision, attack_category,
                     score, risk_level, reason, latency_ms, text_snippet)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.request_id,
                    datetime.utcnow().isoformat(),
                    scan_type,
                    result.decision.value,
                    result.attack_category.value,
                    float(result.score),
                    risk_val,
                    result.reason,
                    float(result.latency_ms),
                    result.text_snippet[:200],
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def query(
        self,
        limit: int = 100,
        offset: int = 0,
        decision: Optional[str] = None,
        attack_category: Optional[str] = None,
        scan_type: Optional[str] = None,
    ) -> List[AuditEntry]:
        """Fetch audit log records with optional filtering."""
        sql = "SELECT * FROM audit_log"
        params: List[Any] = []
        where: List[str] = []

        if decision:
            where.append("decision = ?")
            params.append(decision.upper())
        if attack_category:
            where.append("attack_category = ?")
            params.append(attack_category)
        if scan_type:
            where.append("scan_type = ?")
            params.append(scan_type)

        if where:
            sql += " WHERE " + " AND ".join(where)

        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.connection() as conn:
            rows = conn.execute(sql, params).fetchall()

        entries: List[AuditEntry] = []
        for row in rows:
            keys = row.keys()
            try:
                dec = Decision(row["decision"])
            except ValueError:
                dec = Decision.ALLOW
            try:
                cat = AttackCategory(row["attack_category"])
            except ValueError:
                cat = AttackCategory.UNKNOWN

            risk_val = row["risk_level"] if "risk_level" in keys else "LOW"
            try:
                risk = RiskLevel(risk_val)
            except ValueError:
                risk = RiskLevel.LOW

            entries.append(
                AuditEntry(
                    id=row["id"],
                    request_id=row["request_id"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    scan_type=row["scan_type"],
                    decision=dec,
                    attack_category=cat,
                    score=row["score"],
                    risk_level=risk,
                    reason=row["reason"] or "",
                    latency_ms=row["latency_ms"] or 0.0,
                    text_snippet=row["text_snippet"] or "",
                )
            )
        return entries

    def get_stats(self) -> Dict[str, Any]:
        """Compute aggregate statistics for security dashboards."""
        with self.connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='BLOCK'").fetchone()[0]
            warned = conn.execute("SELECT COUNT(*) FROM audit_log WHERE decision='WARN'").fetchone()[0]
            allowed = total - blocked - warned

            # Breakdown by category
            by_cat = conn.execute(
                """
                SELECT attack_category, COUNT(*) as cnt
                FROM audit_log
                WHERE decision != 'ALLOW'
                GROUP BY attack_category
                ORDER BY cnt DESC
                """
            ).fetchall()

            row = conn.execute("SELECT AVG(latency_ms) FROM audit_log").fetchone()
            avg_latency = row[0] if (row and row[0] is not None) else 0.0

        return {
            "total": total,
            "blocked": blocked,
            "warned": warned,
            "allowed": allowed,
            "avg_latency_ms": round(float(avg_latency), 2),
            "by_category": {r["attack_category"]: r["cnt"] for r in by_cat},
        }

    def clear(self) -> None:
        """Clear all audit logs (primarily for testing)."""
        with self.connection() as conn:
            conn.execute("DELETE FROM audit_log")
            conn.commit()
