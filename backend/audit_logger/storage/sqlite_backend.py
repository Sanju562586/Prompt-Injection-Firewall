"""
SQLite Relational Audit Storage Backend.
Provides indexed querying and immutable event persistence.
"""

import json
import sqlite3
from pathlib import Path
from typing import List
from backend.audit_logger.schemas import AuditEvent, AuditEventType, AuditQueryFilters
from backend.audit_logger.storage.base import AuditStorageBackend


class SQLiteAuditStorage(AuditStorageBackend):
    """SQLite-backed persistent audit sink with indexed lookup."""

    def __init__(self, db_path: str = "logs/audit.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes database schema and performance indexes."""
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    user_id TEXT,
                    tenant_id TEXT,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    input_snippet TEXT,
                    violations_json TEXT,
                    latency_ms REAL,
                    metadata_json TEXT,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events (timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_req_id ON audit_events (request_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events (decision)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_risk_level ON audit_events (risk_level)")

    def append(self, event: AuditEvent) -> None:
        """Inserts an immutable audit event into the database."""
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp, event_type, request_id, user_id, tenant_id,
                    risk_score, risk_level, decision, input_snippet, violations_json,
                    latency_ms, metadata_json, prev_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp,
                    event.event_type.value,
                    event.request_id,
                    event.user_id,
                    event.tenant_id,
                    event.risk_score,
                    event.risk_level,
                    event.decision,
                    event.input_snippet,
                    json.dumps(event.violations),
                    event.latency_ms,
                    json.dumps(event.metadata),
                    event.prev_hash,
                    event.record_hash,
                ),
            )

    def get_last_hash(self) -> str:
        """Returns the hash of the latest event or GENESIS."""
        with self._get_conn() as conn:
            cursor = conn.execute("SELECT record_hash FROM audit_events ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            return row["record_hash"] if row else "GENESIS"

    def get_all(self) -> List[AuditEvent]:
        """Fetches all events in chronological sequence."""
        with self._get_conn() as conn:
            cursor = conn.execute("SELECT * FROM audit_events ORDER BY id ASC")
            rows = cursor.fetchall()
            return [self._row_to_event(r) for r in rows]

    def query(self, filters: AuditQueryFilters) -> List[AuditEvent]:
        """Queries events using parameterized SQL predicates."""
        clauses = []
        params = []

        if filters.event_type:
            clauses.append("event_type = ?")
            params.append(filters.event_type.value)
        if filters.risk_level:
            clauses.append("risk_level = ?")
            params.append(filters.risk_level)
        if filters.decision:
            clauses.append("decision = ?")
            params.append(filters.decision)
        if filters.request_id:
            clauses.append("request_id = ?")
            params.append(filters.request_id)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query_sql = f"""
            SELECT * FROM audit_events
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([filters.limit, filters.offset])

        with self._get_conn() as conn:
            cursor = conn.execute(query_sql, params)
            rows = cursor.fetchall()
            return [self._row_to_event(r) for r in rows]

    def _row_to_event(self, row: sqlite3.Row) -> AuditEvent:
        return AuditEvent(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            event_type=AuditEventType(row["event_type"]),
            request_id=row["request_id"],
            user_id=row["user_id"],
            tenant_id=row["tenant_id"],
            risk_score=row["risk_score"],
            risk_level=row["risk_level"],
            decision=row["decision"],
            input_snippet=row["input_snippet"],
            violations=json.loads(row["violations_json"] or "[]"),
            latency_ms=row["latency_ms"],
            metadata=json.loads(row["metadata_json"] or "{}"),
            prev_hash=row["prev_hash"],
            record_hash=row["record_hash"],
        )
