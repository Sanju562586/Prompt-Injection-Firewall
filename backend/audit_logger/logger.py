"""
Enterprise Audit Logger Service.
Manages tamper-evident logging, cryptographic chain validation, PII anonymization, and forensic analysis.
"""

import re
import threading
import time
from typing import Any, Dict, List, Optional
from backend.audit_logger.schemas import (
    AuditEvent,
    AuditEventType,
    AuditQueryFilters,
    AuditIntegrityReport,
)
from backend.audit_logger.crypto import AuditCrypto
from backend.audit_logger.storage.base import AuditStorageBackend
from backend.audit_logger.storage.sqlite_backend import SQLiteAuditStorage


class AuditLogger:
    """Enterprise Audit Logger with tamper-evident cryptographic chaining."""

    _instance: Optional["AuditLogger"] = None
    _lock = threading.Lock()

    def __init__(self, storage: Optional[AuditStorageBackend] = None):
        self.storage = storage or SQLiteAuditStorage()
        self._write_lock = threading.Lock()
        self._pii_cleaner = re.compile(
            r"\b\d{3}-\d{2}-\d{4}\b|\b(?:\d{4}[-\s]?){3}\d{4}\b|\bsk-[a-zA-Z0-9]{20,}\b"
        )

    @classmethod
    def get_instance(cls, storage: Optional[AuditStorageBackend] = None) -> "AuditLogger":
        """Singleton accessor for shared audit logging."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(storage=storage)
            return cls._instance

    def _mask_pii(self, text: Optional[str]) -> Optional[str]:
        """Scrubs any raw PII from text before recording in audit storage."""
        if not text:
            return None
        return self._pii_cleaner.sub("[REDACTED_SENSITIVE]", text[:300])

    def log_event(
        self,
        event_type: AuditEventType,
        request_id: str,
        risk_score: float,
        risk_level: str,
        decision: str,
        input_text: Optional[str] = None,
        violations: Optional[List[str]] = None,
        latency_ms: float = 0.0,
        user_id: Optional[str] = "anonymous",
        tenant_id: Optional[str] = "default",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        """
        Atomically links and persists a tamper-evident audit event.
        """
        with self._write_lock:
            prev_hash = self.storage.get_last_hash()
            masked_snippet = self._mask_pii(input_text)

            event = AuditEvent(
                timestamp=time.time(),
                event_type=event_type,
                request_id=request_id,
                user_id=user_id or "anonymous",
                tenant_id=tenant_id or "default",
                risk_score=round(risk_score, 4),
                risk_level=risk_level,
                decision=decision,
                input_snippet=masked_snippet,
                violations=violations or [],
                latency_ms=round(latency_ms, 2),
                metadata=metadata or {},
                prev_hash=prev_hash,
            )

            # Compute cryptographic hash bound to previous record
            event.record_hash = AuditCrypto.compute_record_hash(event, prev_hash)

            # Persist to storage backend
            self.storage.append(event)
            return event

    def query(self, filters: Optional[AuditQueryFilters] = None) -> List[AuditEvent]:
        """Queries events using filters."""
        return self.storage.query(filters or AuditQueryFilters())

    def verify_integrity(self) -> AuditIntegrityReport:
        """
        Traverses the full audit chain and verifies cryptographic hashes.
        Detects any unauthorized modification, deletion, or record insertion.
        """
        all_events = self.storage.get_all()
        return AuditCrypto.verify_chain(all_events)

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Aggregates high-level telemetry metrics from stored audit logs."""
        events = self.storage.get_all()
        total = len(events)
        if total == 0:
            return {
                "total_events": 0,
                "decisions": {},
                "risk_levels": {},
                "avg_risk_score": 0.0,
                "avg_latency_ms": 0.0,
                "blocked_percentage": 0.0,
            }

        decision_counts: Dict[str, int] = {}
        risk_counts: Dict[str, int] = {}
        total_risk = 0.0
        total_latency = 0.0

        for e in events:
            decision_counts[e.decision] = decision_counts.get(e.decision, 0) + 1
            risk_counts[e.risk_level] = risk_counts.get(e.risk_level, 0) + 1
            total_risk += e.risk_score
            total_latency += e.latency_ms

        blocked_count = decision_counts.get("BLOCK", 0) + decision_counts.get("QUARANTINE", 0)

        return {
            "total_events": total,
            "decisions": decision_counts,
            "risk_levels": risk_counts,
            "avg_risk_score": round(total_risk / total, 4),
            "avg_latency_ms": round(total_latency / total, 2),
            "blocked_percentage": round((blocked_count / total) * 100.0, 2),
        }
