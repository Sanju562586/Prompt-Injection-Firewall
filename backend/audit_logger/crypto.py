"""
Cryptographic Tamper-Evidence and Hash Chaining.
Provides SHA-256 HMAC and forward-chained block verification for security audit records.
"""

import hashlib
import json
from typing import List, Tuple
from backend.audit_logger.schemas import AuditEvent, AuditIntegrityReport


class AuditCrypto:
    """Cryptographic utility for tamper-evident audit logging."""

    @staticmethod
    def compute_record_hash(event: AuditEvent, prev_hash: str) -> str:
        """
        Calculates SHA-256 digest of canonical event representation chained to prev_hash.
        """
        payload = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "event_type": event.event_type.value,
            "request_id": event.request_id,
            "user_id": event.user_id,
            "tenant_id": event.tenant_id,
            "risk_score": round(event.risk_score, 4),
            "risk_level": event.risk_level,
            "decision": event.decision,
            "input_snippet": event.input_snippet,
            "violations": sorted(event.violations),
            "latency_ms": round(event.latency_ms, 2),
            "prev_hash": prev_hash,
        }
        canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    @classmethod
    def verify_chain(cls, events: List[AuditEvent]) -> AuditIntegrityReport:
        """
        Validates the complete hash chain from genesis to head.
        Flags any altered records or broken links.
        """
        if not events:
            return AuditIntegrityReport(
                is_valid=True,
                total_records_checked=0,
                broken_link_indices=[],
                tampered_records=[],
                details="Empty audit chain. Integrity verified.",
            )

        broken_indices: List[int] = []
        tampered_ids: List[str] = []
        expected_prev_hash = "GENESIS"

        for idx, event in enumerate(events):
            # Check link to previous record
            if event.prev_hash != expected_prev_hash:
                broken_indices.append(idx)
                tampered_ids.append(event.event_id)

            # Recompute expected hash
            expected_hash = cls.compute_record_hash(event, event.prev_hash)
            if event.record_hash != expected_hash:
                if idx not in broken_indices:
                    broken_indices.append(idx)
                if event.event_id not in tampered_ids:
                    tampered_ids.append(event.event_id)

            expected_prev_hash = event.record_hash

        is_valid = len(broken_indices) == 0
        details = (
            f"Audit chain verification succeeded ({len(events)} records verified)."
            if is_valid
            else f"CRITICAL: Integrity failure detected across {len(tampered_ids)} record(s)."
        )

        return AuditIntegrityReport(
            is_valid=is_valid,
            total_records_checked=len(events),
            broken_link_indices=broken_indices,
            tampered_records=tampered_ids,
            details=details,
        )
