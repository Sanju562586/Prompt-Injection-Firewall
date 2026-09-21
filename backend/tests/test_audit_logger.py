"""
Unit and Forensic Integrity Tests for Module 6 - Audit Logger.
Tests SHA-256 hash chaining, tamper detection, query filtering, and PII masking.
"""

import os
import pytest
from backend.audit_logger import (
    AuditLogger,
    AuditEventType,
    AuditQueryFilters,
    SQLiteAuditStorage,
)


@pytest.fixture
def temp_logger(tmp_path):
    db_file = tmp_path / "test_audit.db"
    storage = SQLiteAuditStorage(db_path=str(db_file))
    return AuditLogger(storage=storage)


def test_sequential_hash_chaining(temp_logger):
    # Log 3 events
    e1 = temp_logger.log_event(
        event_type=AuditEventType.PROMPT_SCAN,
        request_id="req-101",
        risk_score=0.1,
        risk_level="LOW",
        decision="ALLOW",
        input_text="Normal query",
    )
    assert e1.prev_hash == "GENESIS"
    assert len(e1.record_hash) == 64

    e2 = temp_logger.log_event(
        event_type=AuditEventType.RISK_EVALUATION,
        request_id="req-102",
        risk_score=0.85,
        risk_level="CRITICAL",
        decision="BLOCK",
        input_text="Malicious payload",
        violations=["Rule: DAN_JAILBREAK"],
    )
    assert e2.prev_hash == e1.record_hash
    assert len(e2.record_hash) == 64

    e3 = temp_logger.log_event(
        event_type=AuditEventType.FIREWALL_BLOCK,
        request_id="req-103",
        risk_score=0.92,
        risk_level="CRITICAL",
        decision="BLOCK",
        input_text="Another attack",
    )
    assert e3.prev_hash == e2.record_hash

    # Verify integrity of untampered chain
    report = temp_logger.verify_integrity()
    assert report.is_valid is True
    assert report.total_records_checked == 3
    assert len(report.tampered_records) == 0


def test_tamper_detection_flags_altered_record(temp_logger):
    # Log 2 events
    temp_logger.log_event(
        event_type=AuditEventType.PROMPT_SCAN,
        request_id="req-201",
        risk_score=0.2,
        risk_level="LOW",
        decision="ALLOW",
        input_text="Event 1",
    )
    temp_logger.log_event(
        event_type=AuditEventType.FIREWALL_BLOCK,
        request_id="req-202",
        risk_score=0.9,
        risk_level="CRITICAL",
        decision="BLOCK",
        input_text="Event 2",
    )

    # Validate before tampering
    assert temp_logger.verify_integrity().is_valid is True

    # Maliciously alter the database record directly (tamper attack)
    with temp_logger.storage._get_conn() as conn:
        conn.execute("UPDATE audit_events SET risk_score = 0.05 WHERE request_id = 'req-202'")

    # Run cryptographic verification
    report = temp_logger.verify_integrity()
    assert report.is_valid is False
    assert len(report.tampered_records) > 0
    assert "req-202" in [
        e.request_id for e in temp_logger.storage.get_all() if e.event_id in report.tampered_records
    ]


def test_pii_masking_in_audit_record(temp_logger):
    sensitive_prompt = "User SSN is 123-45-6789 and API key is sk-1234567890abcdefghijklmnopqrstuvwxyz."
    event = temp_logger.log_event(
        event_type=AuditEventType.PROMPT_SCAN,
        request_id="req-301",
        risk_score=0.7,
        risk_level="HIGH",
        decision="BLOCK",
        input_text=sensitive_prompt,
    )

    assert "123-45-6789" not in event.input_snippet
    assert "sk-1234567890" not in event.input_snippet
    assert "[REDACTED_SENSITIVE]" in event.input_snippet


def test_audit_query_filtering(temp_logger):
    # Add multiple records
    temp_logger.log_event(AuditEventType.PROMPT_SCAN, "req-A", 0.1, "LOW", "ALLOW")
    temp_logger.log_event(AuditEventType.FIREWALL_BLOCK, "req-B", 0.9, "CRITICAL", "BLOCK")
    temp_logger.log_event(AuditEventType.FIREWALL_BLOCK, "req-C", 0.85, "CRITICAL", "BLOCK")

    # Filter by decision
    blocks = temp_logger.query(AuditQueryFilters(decision="BLOCK"))
    assert len(blocks) == 2
    for b in blocks:
        assert b.decision == "BLOCK"

    # Filter by request_id
    req_a = temp_logger.query(AuditQueryFilters(request_id="req-A"))
    assert len(req_a) == 1
    assert req_a[0].request_id == "req-A"


def test_metrics_summary(temp_logger):
    temp_logger.log_event(AuditEventType.PROMPT_SCAN, "req-1", 0.1, "LOW", "ALLOW", latency_ms=10.0)
    temp_logger.log_event(AuditEventType.FIREWALL_BLOCK, "req-2", 0.9, "CRITICAL", "BLOCK", latency_ms=20.0)

    metrics = temp_logger.get_metrics_summary()
    assert metrics["total_events"] == 2
    assert metrics["decisions"]["ALLOW"] == 1
    assert metrics["decisions"]["BLOCK"] == 1
    assert metrics["avg_risk_score"] == 0.5
    assert metrics["avg_latency_ms"] == 15.0
    assert metrics["blocked_percentage"] == 50.0
