"""
Tests for Module 4: Audit (Models, Database, Logger).
"""

import tempfile
from pathlib import Path
from datetime import datetime

from audit.models import Decision, AttackCategory, RiskLevel, ScanResult, AuditEntry
from audit.database import AuditDatabase
from audit.logger import AuditLogger


def test_models_instantiation():
    entry = AuditEntry(
        request_id="req-123",
        timestamp=datetime.utcnow(),
        scan_type="input",
        decision=Decision.BLOCK,
        attack_category=AttackCategory.DIRECT_INJECTION,
        score=0.95,
        risk_level=RiskLevel.CRITICAL,
        reason="Matched pattern",
        latency_ms=1.5,
        text_snippet="ignore previous instructions",
    )
    assert entry.decision == Decision.BLOCK
    assert entry.risk_level == RiskLevel.CRITICAL
    assert entry.score == 0.95


def test_database_insert_and_query():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_audit.db"
        db = AuditDatabase(db_path)

        scan_res = ScanResult(
            request_id="test-1",
            text_snippet="Test input snippet",
            decision=Decision.BLOCK,
            score=0.92,
            attack_category=AttackCategory.DIRECT_INJECTION,
            risk_level=RiskLevel.CRITICAL,
            reason="Blocked by test",
            latency_ms=2.5,
        )

        row_id = db.insert(scan_res, scan_type="input")
        assert row_id > 0

        entries = db.query(limit=10)
        assert len(entries) == 1
        assert entries[0].request_id == "test-1"
        assert entries[0].decision == Decision.BLOCK
        assert entries[0].attack_category == AttackCategory.DIRECT_INJECTION

        stats = db.get_stats()
        assert stats["total"] == 1
        assert stats["blocked"] == 1
        assert stats["allowed"] == 0


def test_logger_query_filters():
    with tempfile.TemporaryDirectory() as tmpdir:
        logger = AuditLogger(Path(tmpdir) / "logger_test.db")

        # Log 1: BLOCK
        logger.log(ScanResult(
            request_id="r1", text_snippet="bad", decision=Decision.BLOCK,
            score=0.9, attack_category=AttackCategory.JAILBREAK, risk_level=RiskLevel.HIGH,
            reason="bad prompt", latency_ms=1.0
        ), scan_type="input")

        # Log 2: ALLOW
        logger.log(ScanResult(
            request_id="r2", text_snippet="good", decision=Decision.ALLOW,
            score=0.1, attack_category=AttackCategory.UNKNOWN, risk_level=RiskLevel.LOW,
            reason="clean prompt", latency_ms=1.0
        ), scan_type="input")

        blocked = logger.query(decision="BLOCK")
        assert len(blocked) == 1
        assert blocked[0].request_id == "r1"

        allowed = logger.query(decision="ALLOW")
        assert len(allowed) == 1
        assert allowed[0].request_id == "r2"

        stats = logger.stats()
        assert stats["total"] == 2
        assert stats["blocked"] == 1
        assert stats["allowed"] == 1
