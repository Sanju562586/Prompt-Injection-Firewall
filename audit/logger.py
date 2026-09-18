"""
Audit Logger
Service for recording scan events, tracking forensic telemetry, and serving metrics.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List, Optional
from audit.database import AuditDatabase
from audit.models import AuditEntry, ScanResult


class AuditLogger:
    """Thread-safe logging service for firewall audit events."""

    def __init__(self, db_path: str | Path | None = None):
        self.db = AuditDatabase(db_path)

    def log(self, result: ScanResult, scan_type: str = "input") -> int:
        """Record a scan event."""
        return self.db.insert(result, scan_type=scan_type)

    def query(
        self,
        limit: int = 100,
        offset: int = 0,
        decision: Optional[str] = None,
        attack_category: Optional[str] = None,
        scan_type: Optional[str] = None,
    ) -> List[AuditEntry]:
        """Fetch audit log entries."""
        return self.db.query(
            limit=limit,
            offset=offset,
            decision=decision,
            attack_category=attack_category,
            scan_type=scan_type,
        )

    def stats(self) -> Dict[str, Any]:
        """Return aggregated audit stats."""
        return self.db.get_stats()

    def get_stats(self) -> Dict[str, Any]:
        """Alias for stats()."""
        return self.db.get_stats()

    def clear(self) -> None:
        """Clear logs (for testing)."""
        self.db.clear()
