"""
Append-Only File Audit Storage Backend.
Stores audit records as immutable, forward-chained JSON Lines (JSONL).
"""

import json
import os
from pathlib import Path
from typing import List
from backend.audit_logger.schemas import AuditEvent, AuditQueryFilters
from backend.audit_logger.storage.base import AuditStorageBackend


class FileAuditStorage(AuditStorageBackend):
    """File-based JSONL audit sink."""

    def __init__(self, file_path: str = "logs/audit.jsonl"):
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.file_path.exists():
            self.file_path.touch()

    def append(self, event: AuditEvent) -> None:
        """Appends serialized event line to JSONL file."""
        with open(self.file_path, "a", encoding="utf-8") as f:
            f.write(event.model_dump_json() + "\n")

    def get_all(self) -> List[AuditEvent]:
        """Reads all events from the log file in sequence."""
        events: List[AuditEvent] = []
        if not self.file_path.exists():
            return events

        with open(self.file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(AuditEvent.model_validate_json(line))
        return events

    def get_last_hash(self) -> str:
        """Finds the record hash of the last entry in the file."""
        events = self.get_all()
        return events[-1].record_hash if events else "GENESIS"

    def query(self, filters: AuditQueryFilters) -> List[AuditEvent]:
        """Filters events in-memory from file lines."""
        events = self.get_all()
        filtered = []
        for e in events:
            if filters.event_type and e.event_type != filters.event_type:
                continue
            if filters.risk_level and e.risk_level != filters.risk_level:
                continue
            if filters.decision and e.decision != filters.decision:
                continue
            if filters.request_id and e.request_id != filters.request_id:
                continue
            filtered.append(e)

        return filtered[filters.offset : filters.offset + filters.limit]
