"""
Audit Storage Base Interface.
"""

from abc import ABC, abstractmethod
from typing import List
from backend.audit_logger.schemas import AuditEvent, AuditQueryFilters


class AuditStorageBackend(ABC):
    """Abstract interface for audit log persistence backends."""

    @abstractmethod
    def append(self, event: AuditEvent) -> None:
        """Persists an individual audit event."""
        pass

    @abstractmethod
    def query(self, filters: AuditQueryFilters) -> List[AuditEvent]:
        """Queries stored audit records based on criteria."""
        pass

    @abstractmethod
    def get_last_hash(self) -> str:
        """Retrieves the record hash of the latest event in the chain."""
        pass

    @abstractmethod
    def get_all(self) -> List[AuditEvent]:
        """Retrieves all audit events in chronological order for verification."""
        pass
