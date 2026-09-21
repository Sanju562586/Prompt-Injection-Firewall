"""
Audit Logging Module.
Tamper-evident, forward-chained immutable logging and forensic verification for LLM Firewall.
"""

from backend.audit_logger.schemas import (
    AuditEvent,
    AuditEventType,
    AuditQueryFilters,
    AuditIntegrityReport,
)
from backend.audit_logger.crypto import AuditCrypto
from backend.audit_logger.storage.base import AuditStorageBackend
from backend.audit_logger.storage.sqlite_backend import SQLiteAuditStorage
from backend.audit_logger.storage.file_backend import FileAuditStorage
from backend.audit_logger.logger import AuditLogger

__all__ = [
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "AuditQueryFilters",
    "AuditIntegrityReport",
    "AuditCrypto",
    "AuditStorageBackend",
    "SQLiteAuditStorage",
    "FileAuditStorage",
]
