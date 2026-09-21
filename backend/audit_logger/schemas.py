"""
Audit Logger Schemas.
Defines immutable audit event formats, query filters, and cryptographic verification reports.
"""

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    PROMPT_SCAN = "PROMPT_SCAN"
    RAG_INSPECTION = "RAG_INSPECTION"
    RISK_EVALUATION = "RISK_EVALUATION"
    OUTPUT_SCAN = "OUTPUT_SCAN"
    FIREWALL_BLOCK = "FIREWALL_BLOCK"
    FIREWALL_ALLOW = "FIREWALL_ALLOW"
    SECURITY_ALERT = "SECURITY_ALERT"


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    timestamp: float = Field(default_factory=time.time)
    event_type: AuditEventType
    request_id: str
    user_id: Optional[str] = "anonymous"
    tenant_id: Optional[str] = "default"
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: str
    decision: str
    input_snippet: Optional[str] = None
    violations: List[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = "GENESIS"
    record_hash: str = ""


class AuditQueryFilters(BaseModel):
    event_type: Optional[AuditEventType] = None
    risk_level: Optional[str] = None
    decision: Optional[str] = None
    request_id: Optional[str] = None
    limit: int = 100
    offset: int = 0


class AuditIntegrityReport(BaseModel):
    is_valid: bool
    total_records_checked: int
    broken_link_indices: List[int] = Field(default_factory=list)
    tampered_records: List[str] = Field(default_factory=list)
    details: str
