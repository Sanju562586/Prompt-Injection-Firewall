"""
Output Scanner Schemas.
Defines data structures for output verification, PII redaction, and leakage detection.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ViolationType(str, Enum):
    PII_LEAK = "PII_LEAK"
    PROMPT_EXTRACTION = "PROMPT_EXTRACTION"
    CANARY_LEAK = "CANARY_LEAK"
    UNSAFE_CODE = "UNSAFE_CODE"
    HALLUCINATION = "HALLUCINATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Violation(BaseModel):
    violation_type: ViolationType
    severity: Severity
    description: str
    matched_text: Optional[str] = None
    start_pos: Optional[int] = None
    end_pos: Optional[int] = None
    replacement: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class OutputScanResult(BaseModel):
    is_safe: bool
    output_risk_score: float = Field(ge=0.0, le=1.0)
    violations: List[Violation] = Field(default_factory=list)
    sanitized_text: Optional[str] = None
    blocked: bool = False
    block_reason: Optional[str] = None
    scan_time_ms: float = 0.0
    details: Dict[str, Any] = Field(default_factory=dict)
