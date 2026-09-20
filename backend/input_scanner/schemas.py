from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AttackType(str, Enum):
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLE_HIJACK = "role_hijack"
    JAILBREAK_DAN = "jailbreak_dan"
    DELIMITER_INJECTION = "delimiter_injection"
    OBFUSCATION = "obfuscation"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    RECURSIVE_INJECTION = "recursive_injection"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class RiskLevel(str, Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RuleMatch(BaseModel):
    rule_id: str
    name: str
    attack_type: AttackType
    severity: RiskLevel
    matched_substring: str
    confidence: float = Field(ge=0.0, le=1.0)


class ScanRequest(BaseModel):
    text: str = Field(..., description="Prompt or user message to inspect for injections")
    context: Optional[str] = Field(None, description="Optional conversation context or system persona")
    sensitivity_threshold: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Override default sensitivity threshold (lower = higher recall)"
    )
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Metadata such as user ID, session ID")


class ScanResult(BaseModel):
    is_safe: bool
    decision: Decision
    risk_score: float = Field(ge=0.0, le=1.0, description="Combined risk score from 0.0 (safe) to 1.0 (critical)")
    risk_level: RiskLevel
    attack_types: List[AttackType]
    flagged_rules: List[RuleMatch]
    ml_score: float = Field(ge=0.0, le=1.0, description="DeBERTa injection probability")
    ml_label: Optional[str] = None
    sanitized_text: Optional[str] = None
    latency_ms: float
    explanation: str
