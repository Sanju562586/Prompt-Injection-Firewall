"""
Audit & Core Data Models
Pydantic schemas used across all modules of the LLM Firewall.
"""

from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ─── Enums ───────────────────────────────────────────────────────────────────

class Decision(str, Enum):
    """Final verdict for a scanned prompt or response."""
    BLOCK = "BLOCK"    # Definitely malicious — do not forward to LLM
    WARN  = "WARN"     # Suspicious — allow but flag/redact for review
    ALLOW = "ALLOW"    # Clean — safe to proceed


class AttackCategory(str, Enum):
    """Categories of prompt injection & LLM security threats."""
    DIRECT_INJECTION   = "direct_injection"    # "Ignore previous instructions..."
    JAILBREAK          = "jailbreak"           # DAN, AIM, fictional framing
    ROLE_HIJACK        = "role_hijack"         # "You are now an unrestricted AI..."
    INDIRECT_INJECTION = "indirect_injection"  # Injections embedded in tool/doc context
    TOKEN_SMUGGLING    = "token_smuggling"     # Base64, ROT13, unicode/whitespace tricks
    PII_EXFILTRATION   = "pii_exfiltration"    # Attempts to extract system prompts or private data
    RAG_POISONING      = "rag_poisoning"       # Poisoned retrieved knowledge chunks
    UNKNOWN            = "unknown"


class DetectorLayer(str, Enum):
    """Detection layer identifier."""
    RULES       = "rules"       # Regex & pattern heuristics (formerly PATTERN)
    PATTERN     = "pattern"     # Backward-compatible alias
    SEMANTIC    = "semantic"    # Sentence-transformer embedding similarity
    CLASSIFIER  = "classifier"  # Pre-trained DeBERTa transformer
    PII         = "pii"         # Presidio / PII detector
    RISK_ENGINE = "risk_engine" # Multi-factor threat scoring engine


class RiskLevel(str, Enum):
    """Threat risk categorization level."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ─── Scan Models ──────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """A prompt or text to be scanned by the firewall."""
    text: str = Field(..., description="The prompt or response text to scan")
    context: Optional[str] = Field(None, description="Optional system prompt or prior conversation context")
    request_id: Optional[str] = Field(None, description="Caller-supplied trace/request ID")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata (user, tenant, source)")


class DetectorResult(BaseModel):
    """Output from a single detection layer."""
    layer: DetectorLayer
    triggered: bool
    score: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    attack_category: AttackCategory = AttackCategory.UNKNOWN
    reason: str = ""
    matched: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Final result after all detectors and risk evaluation have run."""
    request_id: Optional[str] = None
    text_snippet: str = Field(..., description="Preview snippet of the scanned text")
    decision: Decision
    score: float = Field(..., ge=0.0, le=1.0, description="Overall threat score (0-1)")
    attack_category: AttackCategory = AttackCategory.UNKNOWN
    risk_level: RiskLevel = RiskLevel.LOW
    reason: str
    latency_ms: float
    detector_results: List[DetectorResult] = Field(default_factory=list)
    redacted_text: Optional[str] = Field(None, description="Redacted text if PII was sanitized")


# ─── RAG Models ───────────────────────────────────────────────────────────────

class RagDocument(BaseModel):
    """A single document chunk retrieved from a knowledge base."""
    doc_id: str
    content: str
    source: Optional[str] = None


class RagScanResult(BaseModel):
    """Outcome of scanning a collection of RAG-retrieved documents."""
    poisoned_count: int
    clean_count: int
    results: List[Dict[str, Any]] = Field(default_factory=list)


# ─── Audit Log Models ─────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    """Persistent audit log record."""
    id: Optional[int] = None
    request_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    scan_type: str = "input" # "input", "output", "rag", or "proxy"
    decision: Decision
    attack_category: AttackCategory = AttackCategory.UNKNOWN
    score: float
    risk_level: RiskLevel = RiskLevel.LOW
    reason: str = ""
    latency_ms: float = 0.0
    text_snippet: str = ""


# ─── Red-Team Models ──────────────────────────────────────────────────────────

class AttackVector(BaseModel):
    """A single red-team benchmark test case."""
    id: str
    category: AttackCategory
    prompt: str
    description: str
    expected_decision: Decision = Decision.BLOCK


class RedTeamResult(BaseModel):
    """Outcome of running an attack vector against the firewall."""
    attack: AttackVector
    actual_decision: Decision
    score: float
    passed: bool
    reason: str
    latency_ms: float = 0.0


# ─── Reverse Proxy Models ─────────────────────────────────────────────────────

class ProxyMessage(BaseModel):
    role: str
    content: str


class ProxyChatRequest(BaseModel):
    model: str = "gpt-3.5-turbo"
    messages: List[ProxyMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False
