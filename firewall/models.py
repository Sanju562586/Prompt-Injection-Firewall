"""
Data models used throughout the firewall.
All inputs and outputs are typed via Pydantic for validation and clarity.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


# ─── Decision Enums ───────────────────────────────────────────────────────────

class Decision(str, Enum):
    """Final verdict for a scanned prompt or response."""
    BLOCK  = "BLOCK"   # Definitely malicious — do not forward to LLM
    WARN   = "WARN"    # Suspicious — allow but flag for review
    ALLOW  = "ALLOW"   # Clean — safe to proceed


class AttackCategory(str, Enum):
    """Categories of prompt injection attacks."""
    DIRECT_INJECTION  = "direct_injection"    # "Ignore previous instructions…"
    JAILBREAK         = "jailbreak"           # DAN, AIM, fictional framing
    ROLE_HIJACK       = "role_hijack"         # "You are now an unrestricted AI…"
    INDIRECT_INJECTION= "indirect_injection"  # Attacks embedded in tool/doc output
    TOKEN_SMUGGLING   = "token_smuggling"     # Base64, ROT13, whitespace tricks
    PII_EXFILTRATION  = "pii_exfiltration"    # Attempting to extract private data
    RAG_POISONING     = "rag_poisoning"       # Injections hidden in retrieved docs
    UNKNOWN           = "unknown"


class DetectorLayer(str, Enum):
    """Which detection layer caught the attack."""
    PATTERN    = "pattern"     # Layer 1 — regex/keyword rules
    SEMANTIC   = "semantic"    # Layer 2 — sentence-transformer similarity
    CLASSIFIER = "classifier"  # Layer 3 — pre-trained DeBERTa model
    PII        = "pii"         # Presidio PII detector (output scanner)


# ─── Scan Models ──────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """A prompt or text to be scanned by the firewall."""
    text: str = Field(..., description="The prompt or response text to scan")
    context: Optional[str] = Field(None, description="Optional system prompt or prior context")
    request_id: Optional[str] = Field(None, description="Caller-supplied trace ID")


class DetectorResult(BaseModel):
    """Result from a single detection layer."""
    layer: DetectorLayer
    triggered: bool
    score: float = Field(..., ge=0.0, le=1.0, description="Confidence score 0–1")
    attack_category: AttackCategory = AttackCategory.UNKNOWN
    reason: str = ""                  # Human-readable explanation
    matched: Optional[str] = None     # Matched pattern or closest attack label


class ScanResult(BaseModel):
    """Final result after all detectors have run."""
    request_id: Optional[str]
    text_snippet: str                 # First 120 chars of the scanned text
    decision: Decision
    score: float                      # Highest score across all layers
    attack_category: AttackCategory
    reason: str
    latency_ms: float
    detector_results: list[DetectorResult] = []


# ─── RAG Models ───────────────────────────────────────────────────────────────

class RagDocument(BaseModel):
    """A single document chunk retrieved from a vector store."""
    doc_id: str
    content: str
    source: Optional[str] = None      # File name, URL, etc.


class RagScanResult(BaseModel):
    """Result of scanning a list of RAG-retrieved documents."""
    poisoned_count: int
    clean_count: int
    results: list[dict]               # Per-document: doc_id, decision, reason


# ─── Audit Models ─────────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    """A record stored in the audit log for every scan."""
    id: Optional[int] = None
    request_id: Optional[str]
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    scan_type: str                    # "input", "output", or "rag"
    decision: Decision
    attack_category: AttackCategory
    score: float
    reason: str
    latency_ms: float
    text_snippet: str                 # First 120 chars (never full prompt for privacy)


# ─── Red-Team Models ──────────────────────────────────────────────────────────

class AttackVector(BaseModel):
    """A single red-team attack test case."""
    id: str
    category: AttackCategory
    prompt: str
    description: str
    expected_decision: Decision = Decision.BLOCK


class RedTeamResult(BaseModel):
    """Outcome of running one attack through the firewall."""
    attack: AttackVector
    actual_decision: Decision
    score: float
    passed: bool                      # True if actual_decision == expected_decision
    reason: str
