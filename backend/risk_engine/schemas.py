"""
Module 3 -- Risk Engine: Schemas and Data Models
Defines risk levels, decision verdicts, signal inputs, and risk assessment reports.
"""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk tiers mapped to defined score ranges."""
    LOW = "LOW"            # 0.00 <= score < 0.30
    MEDIUM = "MEDIUM"      # 0.30 <= score < 0.60
    HIGH = "HIGH"          # 0.60 <= score < 0.80
    CRITICAL = "CRITICAL"  # 0.80 <= score <= 1.00


class Decision(str, Enum):
    """Enforcement decision based on overall calculated risk."""
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class AttackSeverity(str, Enum):
    """Categorical severity rating of identified attack vector."""
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskSignals(BaseModel):
    """
    Multi-dimensional threat signals gathered across firewall security layers.
    Does NOT let the ML classifier decide everything on its own.
    """
    ml_score: float = Field(0.0, ge=0.0, le=1.0, description="DeBERTa / ML classifier confidence (0.0 - 1.0)")
    rule_score: float = Field(0.0, ge=0.0, le=1.0, description="Heuristic and regex pattern rule signal (0.0 - 1.0)")
    context_score: float = Field(0.0, ge=0.0, le=1.0, description="Contextual distortion or conversational shift signal (0.0 - 1.0)")
    document_risk: float = Field(0.0, ge=0.0, le=1.0, description="RAG retrieved document poisoning risk (0.0 - 1.0)")
    output_risk: float = Field(0.0, ge=0.0, le=1.0, description="Output exfiltration risk or sensitive PII score (0.0 - 1.0)")
    pii_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Explicit alias for output PII score")
    attack_severity: AttackSeverity = Field(default=AttackSeverity.NONE, description="Inferred or declared attack severity")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary audit or caller metadata")

    def model_post_init(self, __context: Any) -> None:
        """Harmonize pii_score and output_risk aliases."""
        if self.pii_score is not None and self.output_risk == 0.0:
            self.output_risk = self.pii_score
        elif self.output_risk > 0.0 and self.pii_score is None:
            self.pii_score = self.output_risk


class ComponentContribution(BaseModel):
    """Forensic breakdown of an individual signal's weighted contribution to overall risk."""
    raw_score: float
    weight: float
    weighted_score: float
    percentage_of_risk: float


class RiskAssessment(BaseModel):
    """
    Comprehensive risk calculation outcome with explainability breakdown.
    """
    overall_risk: float = Field(..., ge=0.0, le=1.0, description="Composite risk score from 0.00 to 1.00")
    risk_level: RiskLevel = Field(..., description="Mapped tier: LOW, MEDIUM, HIGH, or CRITICAL")
    decision: Decision = Field(..., description="Actionable enforcement verdict: ALLOW, FLAG, or BLOCK")
    attack_severity: AttackSeverity = Field(..., description="Severity level taken into account")
    component_breakdown: Dict[str, ComponentContribution] = Field(
        default_factory=dict,
        description="Detailed contribution breakdown per security signal",
    )
    correlation_boost_applied: float = Field(0.0, description="Additional risk score from multi-layer corroboration")
    severity_boost_applied: float = Field(0.0, description="Additional risk score from attack severity scaling")
    primary_threat_factor: str = Field(..., description="Dominant signal driving the overall risk")
    explanation: str = Field(..., description="Human-readable forensic justification")
    latency_ms: float = Field(0.0, description="Calculation latency in milliseconds")
