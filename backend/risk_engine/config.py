"""
Module 3 -- Risk Engine: Configuration and Weights
Configures signal weights, severity scaling, correlation bonuses, and threshold boundaries.
"""

from __future__ import annotations
from typing import Dict
from pydantic import BaseModel, Field

from .schemas import AttackSeverity, RiskLevel


class SignalWeights(BaseModel):
    """
    Normalized weights for multi-factor signal synthesis.
    Ensures no single signal (including the ML classifier) monopolizes the decision.
    """
    ml: float = Field(0.30, ge=0.0, le=1.0, description="Weight for ML injection confidence")
    rule: float = Field(0.30, ge=0.0, le=1.0, description="Weight for heuristic/regex rule signals")
    document: float = Field(0.25, ge=0.0, le=1.0, description="Weight for RAG document poisoning risk")
    context: float = Field(0.10, ge=0.0, le=1.0, description="Weight for conversational context anomaly")
    output: float = Field(0.05, ge=0.0, le=1.0, description="Weight for output exfiltration or PII exposure")


class RiskThresholds(BaseModel):
    """
    Explicit threshold boundaries requested:
    0.00 ----- 0.30 ----- 0.60 ----- 0.80 ----- 1.00
          LOW         MEDIUM        HIGH       CRITICAL
    """
    low_upper: float = Field(0.30, ge=0.0, le=1.0)
    medium_upper: float = Field(0.60, ge=0.0, le=1.0)
    high_upper: float = Field(0.80, ge=0.0, le=1.0)
    critical_min: float = Field(0.80, ge=0.0, le=1.0)


class SeverityBoosts(BaseModel):
    """
    Score adjustments applied based on attack severity assessment.
    """
    boosts: Dict[AttackSeverity, float] = Field(
        default_factory=lambda: {
            AttackSeverity.NONE: 0.00,
            AttackSeverity.LOW: 0.02,
            AttackSeverity.MEDIUM: 0.05,
            AttackSeverity.HIGH: 0.10,
            AttackSeverity.CRITICAL: 0.15,
        }
    )


class CorrelationConfig(BaseModel):
    """
    Multi-signal agreement boost when independent layers corroborate an attack.
    """
    min_signal_threshold: float = Field(0.50, description="Minimum score to consider layer actively triggered")
    boost_per_corroborating_layer: float = Field(0.04, description="Boost per active layer beyond the first")
    max_boost: float = Field(0.12, description="Upper ceiling on correlation boost")


class RiskEngineConfig(BaseModel):
    """Master configuration for Risk Engine."""
    weights: SignalWeights = Field(default_factory=SignalWeights)
    thresholds: RiskThresholds = Field(default_factory=RiskThresholds)
    severity_boosts: SeverityBoosts = Field(default_factory=SeverityBoosts)
    correlation: CorrelationConfig = Field(default_factory=CorrelationConfig)


DEFAULT_CONFIG = RiskEngineConfig()
