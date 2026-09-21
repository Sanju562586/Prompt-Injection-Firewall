"""
Module 3 -- Risk Engine
Provides multi-factor threat risk evaluation, signal synthesis,
attack severity scaling, and risk-tier mapping.
"""

from .schemas import (
    AttackSeverity,
    ComponentContribution,
    Decision,
    RiskAssessment,
    RiskLevel,
    RiskSignals,
)
from .config import (
    DEFAULT_CONFIG,
    RiskEngineConfig,
    RiskThresholds,
    SeverityBoosts,
    SignalWeights,
)
from .calculator import calculate_composite_risk
from .engine import (
    DEFAULT_RISK_ENGINE,
    RiskEngine,
    calculate_risk,
)

__all__ = [
    "AttackSeverity",
    "ComponentContribution",
    "Decision",
    "RiskAssessment",
    "RiskLevel",
    "RiskSignals",
    "DEFAULT_CONFIG",
    "RiskEngineConfig",
    "RiskThresholds",
    "SeverityBoosts",
    "SignalWeights",
    "calculate_composite_risk",
    "DEFAULT_RISK_ENGINE",
    "RiskEngine",
    "calculate_risk",
]
