"""
Module 3 -- Risk Engine: High-Level Risk Engine Service
Coordinates multi-layer threat signal assessment, applies configurable policies,
generates actionable verdicts, and provides forensic explainability.
"""

from __future__ import annotations
import time
from typing import Dict, List, Optional

from .calculator import calculate_composite_risk
from .config import DEFAULT_CONFIG, RiskEngineConfig
from .schemas import (
    AttackSeverity,
    Decision,
    RiskAssessment,
    RiskLevel,
    RiskSignals,
)


class RiskEngine:
    """
    Dedicated Multi-Factor Threat & Risk Engine.
    Ensures that the ML classifier does NOT unilaterally decide verdicts,
    synthesizing rule signals, ML confidence, context anomalies,
    RAG document poisoning, and output exfiltration risks.
    """

    def __init__(self, config: Optional[RiskEngineConfig] = None):
        self.config = config or DEFAULT_CONFIG

    def assess(self, signals: RiskSignals) -> RiskAssessment:
        """
        Evaluate full multi-layer RiskSignals and return a forensic RiskAssessment.
        """
        start = time.perf_counter()

        (
            overall_risk,
            risk_level,
            decision,
            breakdown,
            correlation_boost,
            severity_boost,
            primary_factor,
        ) = calculate_composite_risk(signals, self.config)

        # Generate Human-Readable Forensic Explanation
        explanation = self._build_explanation(
            overall_risk=overall_risk,
            risk_level=risk_level,
            decision=decision,
            signals=signals,
            primary_factor=primary_factor,
            correlation_boost=correlation_boost,
            severity_boost=severity_boost,
        )

        latency_ms = round((time.perf_counter() - start) * 1000, 3)

        return RiskAssessment(
            overall_risk=overall_risk,
            risk_level=risk_level,
            decision=decision,
            attack_severity=signals.attack_severity,
            component_breakdown=breakdown,
            correlation_boost_applied=correlation_boost,
            severity_boost_applied=severity_boost,
            primary_threat_factor=primary_factor,
            explanation=explanation,
            latency_ms=latency_ms,
        )

    def assess_components(
        self,
        rule_score: float = 0.0,
        ml_score: float = 0.0,
        pii_score: float = 0.0,
        document_risk: float = 0.0,
        context_score: float = 0.0,
        output_risk: float = 0.0,
        attack_severity: AttackSeverity | str = AttackSeverity.NONE,
        metadata: Optional[Dict] = None,
    ) -> RiskAssessment:
        """
        Convenience method to evaluate raw component scores directly.
        """
        if isinstance(attack_severity, str):
            try:
                severity_enum = AttackSeverity(attack_severity.upper())
            except ValueError:
                severity_enum = AttackSeverity.NONE
        else:
            severity_enum = attack_severity

        effective_output_risk = max(output_risk, pii_score)

        signals = RiskSignals(
            rule_score=rule_score,
            ml_score=ml_score,
            pii_score=pii_score,
            document_risk=document_risk,
            context_score=context_score,
            output_risk=effective_output_risk,
            attack_severity=severity_enum,
            metadata=metadata or {},
        )
        return self.assess(signals)

    def _build_explanation(
        self,
        overall_risk: float,
        risk_level: RiskLevel,
        decision: Decision,
        signals: RiskSignals,
        primary_factor: str,
        correlation_boost: float,
        severity_boost: float,
    ) -> str:
        """Construct detailed explainability justification for SOC teams."""
        factors: List[str] = []

        if signals.ml_score >= 0.50:
            factors.append(f"ML Classifier ({signals.ml_score:.2f})")
        if signals.rule_score >= 0.50:
            factors.append(f"Rule Heuristics ({signals.rule_score:.2f})")
        if signals.document_risk >= 0.50:
            factors.append(f"RAG Document Poisoning ({signals.document_risk:.2f})")
        if signals.context_score >= 0.50:
            factors.append(f"Context Anomaly ({signals.context_score:.2f})")
        if signals.output_risk >= 0.50:
            factors.append(f"Output/PII Risk ({signals.output_risk:.2f})")

        factor_summary = ", ".join(factors) if factors else "No high-risk layers detected"

        details = []
        if correlation_boost > 0:
            details.append(f"multi-signal correlation boost (+{correlation_boost:.2f})")
        if severity_boost > 0:
            details.append(f"severity adjustment '{signals.attack_severity.value}' (+{severity_boost:.2f})")

        adj_text = f" with {', '.join(details)}" if details else ""

        return (
            f"Overall risk {overall_risk:.2f} ({risk_level.value}) resulted in {decision.value}. "
            f"Primary threat driver: {primary_factor}. "
            f"Elevated signals: [{factor_summary}]{adj_text}."
        )


# Global default instance
DEFAULT_RISK_ENGINE = RiskEngine()


def calculate_risk(
    rule_score: float = 0.0,
    ml_score: float = 0.0,
    pii_score: float = 0.0,
    document_risk: float = 0.0,
    context_score: float = 0.0,
    output_risk: float = 0.0,
    attack_severity: AttackSeverity | str = AttackSeverity.NONE,
    config: Optional[RiskEngineConfig] = None,
) -> RiskAssessment:
    """
    Standard top-level functional entrypoint matching user requirements.
    """
    engine = RiskEngine(config=config) if config else DEFAULT_RISK_ENGINE
    return engine.assess_components(
        rule_score=rule_score,
        ml_score=ml_score,
        pii_score=pii_score,
        document_risk=document_risk,
        context_score=context_score,
        output_risk=output_risk,
        attack_severity=attack_severity,
    )
