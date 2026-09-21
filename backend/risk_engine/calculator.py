"""
Module 3 -- Risk Engine: Mathematical Calculation Engine
Calculates weighted composite risk, applies correlation boosts,
factors in attack severity, and maps to defined risk tiers.
"""

from __future__ import annotations
from typing import Dict, Tuple

from .config import DEFAULT_CONFIG, RiskEngineConfig
from .schemas import (
    AttackSeverity,
    ComponentContribution,
    Decision,
    RiskLevel,
    RiskSignals,
)


def calculate_composite_risk(
    signals: RiskSignals,
    config: RiskEngineConfig | None = None,
) -> Tuple[float, RiskLevel, Decision, Dict[str, ComponentContribution], float, float, str]:
    """
    Executes the multi-factor risk formula:
        Risk = (w_ml * ML_confidence)
             + (w_rule * rule_signals)
             + (w_ctx * context_signals)
             + (w_doc * document_risk)
             + (w_out * output_risk)
             + severity_adjustment
             + correlation_boost

    Returns:
        (overall_risk, risk_level, decision, breakdown, correlation_boost, severity_boost, primary_factor)
    """
    cfg = config or DEFAULT_CONFIG
    w = cfg.weights

    # 1. Component Weighted Scores
    contributions = {
        "ml_classifier": (signals.ml_score, w.ml, signals.ml_score * w.ml),
        "rule_signals": (signals.rule_score, w.rule, signals.rule_score * w.rule),
        "context_signals": (signals.context_score, w.context, signals.context_score * w.context),
        "document_risk": (signals.document_risk, w.document, signals.document_risk * w.document),
        "output_risk": (signals.output_risk, w.output, signals.output_risk * w.output),
    }

    base_risk = sum(item[2] for item in contributions.values())

    # 2. Multi-Signal Corroboration Boost
    # When multiple independent signals simultaneously flag high confidence:
    active_signals = [
        name for name, (raw, _, _) in contributions.items()
        if raw >= cfg.correlation.min_signal_threshold
    ]
    num_active = len(active_signals)
    if num_active >= 2:
        raw_boost = (num_active - 1) * cfg.correlation.boost_per_corroborating_layer
        correlation_boost = min(raw_boost, cfg.correlation.max_boost)
    else:
        correlation_boost = 0.0

    # 3. Severity Scaling
    sev_boost = cfg.severity_boosts.boosts.get(signals.attack_severity, 0.0)

    # 4. Total Composite Risk (bounded to [0.0, 1.0])
    raw_total = base_risk + correlation_boost + sev_boost
    overall_risk = round(max(0.0, min(1.0, raw_total)), 4)

    # 5. Component Breakdown Formatting
    breakdown: Dict[str, ComponentContribution] = {}
    for name, (raw, weight, weighted) in contributions.items():
        pct = round((weighted / base_risk * 100), 2) if base_risk > 0 else 0.0
        breakdown[name] = ComponentContribution(
            raw_score=round(raw, 4),
            weight=round(weight, 4),
            weighted_score=round(weighted, 4),
            percentage_of_risk=pct,
        )

    # 6. Determine Primary Factor
    primary_factor = max(
        contributions.keys(),
        key=lambda k: contributions[k][2],
    )

    # 7. Map to Specified Risk Tiers:
    # 0.00 ----- 0.30 ----- 0.60 ----- 0.80 ----- 1.00
    #       LOW         MEDIUM        HIGH       CRITICAL
    t = cfg.thresholds
    if overall_risk >= t.critical_min:
        risk_level = RiskLevel.CRITICAL
        decision = Decision.BLOCK
    elif overall_risk >= t.medium_upper:
        risk_level = RiskLevel.HIGH
        decision = Decision.BLOCK
    elif overall_risk >= t.low_upper:
        risk_level = RiskLevel.MEDIUM
        decision = Decision.FLAG
    else:
        risk_level = RiskLevel.LOW
        decision = Decision.ALLOW

    return (
        overall_risk,
        risk_level,
        decision,
        breakdown,
        round(correlation_boost, 4),
        round(sev_boost, 4),
        primary_factor,
    )
