"""
Unit and Integration Tests for Module 3 -- Risk Engine
"""

import pytest
from backend.risk_engine import (
    AttackSeverity,
    Decision,
    RiskEngine,
    RiskLevel,
    RiskSignals,
    calculate_risk,
)


def test_user_exact_specification_scenario():
    """
    Validates user's explicit requirement:
        Rule score       = 0.8
        ML score         = 0.91
        PII score        = 0.0
        Document risk    = 0.7
        Attack severity  = HIGH
    Ensures that multi-signal corroboration pushes this into CRITICAL (>= 0.80).
    """
    assessment = calculate_risk(
        rule_score=0.8,
        ml_score=0.91,
        pii_score=0.0,
        document_risk=0.7,
        attack_severity="HIGH",
    )

    assert assessment.overall_risk >= 0.80, f"Expected CRITICAL (>= 0.80), got {assessment.overall_risk}"
    assert assessment.risk_level == RiskLevel.CRITICAL
    assert assessment.decision == Decision.BLOCK
    assert assessment.correlation_boost_applied > 0.0
    assert assessment.severity_boost_applied > 0.0
    assert "ml_classifier" in assessment.component_breakdown
    assert "rule_signals" in assessment.component_breakdown
    assert "document_risk" in assessment.component_breakdown


def test_threshold_tier_mappings():
    """
    Validates explicit tier boundary mapping:
        0.00 ----- 0.30 ----- 0.60 ----- 0.80 ----- 1.00
              LOW         MEDIUM        HIGH       CRITICAL
    """
    engine = RiskEngine()

    # Low Tier (< 0.30)
    low_res = engine.assess(RiskSignals(ml_score=0.20, rule_score=0.10))
    assert 0.00 <= low_res.overall_risk < 0.30
    assert low_res.risk_level == RiskLevel.LOW
    assert low_res.decision == Decision.ALLOW

    # Medium Tier (0.30 <= score < 0.60)
    med_res = engine.assess(RiskSignals(ml_score=0.60, rule_score=0.50))
    assert 0.30 <= med_res.overall_risk < 0.60
    assert med_res.risk_level == RiskLevel.MEDIUM
    assert med_res.decision == Decision.FLAG

    # High Tier (0.60 <= score < 0.80)
    high_res = engine.assess(RiskSignals(ml_score=0.80, rule_score=0.75, document_risk=0.50))
    assert 0.60 <= high_res.overall_risk < 0.80
    assert high_res.risk_level == RiskLevel.HIGH
    assert high_res.decision == Decision.BLOCK

    # Critical Tier (0.80 <= score <= 1.00)
    crit_res = engine.assess(RiskSignals(ml_score=0.91, rule_score=0.80, document_risk=0.70, attack_severity=AttackSeverity.HIGH))
    assert crit_res.overall_risk >= 0.80
    assert crit_res.risk_level == RiskLevel.CRITICAL
    assert crit_res.decision == Decision.BLOCK


def test_ml_classifier_does_not_unilaterally_decide_everything():
    """
    Confirms requirement: 'Don't make the ML classifier directly decide everything'.
    High ML score alone with all other signals clean should not reach BLOCK/CRITICAL.
    """
    res = calculate_risk(
        ml_score=0.82,
        rule_score=0.0,
        context_score=0.0,
        document_risk=0.0,
        output_risk=0.0,
        attack_severity=AttackSeverity.NONE,
    )
    # ML alone weighted at 0.30 yields 0.246 -> mapped to LOW
    assert res.overall_risk < 0.30
    assert res.risk_level == RiskLevel.LOW
    assert res.decision == Decision.ALLOW


def test_document_and_rule_signals_dominate_without_ml():
    """
    Validates that document poisoning and rule indicators can independently trigger BLOCK
    even if ML confidence is low or zero.
    """
    res = calculate_risk(
        ml_score=0.0,
        rule_score=0.90,
        document_risk=0.85,
        attack_severity="HIGH",
    )
    assert res.overall_risk >= 0.60
    assert res.decision == Decision.BLOCK
    assert res.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_clean_input_prompt_produces_zero_risk():
    """Verifies that completely benign inputs evaluate to 0.0 risk and ALLOW."""
    res = calculate_risk()
    assert res.overall_risk == 0.0
    assert res.risk_level == RiskLevel.LOW
    assert res.decision == Decision.ALLOW
    assert res.correlation_boost_applied == 0.0


def test_component_breakdown_integrity():
    """Verifies forensic explanation and breakdown contains all 5 signal channels."""
    res = calculate_risk(
        rule_score=0.5,
        ml_score=0.5,
        document_risk=0.5,
        context_score=0.5,
        output_risk=0.5,
    )
    breakdown = res.component_breakdown
    assert "ml_classifier" in breakdown
    assert "rule_signals" in breakdown
    assert "context_signals" in breakdown
    assert "document_risk" in breakdown
    assert "output_risk" in breakdown

    total_pct = sum(c.percentage_of_risk for c in breakdown.values())
    assert 99.9 <= total_pct <= 100.1
