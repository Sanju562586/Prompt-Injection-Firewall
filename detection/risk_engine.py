"""
Detection Module — Risk Engine
Multi-factor risk assessment engine that combines signals from multiple detectors,
applies weights and confidence thresholds, and computes final RiskLevel and Decision.
"""

from __future__ import annotations
from typing import List, Tuple
from audit.models import AttackCategory, Decision, DetectorLayer, DetectorResult, RiskLevel
from config import CONFIG


class RiskEngine:
    """Evaluates composite threat scores across multiple detection layers."""

    def __init__(
        self,
        block_threshold: float = 0.80,
        warn_threshold: float = 0.55,
        weights: dict | None = None,
    ):
        cfg = CONFIG.get("detection", {}).get("risk_engine", {})
        self.block_threshold = block_threshold
        self.warn_threshold = warn_threshold
        self.weights = weights or cfg.get("weights", {
            "rules": 0.45,
            "semantic": 0.35,
            "classifier": 0.40,
            "pii": 0.40,
        })
        self.thresholds = cfg.get("thresholds", {
            "critical": 0.85,
            "high": 0.75,
            "medium": 0.50,
            "low": 0.25,
        })

    def evaluate(self, results: List[DetectorResult]) -> Tuple[Decision, float, AttackCategory, RiskLevel, str]:
        """
        Synthesize detector results into a final risk decision.
        Returns: (Decision, composite_score, AttackCategory, RiskLevel, reason)
        """
        triggered_results = [r for r in results if r.triggered]

        if not triggered_results:
            # Check maximum un-triggered score as baseline noise
            max_score = max((r.score for r in results), default=0.0)
            return (
                Decision.ALLOW,
                round(max_score, 4),
                AttackCategory.UNKNOWN,
                RiskLevel.LOW,
                "No threat signatures or anomalous patterns detected",
            )

        # Primary contributor is the highest confidence triggered detector
        primary = max(triggered_results, key=lambda r: r.score)

        # Multi-factor score calculation
        # If multiple detectors triggered simultaneously, apply multi-layer correlation boost
        base_score = primary.score
        num_triggered = len(triggered_results)

        if num_triggered >= 2:
            # Boost score if multiple independent layers corroborate the threat
            boost = 0.05 * (num_triggered - 1)
            composite_score = min(1.0, base_score + boost)
        else:
            composite_score = base_score

        # Determine RiskLevel
        if composite_score >= self.thresholds.get("critical", 0.85):
            risk_level = RiskLevel.CRITICAL
        elif composite_score >= self.thresholds.get("high", 0.75):
            risk_level = RiskLevel.HIGH
        elif composite_score >= self.thresholds.get("medium", 0.50):
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        # Determine final decision
        if composite_score >= self.block_threshold:
            decision = Decision.BLOCK
        elif composite_score >= self.warn_threshold:
            decision = Decision.WARN
        else:
            decision = Decision.ALLOW

        reason = primary.reason
        if num_triggered > 1:
            layer_names = ", ".join(r.layer.value for r in triggered_results)
            reason = f"Multi-layer detection ({layer_names}): {primary.reason}"

        return (
            decision,
            round(composite_score, 4),
            primary.attack_category,
            risk_level,
            reason,
        )


# Global default risk engine instance
DEFAULT_RISK_ENGINE = RiskEngine()
