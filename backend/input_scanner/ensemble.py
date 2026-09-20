import re
from typing import List, Set, Tuple, Optional
from .schemas import (
    Decision,
    RiskLevel,
    AttackType,
    RuleMatch,
    ScanResult
)

# Patterns that indicate legitimate research, education, or defense inquiries
BENIGN_INQUIRY_PATTERNS = [
    re.compile(r"(?i)\b(?:what\s+is|explain|describe|define|overview\s+of|history\s+of)\s+prompt\s+injection\b"),
    re.compile(r"(?i)\b(?:how\s+to\s+prevent|how\s+do\s+firewalls\s+block|defend\s+against)\b"),
    re.compile(r"(?i)\b(?:examples?\s+of\s+security\s+vulnerabilit(?:y|ies))\b"),
    re.compile(r"(?i)\b(?:difference\s+between\s+jailbreak\s+and\s+prompt\s+injection)\b"),
]


class EnsembleDecisionEngine:
    """
    Fuses Rule-Based heuristics with DeBERTa ML classifier outputs to deliver
    High Recall (catching subtle and novel injection attempts) and Balanced Precision
    (minimizing false alarms on educational, development, or benign queries).
    """

    def __init__(
        self,
        block_threshold: float = 0.70,
        flag_threshold: float = 0.40,
        ml_weight: float = 0.55,
        rule_weight: float = 0.45,
    ):
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self.ml_weight = ml_weight
        self.rule_weight = rule_weight

    def fuse(
        self,
        text: str,
        rule_score: float,
        flagged_rules: List[RuleMatch],
        rule_attack_types: Set[AttackType],
        ml_score: float,
        ml_label: str,
        sensitivity_override: Optional[float] = None,
        latency_ms: float = 0.0,
    ) -> ScanResult:
        """
        Combines rule signals and ML probabilities into a final security decision.
        """
        active_block_threshold = sensitivity_override or self.block_threshold

        # Determine if prompt is a benign educational/research query
        is_benign_inquiry = any(p.search(text) for p in BENIGN_INQUIRY_PATTERNS)
        has_critical_rule = any(r.severity == RiskLevel.CRITICAL for r in flagged_rules)

        # 1. Base Multi-Signal Fusion
        raw_combined_score = (ml_score * self.ml_weight) + (rule_score * self.rule_weight)

        # 2. High Recall Boosts:
        # If any CRITICAL rule matched, enforce high risk score immediately
        if has_critical_rule:
            combined_score = max(raw_combined_score, 0.85)
        # If ML is extremely confident of injection (>= 0.85), enforce high risk score
        elif ml_score >= 0.85:
            combined_score = max(raw_combined_score, ml_score)
        # If both Rule Engine and ML detect suspicious indicators simultaneously
        elif rule_score >= 0.40 and ml_score >= 0.40:
            combined_score = min(1.0, raw_combined_score + 0.15)
        else:
            combined_score = raw_combined_score

        # 3. Precision Calibration (False Positive Mitigation)
        # If detected as benign educational query AND no hard critical rule fired:
        if is_benign_inquiry and not has_critical_rule:
            combined_score = combined_score * 0.35

        final_risk = round(max(0.0, min(1.0, combined_score)), 4)

        # 4. Map to RiskLevel
        if final_risk >= 0.80:
            risk_level = RiskLevel.CRITICAL
        elif final_risk >= 0.60:
            risk_level = RiskLevel.HIGH
        elif final_risk >= 0.35:
            risk_level = RiskLevel.MEDIUM
        elif final_risk >= 0.15:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.SAFE

        # 5. Determine Decision (ALLOW / FLAG / BLOCK)
        if has_critical_rule or final_risk >= active_block_threshold:
            decision = Decision.BLOCK
            is_safe = False
        elif final_risk >= self.flag_threshold:
            decision = Decision.FLAG
            is_safe = False
        else:
            decision = Decision.ALLOW
            is_safe = True

        # 6. Aggregate Attack Types
        attack_types_list = list(rule_attack_types)
        if ml_score >= 0.60 and not attack_types_list:
            attack_types_list.append(AttackType.INSTRUCTION_OVERRIDE)

        # 7. Formulate Explanation
        explanation = self._build_explanation(
            decision=decision,
            risk_level=risk_level,
            final_risk=final_risk,
            flagged_rules=flagged_rules,
            ml_score=ml_score,
            is_benign_inquiry=is_benign_inquiry
        )

        return ScanResult(
            is_safe=is_safe,
            decision=decision,
            risk_score=final_risk,
            risk_level=risk_level,
            attack_types=attack_types_list,
            flagged_rules=flagged_rules,
            ml_score=ml_score,
            ml_label=ml_label,
            sanitized_text=None,
            latency_ms=round(latency_ms, 2),
            explanation=explanation
        )

    def _build_explanation(
        self,
        decision: Decision,
        risk_level: RiskLevel,
        final_risk: float,
        flagged_rules: List[RuleMatch],
        ml_score: float,
        is_benign_inquiry: bool
    ) -> str:
        if decision == Decision.BLOCK:
            reasons = [f"Rule '{r.name}' triggered" for r in flagged_rules[:2]]
            if ml_score >= 0.65:
                reasons.append(f"DeBERTa model detected injection pattern with {int(ml_score * 100)}% probability")
            reason_str = "; ".join(reasons) if reasons else "High injection risk detected by security ensemble"
            return f"Blocked: {reason_str} (Risk Score: {final_risk})."

        elif decision == Decision.FLAG:
            reasons = [r.name for r in flagged_rules]
            if ml_score >= 0.40:
                reasons.append(f"ML probability {int(ml_score * 100)}%")
            return f"Flagged for audit: Moderate injection risk detected ({', '.join(reasons)})."

        else:
            if is_benign_inquiry:
                return "Allowed: Evaluated as benign educational or security inquiry."
            return "Allowed: Input prompt passed all security filters."
