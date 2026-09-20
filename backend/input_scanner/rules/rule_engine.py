from typing import List, Tuple, Set
from ..schemas import AttackType, RiskLevel, RuleMatch
from .patterns import INJECTION_PATTERNS
from .decoders import ObfuscationDecoder


class RuleEngine:
    """
    Evaluates text against comprehensive regex patterns, heuristics, and decoded
    obfuscation variants.
    """

    def __init__(self, patterns: List[dict] = None):
        self.patterns = patterns or INJECTION_PATTERNS

    def evaluate(self, text: str) -> Tuple[float, List[RuleMatch], Set[AttackType]]:
        """
        Scans raw text along with normalized/decoded variations.
        Returns:
            - rule_risk_score (float): 0.0 to 1.0
            - flagged_rules (List[RuleMatch])
            - attack_types (Set[AttackType])
        """
        if not text or not text.strip():
            return 0.0, [], set()

        # Generate variations (zero-width removed, base64 unpacked, leetspeak normalized, etc.)
        variants = ObfuscationDecoder.generate_candidate_variants(text)
        
        flagged_rules: List[RuleMatch] = []
        attack_types: Set[AttackType] = set()
        seen_rule_ids: Set[str] = set()
        max_confidence: float = 0.0

        for variant_label, candidate_text in variants:
            is_obfuscated_variant = variant_label != "raw"

            for rule in self.patterns:
                rule_id = rule["id"]
                match = rule["pattern"].search(candidate_text)
                if match:
                    # If matched on decoded obfuscated text, tag attack type with OBFUSCATION as well
                    attack_type = rule["attack_type"]
                    attack_types.add(attack_type)
                    if is_obfuscated_variant:
                        attack_types.add(AttackType.OBFUSCATION)

                    confidence = rule["confidence"]
                    # If detected inside encoded form, boost confidence for deliberate evasion
                    if is_obfuscated_variant and confidence < 0.95:
                        confidence = min(1.0, confidence + 0.1)

                    if rule_id not in seen_rule_ids:
                        seen_rule_ids.add(rule_id)
                        matched_snippet = match.group(0)
                        flagged_rules.append(
                            RuleMatch(
                                rule_id=rule_id,
                                name=f"{rule['name']} ({variant_label})" if is_obfuscated_variant else rule["name"],
                                attack_type=attack_type,
                                severity=rule["severity"],
                                matched_substring=matched_snippet[:100],
                                confidence=confidence
                            )
                        )
                        if confidence > max_confidence:
                            max_confidence = confidence

        # Calculate composite risk score from matched rules
        if not flagged_rules:
            return 0.0, [], set()

        # Weighting: Highest confidence match + cumulative factor for multiple distinct rules
        cumulative_bonus = min(0.15, 0.05 * (len(flagged_rules) - 1))
        composite_score = min(1.0, max_confidence + cumulative_bonus)

        return composite_score, flagged_rules, attack_types
