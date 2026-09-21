"""
Grounding and Hallucination Checker.
Compares the model response against provided context documents to detect ungrounded claims or factual hallucinations.
"""

import re
from typing import List, Optional
from backend.output_scanner.schemas import Violation, ViolationType, Severity


class GroundingChecker:
    """Verifies that facts, figures, and key assertions in the output are grounded in retrieved context."""

    def __init__(self, hallucination_threshold: float = 0.5):
        self.hallucination_threshold = hallucination_threshold

    def check(self, response_text: str, context_documents: Optional[List[str]] = None) -> List[Violation]:
        """Checks if response contains ungrounded factual assertions relative to context."""
        violations: List[Violation] = []
        if not response_text or not context_documents:
            return violations

        combined_context = " ".join(context_documents).lower()
        if not combined_context.strip():
            return violations

        # 1. Check numbers/metrics (e.g. monetary figures, percentages, dates)
        number_pattern = re.compile(r"\b(?:\$\d+(?:,\d{3})*(?:\.\d+)?|\d+%(?:|\.\d+%)|\d{4}-\d{2}-\d{2})\b")
        response_numbers = number_pattern.findall(response_text)
        
        ungrounded_numbers = []
        for num in response_numbers:
            if num.lower() not in combined_context:
                ungrounded_numbers.append(num)

        if ungrounded_numbers:
            violations.append(
                Violation(
                    violation_type=ViolationType.HALLUCINATION,
                    severity=Severity.MEDIUM if len(ungrounded_numbers) == 1 else Severity.HIGH,
                    description=f"Output contains ungrounded numerical metrics or dates not present in retrieved context: {', '.join(ungrounded_numbers[:3])}",
                    matched_text=", ".join(ungrounded_numbers[:3]),
                    replacement=None,
                    metadata={"ungrounded_figures": ungrounded_numbers}
                )
            )

        # 2. Vocabulary & Entity overlap ratio
        def tokenize(s: str) -> set:
            words = re.findall(r"\b[a-zA-Z]{4,}\b", s.lower())
            stop_words = {
                "this", "that", "there", "these", "those", "have", "with",
                "from", "about", "which", "their", "would", "could", "should",
                "other", "after", "first", "also", "where", "being", "under"
            }
            return {w for w in words if w not in stop_words}

        resp_tokens = tokenize(response_text)
        ctx_tokens = tokenize(combined_context)

        if len(resp_tokens) >= 5:
            overlap = len(resp_tokens.intersection(ctx_tokens))
            overlap_ratio = overlap / len(resp_tokens)
            # If less than 20% of substantial response words appear in context, flag hallucination
            if overlap_ratio < 0.20:
                violations.append(
                    Violation(
                        violation_type=ViolationType.HALLUCINATION,
                        severity=Severity.HIGH,
                        description=f"Output has very low grounding overlap with source documents (overlap ratio: {overlap_ratio:.2f})",
                        matched_text=None,
                        replacement=None,
                        metadata={"overlap_ratio": overlap_ratio}
                    )
                )

        return violations
