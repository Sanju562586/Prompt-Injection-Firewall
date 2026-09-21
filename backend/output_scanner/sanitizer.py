"""
Output Sanitizer and Redaction Engine.
Performs clean, non-overlapping redaction of sensitive data, PII, and credentials in LLM outputs.
"""

from typing import List, Tuple
from backend.output_scanner.schemas import Violation


class OutputSanitizer:
    """Sanitizes text by replacing detected sensitive spans with redaction tokens."""

    @staticmethod
    def sanitize(text: str, violations: List[Violation]) -> str:
        """Applies replacements in reverse order of start position to preserve indexing."""
        if not text or not violations:
            return text

        # Filter violations with replacement defined and valid positions
        replaceable: List[Tuple[int, int, str]] = []
        for v in violations:
            if v.replacement and v.start_pos is not None and v.end_pos is not None:
                replaceable.append((v.start_pos, v.end_pos, v.replacement))

        if not replaceable:
            return text

        # Sort by start position ascending
        replaceable.sort(key=lambda x: x[0])

        # Resolve overlapping spans: merge or keep the widest
        merged: List[Tuple[int, int, str]] = []
        for start, end, repl in replaceable:
            if not merged:
                merged.append((start, end, repl))
            else:
                prev_start, prev_end, prev_repl = merged[-1]
                if start < prev_end:
                    # Overlap detected, keep the wider span
                    new_end = max(prev_end, end)
                    merged[-1] = (prev_start, new_end, prev_repl)
                else:
                    merged.append((start, end, repl))

        # Apply replacements from back to front so indices remain valid
        result = list(text)
        for start, end, repl in reversed(merged):
            result[start:end] = list(repl)

        return "".join(result)
