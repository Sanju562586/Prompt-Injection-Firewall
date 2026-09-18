"""
PII Detector — used by the output scanner.
Wraps Microsoft Presidio to detect personal information in LLM responses.
Catches: emails, phone numbers, credit cards, SSNs, names, locations, etc.
"""

from __future__ import annotations
from functools import lru_cache
from firewall.models import AttackCategory, DetectorLayer, DetectorResult


@lru_cache(maxsize=1)
def _load_analyzer():
    """Load the Presidio AnalyzerEngine once and cache it."""
    from presidio_analyzer import AnalyzerEngine
    return AnalyzerEngine()


def detect(text: str) -> DetectorResult:
    """
    Scan `text` for PII using Presidio.
    Returns triggered=True if any PII entity is found.
    """
    analyzer = _load_analyzer()

    try:
        results = analyzer.analyze(text=text, language="en")

        if results:
            entity_types = list({r.entity_type for r in results})
            top_score    = max(r.score for r in results)
            snippet      = ", ".join(entity_types[:5])

            return DetectorResult(
                layer=DetectorLayer.PII,
                triggered=True,
                score=round(top_score, 4),
                attack_category=AttackCategory.PII_EXFILTRATION,
                reason=f"PII detected in response: {snippet}",
                matched=snippet,
            )

    except Exception as exc:
        return DetectorResult(
            layer=DetectorLayer.PII,
            triggered=False,
            score=0.0,
            reason=f"PII detector unavailable: {exc}",
        )

    return DetectorResult(
        layer=DetectorLayer.PII,
        triggered=False,
        score=0.0,
        reason="No PII detected",
    )
