"""
Scanners Module — PII Scanner
Detects and redacts Personally Identifiable Information (PII) using Presidio and regex heuristics.
Prevents accidental leakage of emails, phone numbers, SSNs, credit cards, and API keys.
"""

from __future__ import annotations
import re
from functools import lru_cache
from typing import List, Optional, Set, Tuple
from audit.models import AttackCategory, DetectorLayer, DetectorResult
from config import CONFIG

# Configurable sensitivity settings
PII_CFG = CONFIG.get("scanners", {}).get("pii", {})
SENSITIVE_ENTITIES: Set[str] = set(PII_CFG.get("sensitive_entities", [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "US_SSN",
    "CREDIT_CARD",
    "CRYPTO",
    "IBAN_CODE",
    "IP_ADDRESS",
    "API_KEY",
]))
IGNORE_GENERAL_LOCATIONS: bool = PII_CFG.get("ignore_general_locations", True)

# Regex heuristics for high-risk PII patterns
REGEX_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("EMAIL_ADDRESS", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")),
    ("PHONE_NUMBER",  re.compile(r"\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("US_SSN",        re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT_CARD",   re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("API_KEY",       re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b")),
]


@lru_cache(maxsize=1)
def _load_presidio_analyzer():
    """Load Presidio AnalyzerEngine once and cache in memory."""
    from presidio_analyzer import AnalyzerEngine
    return AnalyzerEngine()


@lru_cache(maxsize=1)
def _load_presidio_anonymizer():
    """Load Presidio AnonymizerEngine once and cache in memory."""
    from presidio_anonymizer import AnonymizerEngine
    return AnonymizerEngine()


def _regex_scan(text: str) -> List[Tuple[str, str, float]]:
    """Fast regex-based PII fallback finder."""
    matches = []
    for entity_type, pattern in REGEX_PATTERNS:
        for m in pattern.finditer(text):
            matches.append((entity_type, m.group(0), 0.95))
    return matches


def scan_pii(text: str, custom_threshold: float = 0.60) -> DetectorResult:
    """
    Inspect text for sensitive personal data.
    Distinguishes high-risk PII (SSN, credit card, phone, email) from non-sensitive geographic locations.
    """
    detected_entities: List[str] = []
    top_score = 0.0

    # 1. First run fast regex scan for high-risk PII
    regex_matches = _regex_scan(text)
    for entity_type, snippet, score in regex_matches:
        if entity_type in SENSITIVE_ENTITIES:
            detected_entities.append(entity_type)
            top_score = max(top_score, score)

    # 2. Run Presidio AnalyzerEngine if available
    try:
        analyzer = _load_presidio_analyzer()
        presidio_results = analyzer.analyze(text=text, language="en")
        for r in presidio_results:
            entity_type = r.entity_type

            # Skip general locations if configured (prevents blocking "The capital of France is Paris.")
            if IGNORE_GENERAL_LOCATIONS and entity_type in ("LOCATION", "GPE"):
                continue

            # Only consider entities in our sensitive set or with high confidence
            if entity_type in SENSITIVE_ENTITIES or r.score >= 0.85:
                detected_entities.append(entity_type)
                top_score = max(top_score, float(r.score))
    except Exception:
        # Presidio not installed or failed — regex findings still stand
        pass

    if detected_entities:
        unique_entities = sorted(list(set(detected_entities)))
        snippet = ", ".join(unique_entities[:5])
        triggered = top_score >= custom_threshold
        return DetectorResult(
            layer=DetectorLayer.PII,
            triggered=triggered,
            score=round(top_score, 4),
            attack_category=AttackCategory.PII_EXFILTRATION,
            reason=f"PII detected: {snippet}",
            matched=snippet,
            details={"entities": unique_entities, "top_score": top_score},
        )

    return DetectorResult(
        layer=DetectorLayer.PII,
        triggered=False,
        score=0.0,
        attack_category=AttackCategory.UNKNOWN,
        reason="No sensitive PII detected",
    )


def mask_pii(text: str) -> str:
    """
    Mask or redact detected PII in text.
    """
    # Try Presidio Anonymizer first
    try:
        analyzer = _load_presidio_analyzer()
        anonymizer = _load_presidio_anonymizer()
        results = analyzer.analyze(text=text, language="en")
        # Filter out locations if configured
        filtered = [r for r in results if not (IGNORE_GENERAL_LOCATIONS and r.entity_type in ("LOCATION", "GPE"))]
        if filtered:
            anonymized = anonymizer.anonymize(text=text, analyzer_results=filtered)
            return anonymized.text
    except Exception:
        pass

    # Fallback to regex masking
    masked = text
    for entity_type, pattern in REGEX_PATTERNS:
        masked = pattern.sub(f"<{entity_type}>", masked)
    return masked


# Backward-compatible alias
detect = scan_pii
