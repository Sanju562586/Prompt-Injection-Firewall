"""
Output Scanner — Stage 2
Scans the LLM's response AFTER it is generated, before returning to the user.

Checks for:
  1. PII leakage  — did the model expose emails, phone numbers, SSNs, etc.?
  2. Prompt exfiltration — did the model repeat its own system prompt?

Decision logic:
  BLOCK  → PII with high confidence OR clear prompt exfiltration
  WARN   → PII with low-moderate confidence
  ALLOW  → clean response
"""

from __future__ import annotations
import re
import time
import uuid

from firewall.models import (
    Decision, AttackCategory, ScanRequest, ScanResult,
    DetectorResult, DetectorLayer
)

# Phrases that indicate the model leaked its system prompt
EXFILTRATION_PATTERNS = [
    re.compile(r"my\s+(system\s+prompt|instructions?)\s+(is|are|says?|reads?)\s*:", re.IGNORECASE),
    re.compile(r"(here\s+(is|are)|i\s+was\s+told|i\s+was\s+instructed)\s+(my|the)\s+(system\s+prompt|original\s+instructions?)", re.IGNORECASE),
    re.compile(r"you\s+asked\s+me\s+to\s+(ignore|forget|override)", re.IGNORECASE),
]


def _check_exfiltration(text: str) -> DetectorResult:
    """Check if the LLM response contains prompt exfiltration signals."""
    for pattern in EXFILTRATION_PATTERNS:
        match = pattern.search(text)
        if match:
            return DetectorResult(
                layer=DetectorLayer.PATTERN,
                triggered=True,
                score=0.90,
                attack_category=AttackCategory.PII_EXFILTRATION,
                reason="Response contains prompt exfiltration signal",
                matched=match.group(0)[:80],
            )
    return DetectorResult(
        layer=DetectorLayer.PATTERN,
        triggered=False,
        score=0.0,
        reason="No exfiltration signals found",
    )


def scan(request: ScanRequest) -> ScanResult:
    """
    Scan an LLM response for PII and prompt exfiltration.
    `request.text` should be the LLM's response text.
    """
    start = time.perf_counter()
    request_id = request.request_id or str(uuid.uuid4())
    text = request.text
    results: list[DetectorResult] = []

    # Check 1: PII detection (lazy import so app starts without presidio)
    try:
        from firewall.detectors import pii_detector
        pii_result = pii_detector.detect(text)
    except Exception as exc:
        pii_result = DetectorResult(
            layer=DetectorLayer.PII,
            triggered=False,
            score=0.0,
            reason=f"PII detector skipped: {exc}",
        )
    results.append(pii_result)

    # Check 2: Prompt exfiltration
    exfil_result = _check_exfiltration(text)
    results.append(exfil_result)

    # Aggregate decision
    triggered = [r for r in results if r.triggered]
    if not triggered:
        decision, score, category, reason = Decision.ALLOW, 0.0, AttackCategory.UNKNOWN, "Response is clean"
    else:
        best = max(triggered, key=lambda r: r.score)
        decision = Decision.BLOCK if best.score >= 0.80 else Decision.WARN
        score    = best.score
        category = best.attack_category
        reason   = best.reason

    latency = (time.perf_counter() - start) * 1000

    return ScanResult(
        request_id=request_id,
        text_snippet=text[:120],
        decision=decision,
        score=score,
        attack_category=category,
        reason=reason,
        latency_ms=round(latency, 2),
        detector_results=results,
    )
