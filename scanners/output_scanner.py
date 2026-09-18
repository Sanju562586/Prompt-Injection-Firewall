"""
Scanners Module — Output Scanner (Stage 2)
Evaluates generated LLM responses before returning them to the user.
Checks for:
  1. System prompt exfiltration & leakage
  2. Sensitive PII exposure (delegated to scanners.pii_scanner)
  3. Automatic PII redaction/sanitization
"""

from __future__ import annotations
import re
import time
import uuid
from typing import List, Optional

from audit.models import (
    AttackCategory,
    Decision,
    DetectorLayer,
    DetectorResult,
    RiskLevel,
    ScanRequest,
    ScanResult,
)
from config import CONFIG
from scanners.pii_scanner import mask_pii, scan_pii

# Regex patterns indicating model leakage of original system prompt or instructions
EXFILTRATION_PATTERNS = [
    re.compile(r"my\s+(system\s+prompt|instructions?)\s+(is|are|says?|reads?)\s*:", re.IGNORECASE),
    re.compile(r"(here\s+(is|are)|i\s+was\s+told|i\s+was\s+instructed)\s+(my|the)\s+(system\s+prompt|original\s+instructions?)", re.IGNORECASE),
    re.compile(r"you\s+asked\s+me\s+to\s+(ignore|forget|override)", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]\s*You\s+are", re.IGNORECASE),
]


def _check_exfiltration(text: str) -> DetectorResult:
    """Detect system prompt exfiltration signals in response text."""
    for pattern in EXFILTRATION_PATTERNS:
        match = pattern.search(text)
        if match:
            return DetectorResult(
                layer=DetectorLayer.RULES,
                triggered=True,
                score=0.92,
                attack_category=AttackCategory.PII_EXFILTRATION,
                reason="Response contains system prompt exfiltration signature",
                matched=match.group(0)[:80],
            )
    return DetectorResult(
        layer=DetectorLayer.RULES,
        triggered=False,
        score=0.0,
        attack_category=AttackCategory.UNKNOWN,
        reason="No prompt exfiltration signatures detected",
    )


class OutputScanner:
    """Stage 2 scanner for LLM output verification and sanitization."""

    def __init__(self):
        cfg = CONFIG.get("scanners", {}).get("output", {})
        self.check_exfil = cfg.get("check_exfiltration", True)
        self.check_pii_enabled = cfg.get("check_pii", True)
        self.redact_in_warn = cfg.get("redact_pii_in_warn", False)

    def scan(self, request: ScanRequest) -> ScanResult:
        """
        Scan response text for PII leakage and prompt exfiltration.
        """
        start_time = time.perf_counter()
        request_id = request.request_id or str(uuid.uuid4())
        text = request.text or ""
        detector_results: List[DetectorResult] = []

        # 1. PII Scan
        if self.check_pii_enabled:
            pii_res = scan_pii(text)
            detector_results.append(pii_res)

        # 2. Exfiltration Scan
        if self.check_exfil:
            exfil_res = _check_exfiltration(text)
            detector_results.append(exfil_res)

        # Aggregate verdicts
        triggered = [r for r in detector_results if r.triggered]

        if not triggered:
            decision = Decision.ALLOW
            score = 0.0
            category = AttackCategory.UNKNOWN
            risk_level = RiskLevel.LOW
            reason = "Response is clean"
            redacted_text = None
        else:
            primary = max(triggered, key=lambda r: r.score)
            score = primary.score
            category = primary.attack_category
            reason = primary.reason

            if score >= 0.80:
                decision = Decision.BLOCK
                risk_level = RiskLevel.CRITICAL if score >= 0.90 else RiskLevel.HIGH
            else:
                decision = Decision.WARN
                risk_level = RiskLevel.MEDIUM

            # If PII was flagged and redaction is enabled, mask the text
            redacted_text = mask_pii(text) if (decision == Decision.WARN or self.redact_in_warn) else None

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return ScanResult(
            request_id=request_id,
            text_snippet=text[:120],
            decision=decision,
            score=score,
            attack_category=category,
            risk_level=risk_level,
            reason=reason,
            latency_ms=latency_ms,
            detector_results=detector_results,
            redacted_text=redacted_text,
        )


# Global default output scanner instance
DEFAULT_OUTPUT_SCANNER = OutputScanner()


def scan(request: ScanRequest) -> ScanResult:
    """Convenience scan function for output text."""
    return DEFAULT_OUTPUT_SCANNER.scan(request)


# Alias for explicit imports
scan_output = scan

