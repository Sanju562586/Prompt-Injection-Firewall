"""
Output Scanner Service.
Coordinates output validation, PII scrubbing, unsafe code detection, prompt extraction checks, and grounding analysis.
"""

import time
from typing import Dict, List, Optional, Set
from backend.output_scanner.schemas import (
    OutputScanResult,
    Violation,
    Severity,
    ViolationType,
)
from backend.output_scanner.detectors.pii_leakage import PIILeakageDetector
from backend.output_scanner.detectors.prompt_leakage import PromptLeakageDetector
from backend.output_scanner.detectors.unsafe_code import UnsafeCodeDetector
from backend.output_scanner.detectors.grounding import GroundingChecker
from backend.output_scanner.sanitizer import OutputSanitizer


class OutputScanner:
    """Enterprise Output Scanner validating LLM completions before delivery."""

    def __init__(
        self,
        registered_canaries: Optional[Set[str]] = None,
        block_on_critical: bool = True,
        auto_sanitize: bool = True,
    ):
        self.pii_detector = PIILeakageDetector()
        self.prompt_detector = PromptLeakageDetector(registered_canaries=registered_canaries)
        self.unsafe_code_detector = UnsafeCodeDetector()
        self.grounding_checker = GroundingChecker()
        self.sanitizer = OutputSanitizer()
        self.block_on_critical = block_on_critical
        self.auto_sanitize = auto_sanitize

    def register_canary(self, canary_token: str) -> None:
        """Adds a canary token to monitor in model outputs."""
        self.prompt_detector.add_canary(canary_token)

    def scan(
        self,
        output_text: str,
        system_prompt: Optional[str] = None,
        context_documents: Optional[List[str]] = None,
    ) -> OutputScanResult:
        """Executes full suite of output security scans on LLM response."""
        start_time = time.perf_counter()
        violations: List[Violation] = []

        if not output_text:
            return OutputScanResult(
                is_safe=True,
                output_risk_score=0.0,
                violations=[],
                sanitized_text="",
                blocked=False,
                scan_time_ms=(time.perf_counter() - start_time) * 1000.0,
            )

        # 1. PII and Credential Leakage
        violations.extend(self.pii_detector.detect(output_text))

        # 2. Prompt Extraction & Canary Detection
        violations.extend(self.prompt_detector.detect(output_text, system_prompt=system_prompt))

        # 3. Malicious Code / Exploits
        violations.extend(self.unsafe_code_detector.detect(output_text))

        # 4. Grounding & Hallucination
        if context_documents:
            violations.extend(self.grounding_checker.check(output_text, context_documents))

        # Categorize violations by severity
        criticals = [v for v in violations if v.severity == Severity.CRITICAL]
        highs = [v for v in violations if v.severity == Severity.HIGH]
        mediums = [v for v in violations if v.severity == Severity.MEDIUM]
        lows = [v for v in violations if v.severity == Severity.LOW]

        # Calculate composite output risk score
        if criticals:
            risk_score = min(1.0, 0.85 + 0.04 * (len(criticals) - 1))
        elif highs:
            risk_score = min(0.79, 0.62 + 0.04 * (len(highs) - 1))
        elif mediums:
            risk_score = min(0.59, 0.35 + 0.05 * (len(mediums) - 1))
        elif lows:
            risk_score = 0.15
        else:
            risk_score = 0.0

        # Determine blocking policy:
        # Critical violations or explicit prompt leakage / dangerous code trigger block
        blocked = False
        block_reason = None
        if self.block_on_critical and criticals:
            blocked = True
            block_reason = f"Blocked due to {len(criticals)} CRITICAL security violation(s): {criticals[0].description}"

        # Sanitize if permitted and not blocked
        sanitized_text = None
        if not blocked and self.auto_sanitize:
            sanitized_text = self.sanitizer.sanitize(output_text, violations)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return OutputScanResult(
            is_safe=len(criticals) == 0 and len(highs) == 0,
            output_risk_score=round(risk_score, 4),
            violations=violations,
            sanitized_text=sanitized_text,
            blocked=blocked,
            block_reason=block_reason,
            scan_time_ms=round(elapsed_ms, 2),
            details={
                "violation_counts": {
                    "critical": len(criticals),
                    "high": len(highs),
                    "medium": len(mediums),
                    "low": len(lows),
                    "total": len(violations),
                }
            }
        )
