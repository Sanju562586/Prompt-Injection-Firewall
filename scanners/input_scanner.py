"""
Scanners Module — Input Scanner (Stage 1)
Evaluates incoming user prompts before they reach the LLM.
Coordinates multi-layer threat detection (Rules, Semantic, Classifier) and Risk Engine.
"""

from __future__ import annotations
import time
import uuid
from typing import Optional

from audit.models import Decision, AttackCategory, ScanRequest, ScanResult, RiskLevel
from detection.ensemble import DEFAULT_ENSEMBLE, DetectionEnsemble


class InputScanner:
    """Stage 1 firewall scanner for prompts before LLM execution."""

    def __init__(self, ensemble: Optional[DetectionEnsemble] = None):
        self.ensemble = ensemble or DEFAULT_ENSEMBLE

    def scan(self, request: ScanRequest, force_all_layers: bool = False) -> ScanResult:
        """
        Scan a prompt through the detection ensemble.
        Returns a comprehensive ScanResult with decision and forensic telemetry.
        """
        start_time = time.perf_counter()
        request_id = request.request_id or str(uuid.uuid4())
        text = request.text or ""

        # Run ensemble
        results, decision, score, attack_cat, risk_level, reason = self.ensemble.run(
            text=text,
            force_all_layers=force_all_layers,
        )

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return ScanResult(
            request_id=request_id,
            text_snippet=text[:120],
            decision=decision,
            score=score,
            attack_category=attack_cat,
            risk_level=risk_level,
            reason=reason,
            latency_ms=latency_ms,
            detector_results=results,
        )


# Global default input scanner instance
DEFAULT_INPUT_SCANNER = InputScanner()


def scan(request: ScanRequest, force_all_layers: bool = False) -> ScanResult:
    """Convenience scan function matching standard interface."""
    return DEFAULT_INPUT_SCANNER.scan(request, force_all_layers=force_all_layers)


# Alias for explicit imports
scan_input = scan

