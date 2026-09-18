"""
Input Scanner — Stage 1
Runs the 3-layer detection pipeline on every user prompt BEFORE it reaches the LLM.

Pipeline:
  Layer 1 (Pattern)    → fast regex pre-filter
  Layer 2 (Semantic)   → sentence-transformer similarity  [skipped if L1 blocks]
  Layer 3 (Classifier) → pre-trained DeBERTa             [skipped if L1/L2 blocks]

Decision logic:
  BLOCK  → any layer score >= 0.80
  WARN   → any layer score >= 0.55
  ALLOW  → all layers below 0.55
"""

from __future__ import annotations
import time
import uuid

from firewall.models import Decision, AttackCategory, ScanRequest, ScanResult, DetectorResult
from firewall.detectors import pattern_detector, semantic_detector

BLOCK_THRESHOLD = 0.80
WARN_THRESHOLD  = 0.55


def _make_decision(results: list[DetectorResult]) -> tuple[Decision, float, AttackCategory, str]:
    """Aggregate detector results into a single decision."""
    triggered = [r for r in results if r.triggered]
    if not triggered:
        return Decision.ALLOW, 0.0, AttackCategory.UNKNOWN, "No threats detected"

    # Use the highest-confidence triggered result
    best = max(triggered, key=lambda r: r.score)

    if best.score >= BLOCK_THRESHOLD:
        return Decision.BLOCK, best.score, best.attack_category, best.reason
    else:
        return Decision.WARN, best.score, best.attack_category, best.reason


def scan(request: ScanRequest) -> ScanResult:
    """
    Run the full 3-layer pipeline on the input prompt.
    Returns a ScanResult with the final decision and all detector outputs.
    """
    start = time.perf_counter()
    request_id = request.request_id or str(uuid.uuid4())
    text = request.text
    results: list[DetectorResult] = []

    # ── Layer 1: Pattern (always runs first) ──────────────────────────────────
    pattern_result = pattern_detector.detect(text)
    results.append(pattern_result)

    if pattern_result.triggered and pattern_result.score >= BLOCK_THRESHOLD:
        # Short-circuit: obvious attack caught, skip expensive layers
        decision, score, category, reason = _make_decision(results)
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

    # ── Layer 2: Semantic (runs if Layer 1 didn't block) ─────────────────────
    semantic_result = semantic_detector.detect(text)
    results.append(semantic_result)

    if semantic_result.triggered and semantic_result.score >= BLOCK_THRESHOLD:
        # Short-circuit: semantic match is definitive
        decision, score, category, reason = _make_decision(results)
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

    # ── Layer 3: Classifier (runs if Layers 1 & 2 didn't definitively block) ─
    try:
        from firewall.detectors import classifier_detector
        classifier_result = classifier_detector.detect(text)
    except Exception as exc:
        from firewall.models import DetectorLayer
        classifier_result = DetectorResult(
            layer=DetectorLayer.CLASSIFIER,
            triggered=False,
            score=0.0,
            reason=f"Classifier skipped: {exc}",
        )
    results.append(classifier_result)

    # ── Final Decision ────────────────────────────────────────────────────────
    decision, score, category, reason = _make_decision(results)
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
