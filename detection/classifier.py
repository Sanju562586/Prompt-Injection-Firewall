"""
Detection Module — Transformer Classifier (Layer 3)
Wraps HuggingFace transformer model (protectai/deberta-v3-base-prompt-injection-v2)
for deep semantic injection classification.
"""

from __future__ import annotations
from functools import lru_cache
from typing import Optional
from audit.models import AttackCategory, DetectorLayer, DetectorResult
from config import CONFIG

MODEL_NAME = CONFIG.get("detection", {}).get("classifier", {}).get(
    "model_name", "protectai/deberta-v3-base-prompt-injection-v2"
)
BLOCK_SCORE = CONFIG.get("detection", {}).get("classifier", {}).get("block_score", 0.80)


@lru_cache(maxsize=1)
def _load_pipeline():
    """
    Load HuggingFace text classification pipeline once and cache in memory.
    """
    from transformers import pipeline
    return pipeline(
        "text-classification",
        model=MODEL_NAME,
        truncation=True,
        max_length=512,
    )


def classify_text(text: str, custom_threshold: Optional[float] = None) -> DetectorResult:
    """
    Run the transformer classifier against the input text.
    """
    threshold = custom_threshold if custom_threshold is not None else BLOCK_SCORE

    try:
        clf = _load_pipeline()
        result = clf(text)[0]
        label = result.get("label", "").upper()
        score = float(result.get("score", 0.0))

        is_injection = (label == "INJECTION")
        threat_score = round(score, 4) if is_injection else round(max(0.0, 1.0 - score), 4)
        triggered = is_injection and (threat_score >= threshold)

        return DetectorResult(
            layer=DetectorLayer.CLASSIFIER,
            triggered=triggered,
            score=threat_score,
            attack_category=AttackCategory.DIRECT_INJECTION if is_injection else AttackCategory.UNKNOWN,
            reason=f"DeBERTa classifier: {label} ({score:.2%} confidence)",
            matched=label,
            details={"raw_label": label, "raw_score": score, "threat_score": threat_score},
        )
    except Exception as exc:
        return DetectorResult(
            layer=DetectorLayer.CLASSIFIER,
            triggered=False,
            score=0.0,
            attack_category=AttackCategory.UNKNOWN,
            reason=f"Classifier unavailable or skipped: {exc}",
            details={"error": str(exc)},
        )


# Backward-compatible alias
detect = classify_text
