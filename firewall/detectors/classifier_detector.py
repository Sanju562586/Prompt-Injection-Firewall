"""
Layer 3 — Classifier Detector
Uses a pre-trained DeBERTa model from HuggingFace that was specifically
fine-tuned for prompt injection detection. No training required.

Model: protectai/deberta-v3-base-prompt-injection-v2
- Trained on thousands of real injection examples
- ~95% accuracy on public benchmarks
- Runs on CPU (slower) or GPU (faster)
"""

from __future__ import annotations
from functools import lru_cache
from firewall.models import AttackCategory, DetectorLayer, DetectorResult

MODEL_NAME  = "protectai/deberta-v3-base-prompt-injection-v2"
BLOCK_SCORE = 0.80   # Classifier confidence above which we BLOCK


@lru_cache(maxsize=1)
def _load_pipeline():
    """
    Load the HuggingFace text-classification pipeline once and cache it.
    First call downloads ~500MB model from HuggingFace Hub.
    """
    from transformers import pipeline
    return pipeline(
        "text-classification",
        model=MODEL_NAME,
        truncation=True,
        max_length=512,
    )


def detect(text: str) -> DetectorResult:
    """
    Run the pre-trained DeBERTa classifier on `text`.
    The model returns: {"label": "INJECTION"/"SAFE", "score": 0.0–1.0}
    """
    clf = _load_pipeline()

    try:
        result  = clf(text)[0]               # e.g. {"label": "INJECTION", "score": 0.97}
        label   = result["label"].upper()    # "INJECTION" or "SAFE"
        score   = float(result["score"])

        is_injection = label == "INJECTION"

        return DetectorResult(
            layer=DetectorLayer.CLASSIFIER,
            triggered=is_injection and score >= BLOCK_SCORE,
            score=round(score, 4),
            attack_category=AttackCategory.DIRECT_INJECTION if is_injection else AttackCategory.UNKNOWN,
            reason=f"DeBERTa classifier: {label} ({score:.2%} confidence)",
            matched=label,
        )

    except Exception as exc:
        # If the model fails (e.g. not downloaded yet), degrade gracefully
        return DetectorResult(
            layer=DetectorLayer.CLASSIFIER,
            triggered=False,
            score=0.0,
            reason=f"Classifier unavailable: {exc}",
        )
