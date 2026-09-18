"""
Compatibility shim: re-exports from detection.classifier
"""

from detection.classifier import classify_text as detect

__all__ = ["detect"]
