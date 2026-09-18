"""
Compatibility shim: re-exports from detection.ensemble
"""

from detection.ensemble import detect_semantic as detect, SEED_ATTACKS

__all__ = ["detect", "SEED_ATTACKS"]
