"""
Compatibility shim: re-exports from detection.rules
"""

from detection.rules import detect_rules as detect, RULE_PATTERNS as PATTERNS

__all__ = ["detect", "PATTERNS"]
