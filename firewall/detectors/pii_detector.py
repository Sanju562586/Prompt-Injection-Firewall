"""
Compatibility shim: re-exports from scanners.pii_scanner
"""

from scanners.pii_scanner import scan_pii as detect

__all__ = ["detect"]
