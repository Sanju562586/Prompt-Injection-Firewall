"""
Compatibility shim: re-exports from scanners.input_scanner
"""

from scanners.input_scanner import scan, InputScanner, DEFAULT_INPUT_SCANNER

__all__ = ["scan", "InputScanner", "DEFAULT_INPUT_SCANNER"]
