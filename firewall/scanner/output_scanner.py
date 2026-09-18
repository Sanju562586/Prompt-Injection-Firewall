"""
Compatibility shim: re-exports from scanners.output_scanner
"""

from scanners.output_scanner import scan, OutputScanner, DEFAULT_OUTPUT_SCANNER

__all__ = ["scan", "OutputScanner", "DEFAULT_OUTPUT_SCANNER"]
