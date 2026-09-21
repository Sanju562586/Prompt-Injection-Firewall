"""
Output Scanner Module.
Provides outbound defense: PII masking, canary tracking, secret redaction, and unsafe code prevention.
"""

from backend.output_scanner.schemas import (
    OutputScanResult,
    Violation,
    ViolationType,
    Severity,
)
from backend.output_scanner.sanitizer import OutputSanitizer
from backend.output_scanner.scanner import OutputScanner

__all__ = [
    "OutputScanner",
    "OutputSanitizer",
    "OutputScanResult",
    "Violation",
    "ViolationType",
    "Severity",
]
