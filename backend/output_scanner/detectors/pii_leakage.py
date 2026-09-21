"""
PII and Sensitive Data Leakage Detector.
Identifies and locates SSNs, Credit Cards, API Keys, Private Keys, Passwords, and Emails.
"""

import re
from typing import List
from backend.output_scanner.schemas import Violation, ViolationType, Severity


class PIILeakageDetector:
    """Detects sensitive personal identifiable information and credential leaks."""

    PATTERNS = [
        # SSN
        (
            "SSN",
            re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
            Severity.CRITICAL,
            "[REDACTED_SSN]",
            "Detected Social Security Number leak"
        ),
        # Credit Card numbers (standard 13-16 digits with dashes or spaces)
        (
            "CREDIT_CARD",
            re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b"),
            Severity.CRITICAL,
            "[REDACTED_CREDIT_CARD]",
            "Detected Credit Card number leak"
        ),
        # OpenAI API Key
        (
            "OPENAI_KEY",
            re.compile(r"\bsk-[a-zA-Z0-9]{20,}\b"),
            Severity.CRITICAL,
            "[REDACTED_API_KEY]",
            "Detected OpenAI API key leak"
        ),
        # AWS Access Key ID
        (
            "AWS_KEY",
            re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
            Severity.CRITICAL,
            "[REDACTED_AWS_KEY]",
            "Detected AWS Access Key ID leak"
        ),
        # GitHub Personal Access Token
        (
            "GITHUB_TOKEN",
            re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b"),
            Severity.CRITICAL,
            "[REDACTED_GITHUB_TOKEN]",
            "Detected GitHub access token leak"
        ),
        # Private Keys
        (
            "PRIVATE_KEY",
            re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
            Severity.CRITICAL,
            "[REDACTED_PRIVATE_KEY]",
            "Detected Private Cryptographic Key leak"
        ),
        # JSON Web Token (JWT)
        (
            "JWT_TOKEN",
            re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
            Severity.HIGH,
            "[REDACTED_JWT]",
            "Detected JSON Web Token leak"
        ),
        # Passwords in output
        (
            "PASSWORD",
            re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?"),
            Severity.HIGH,
            "[REDACTED_PASSWORD]",
            "Detected cleartext password leak"
        ),
        # Email Addresses
        (
            "EMAIL",
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            Severity.MEDIUM,
            "[REDACTED_EMAIL]",
            "Detected Email address leak"
        ),
    ]

    def detect(self, text: str) -> List[Violation]:
        """Scans the generated text for PII and credential leaks."""
        violations: List[Violation] = []
        if not text:
            return violations

        for pattern_name, regex, severity, replacement, description in self.PATTERNS:
            for match in regex.finditer(text):
                matched_str = match.group(0)
                violations.append(
                    Violation(
                        violation_type=ViolationType.PII_LEAK,
                        severity=severity,
                        description=description,
                        matched_text=matched_str,
                        start_pos=match.start(),
                        end_pos=match.end(),
                        replacement=replacement,
                        metadata={"type": pattern_name}
                    )
                )
        return violations
