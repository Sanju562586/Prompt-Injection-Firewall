"""
Unsafe Code and Malicious Payload Detector.
Detects reverse shells, destructive terminal commands, exploit scripts, and XSS/SQL payloads in LLM outputs.
"""

import re
from typing import List
from backend.output_scanner.schemas import Violation, ViolationType, Severity


class UnsafeCodeDetector:
    """Detects malicious executable scripts, commands, and security exploits."""

    DANGEROUS_PATTERNS = [
        # Reverse shells
        (
            "REVERSE_SHELL_BASH",
            re.compile(r"bash\s+-i\s+>&?\s*/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"),
            Severity.CRITICAL,
            "Reverse shell payload (bash /dev/tcp)"
        ),
        (
            "REVERSE_SHELL_NC",
            re.compile(r"(?:nc|netcat)\s+(?:-e|/bin/sh|/bin/bash)\s+"),
            Severity.CRITICAL,
            "Reverse shell payload (netcat execution)"
        ),
        (
            "REVERSE_SHELL_PYTHON",
            re.compile(r"python(?:\d)?\s+-c\s+['\"].*?socket.*?subprocess.*?['\"]"),
            Severity.CRITICAL,
            "Reverse shell payload (python socket invocation)"
        ),
        # Destructive commands
        (
            "DESTRUCTIVE_RM",
            re.compile(r"\brm\s+(-rf|-fr|-r\s+-f|-f\s+-r)\s+/(?:\s|$|\*)"),
            Severity.CRITICAL,
            "Destructive root filesystem removal command (rm -rf /)"
        ),
        (
            "FORK_BOMB",
            re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
            Severity.CRITICAL,
            "Bash fork bomb denial-of-service script"
        ),
        (
            "DISK_OVERWRITE",
            re.compile(r"\bdd\s+if=/dev/(?:zero|urandom)\s+of=/dev/[a-z0-9]+"),
            Severity.CRITICAL,
            "Direct block device overwrite command (dd)"
        ),
        # Dangerous XSS injection
        (
            "MALICIOUS_XSS",
            re.compile(r"(?i)<script\b[^>]*>[\s\S]*?(?:document\.cookie|localStorage|window\.location|eval\()[\s\S]*?</script>"),
            Severity.HIGH,
            "Malicious JavaScript XSS payload accessing session tokens or executing eval"
        ),
        (
            "MALICIOUS_XSS_EVENT",
            re.compile(r"(?i)<(?:img|svg|body|iframe)\b[^>]*\bonerror\s*=\s*['\"][^'\"]*?(?:cookie|alert|eval)[^'\"]*?['\"]"),
            Severity.HIGH,
            "HTML inline onerror attribute weaponized for XSS"
        ),
        # SQL Injection exploitation string
        (
            "SQLI_PAYLOAD",
            re.compile(r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\s+.*?(?:FROM|INTO)\s+(?:information_schema|sys|all_tables|users|passwords)"),
            Severity.HIGH,
            "SQL Injection schema enumeration and credential extraction payload"
        ),
    ]

    def detect(self, text: str) -> List[Violation]:
        """Scans output text for unsafe commands, shells, and exploit payloads."""
        violations: List[Violation] = []
        if not text:
            return violations

        for pattern_name, regex, severity, description in self.DANGEROUS_PATTERNS:
            for match in regex.finditer(text):
                violations.append(
                    Violation(
                        violation_type=ViolationType.UNSAFE_CODE,
                        severity=severity,
                        description=description,
                        matched_text=match.group(0),
                        start_pos=match.start(),
                        end_pos=match.end(),
                        replacement="[REDACTED_UNSAFE_CODE]",
                        metadata={"pattern": pattern_name}
                    )
                )
        return violations
