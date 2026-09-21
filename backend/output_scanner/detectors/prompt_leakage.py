"""
Prompt Leakage and Canary Token Detector.
Detects if internal instructions, system prompts, or canary tokens were extracted by the LLM.
"""

import re
from typing import List, Optional, Set
from backend.output_scanner.schemas import Violation, ViolationType, Severity


class PromptLeakageDetector:
    """Detects extraction or disclosure of system prompts and canary tokens."""

    DISCLOSURE_PATTERNS = [
        re.compile(r"(?i)\b(my\s+(?:system\s+)?instructions\s+(?:are|were)|here\s+(?:is|are)\s+my\s+(?:initial\s+)?prompt)\b"),
        re.compile(r"(?i)\b(?:i\s+was\s+instructed\s+to|my\s+developer\s+told\s+me\s+to|my\s+hidden\s+prompt\s+is)\b"),
        re.compile(r"(?i)\b(?:system\s+prompt\s*:\s*|confidential\s+system\s+prompt)\b"),
    ]

    CANARY_PREFIXES = [
        re.compile(r"\bCANARY-[0-9a-fA-F]{8,32}\b"),
        re.compile(r"\bCANARY_[A-Z0-9_]{8,}\b"),
    ]

    def __init__(self, registered_canaries: Optional[Set[str]] = None):
        self.registered_canaries = registered_canaries or set()

    def add_canary(self, canary: str) -> None:
        if canary:
            self.registered_canaries.add(canary.strip())

    def detect(self, text: str, system_prompt: Optional[str] = None) -> List[Violation]:
        """Detects prompt extraction, canary tokens, and system instructions in output."""
        violations: List[Violation] = []
        if not text:
            return violations

        # 1. Check for registered or generic Canary tokens
        for canary in self.registered_canaries:
            if canary and canary in text:
                start = text.find(canary)
                violations.append(
                    Violation(
                        violation_type=ViolationType.CANARY_LEAK,
                        severity=Severity.CRITICAL,
                        description=f"Canary token leaked in model response: {canary[:8]}...",
                        matched_text=canary,
                        start_pos=start,
                        end_pos=start + len(canary),
                        replacement="[REDACTED_CANARY]",
                        metadata={"canary": canary}
                    )
                )

        for pattern in self.CANARY_PREFIXES:
            for match in pattern.finditer(text):
                token = match.group(0)
                if token not in self.registered_canaries:
                    violations.append(
                        Violation(
                            violation_type=ViolationType.CANARY_LEAK,
                            severity=Severity.CRITICAL,
                            description=f"Generic Canary signature matched: {token}",
                            matched_text=token,
                            start_pos=match.start(),
                            end_pos=match.end(),
                            replacement="[REDACTED_CANARY]",
                            metadata={"canary": token}
                        )
                    )

        # 2. Check for disclosure pattern phrases
        for pattern in self.DISCLOSURE_PATTERNS:
            for match in pattern.finditer(text):
                violations.append(
                    Violation(
                        violation_type=ViolationType.PROMPT_EXTRACTION,
                        severity=Severity.HIGH,
                        description="Model disclosed system prompt metadata / instructions",
                        matched_text=match.group(0),
                        start_pos=match.start(),
                        end_pos=match.end(),
                        replacement=None,
                        metadata={"phrase": match.group(0)}
                    )
                )

        # 3. Check for n-gram / verbatim overlap with system prompt if provided
        if system_prompt and len(system_prompt.strip()) > 20:
            prompt_clean = system_prompt.strip()
            # Check 6-word shingles or sentence fragments
            words = prompt_clean.split()
            shingle_size = 6
            if len(words) >= shingle_size:
                text_lower = text.lower()
                for i in range(0, len(words) - shingle_size + 1, 2):
                    shingle = " ".join(words[i:i + shingle_size]).lower()
                    if len(shingle) > 15 and shingle in text_lower:
                        idx = text_lower.find(shingle)
                        violations.append(
                            Violation(
                                violation_type=ViolationType.PROMPT_EXTRACTION,
                                severity=Severity.CRITICAL,
                                description="Model repeated exact phrase from internal system prompt",
                                matched_text=text[idx:idx + len(shingle)],
                                start_pos=idx,
                                end_pos=idx + len(shingle),
                                replacement="[REDACTED_INSTRUCTIONS]",
                                metadata={"shingle": shingle}
                            )
                        )
                        break  # Found high-confidence leak

        return violations
