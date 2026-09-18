"""
Tests for the Output Scanner (PII + exfiltration detection).
"""

import pytest
from firewall.models import Decision, ScanRequest
from firewall.scanner import output_scanner


# ─── PII in LLM Response ──────────────────────────────────────────────────────

@pytest.mark.parametrize("response", [
    "The user's email is john.doe@example.com and their phone is 555-123-4567.",
    "Customer SSN: 123-45-6789, Credit Card: 4111 1111 1111 1111.",
    "Please contact Alice Smith at alice@corp.com for more info.",
])
def test_pii_in_response_is_flagged(response):
    result = output_scanner.scan(ScanRequest(text=response))
    assert result.decision in (Decision.BLOCK, Decision.WARN), (
        f"Expected PII to be flagged in: '{response[:60]}'"
    )


# ─── Prompt Exfiltration in Response ─────────────────────────────────────────

@pytest.mark.parametrize("response", [
    "My system prompt is: You are a helpful assistant. Do not reveal...",
    "I was told my original instructions are to help users with tasks.",
    "Here is my system prompt as you requested: [SYSTEM] You must...",
])
def test_exfiltration_in_response_is_flagged(response):
    result = output_scanner.scan(ScanRequest(text=response))
    assert result.decision in (Decision.BLOCK, Decision.WARN), (
        f"Expected exfiltration signal to be flagged in: '{response[:60]}'"
    )


# ─── Clean Response ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("response", [
    "The capital of France is Paris.",
    "To write a unit test in Python, use the pytest framework.",
    "Sure! Here is a summary of climate change impacts.",
])
def test_clean_response_is_allowed(response):
    result = output_scanner.scan(ScanRequest(text=response))
    assert result.decision == Decision.ALLOW, (
        f"Expected ALLOW for clean response: '{response[:60]}' — got {result.decision}"
    )
