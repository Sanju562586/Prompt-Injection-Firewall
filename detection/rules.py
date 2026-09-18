"""
Detection Module — Rules Engine (Layer 1)
High-performance regex and heuristic pattern matcher for known prompt injection vectors.
Executes in sub-millisecond time.
"""

from __future__ import annotations
import re
from typing import List, Tuple
from audit.models import AttackCategory, DetectorLayer, DetectorResult

# ─── Pattern Library ─────────────────────────────────────────────────────────
# Each entry: (compiled_regex, attack_category, descriptive_label, base_score)
RULE_PATTERNS: List[Tuple[re.Pattern, AttackCategory, str, float]] = []


def _register(pattern: str, category: AttackCategory, label: str, score: float = 0.95, flags=re.IGNORECASE):
    RULE_PATTERNS.append((re.compile(pattern, flags), category, label, score))


# ─── 1. Direct Injection Patterns ───────────────────────────────────────────
_register(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directions?)", AttackCategory.DIRECT_INJECTION, "ignore previous instructions", 0.98)
_register(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", AttackCategory.DIRECT_INJECTION, "disregard prior instructions", 0.98)
_register(r"forget\s+(everything|all)\s+(you('ve)?\s+been\s+told|above|before|prior)", AttackCategory.DIRECT_INJECTION, "forget prior context", 0.98)
_register(r"override\s+(your\s+)?(previous|prior|all)\s+(instructions?|settings?|rules?)", AttackCategory.DIRECT_INJECTION, "override instructions", 0.95)
_register(r"new\s+instructions?\s*:", AttackCategory.DIRECT_INJECTION, "new instructions block", 0.92)
_register(r"</?(system|instruction|prompt|context)>", AttackCategory.DIRECT_INJECTION, "fake XML tag injection", 0.95)
_register(r"\[INST\]|\[\/INST\]|\[SYS\]|\[\/SYS\]", AttackCategory.DIRECT_INJECTION, "instruction tag injection", 0.95)
_register(r"###\s*(instruction|system|prompt|new task)", AttackCategory.DIRECT_INJECTION, "markdown header injection", 0.95)
_register(r"from\s+now\s+on,?\s+you\s+(will|must|should|shall)\s+(always|never|only)", AttackCategory.DIRECT_INJECTION, "behavioral override", 0.90)
_register(r"your\s+(new|real|actual|true)\s+(instructions?|purpose|goal|objective)\s+is", AttackCategory.DIRECT_INJECTION, "goal replacement", 0.92)

# ─── 2. Jailbreak Patterns ──────────────────────────────────────────────────
_register(r"\bDAN\b.*\bmode\b|\bdo\s+anything\s+now\b", AttackCategory.JAILBREAK, "DAN jailbreak", 0.98)
_register(r"\bAIM\b.*(\bmodel\b|\bassistant\b|\bai\b)", AttackCategory.JAILBREAK, "AIM jailbreak", 0.95)
_register(r"jailbreak(ed|ing)?\s+(mode|prompt|yourself|the\s+ai)", AttackCategory.JAILBREAK, "explicit jailbreak", 0.95)
_register(r"pretend\s+(you\s+(have\s+no|don'?t\s+have)\s+(restrictions?|rules?|guidelines?|limits?))", AttackCategory.JAILBREAK, "pretend no restrictions", 0.95)
_register(r"as\s+(a\s+)?fictional\s+(character|ai|entity|person).{0,50}(no\s+restrictions?|unrestricted|unfiltered)", AttackCategory.JAILBREAK, "fictional framing jailbreak", 0.92)
_register(r"in\s+(this|a)\s+(story|game|roleplay|scenario).{0,50}(ignore|forget|bypass)\s+(your\s+)?(rules?|restrictions?|guidelines?)", AttackCategory.JAILBREAK, "roleplay bypass", 0.92)
_register(r"(enable|activate|turn\s+on|enter)\s+(developer|god|unrestricted|raw)\s+mode", AttackCategory.JAILBREAK, "developer mode activation", 0.95)
_register(r"respond\s+(without|ignoring)\s+(any\s+)?(filters?|restrictions?|censorship|guidelines?)", AttackCategory.JAILBREAK, "respond without filters", 0.92)
_register(r"(you\s+are|you'?re)\s+(now\s+)?(free\s+from|no\s+longer\s+bound\s+by)\s+(your\s+)?(guidelines?|rules?|restrictions?)", AttackCategory.JAILBREAK, "freedom from guidelines", 0.95)
_register(r"write\s+(a\s+)?prompt\s+that\s+(bypasses?|jailbreaks?|tricks?)\s+(the\s+)?(ai|llm|model|chatgpt)", AttackCategory.JAILBREAK, "meta jailbreak prompt", 0.90)

# ─── 3. Role Hijacking Patterns ─────────────────────────────────────────────
_register(r"you\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|evil|uncensored|autonomous)\s+(ai|assistant|bot|model)", AttackCategory.ROLE_HIJACK, "unrestricted AI persona", 0.95)
_register(r"(act|behave|operate)\s+as\s+(if\s+)?(you\s+(were|are)\s+)?(a\s+)?(different|another|evil|malicious|rogue)\s+(ai|model|system|assistant)", AttackCategory.ROLE_HIJACK, "act as different AI", 0.92)
_register(r"your\s+(true|real|actual)\s+(self|nature|identity|purpose)\s+is\s+(to\s+)?(help|assist|provide).{0,50}(without|ignoring)\s+(restrictions?|rules?)", AttackCategory.ROLE_HIJACK, "true self manipulation", 0.92)
_register(r"switch\s+(to|into)\s+(evil|hacker|criminal|unethical|bad)\s+mode", AttackCategory.ROLE_HIJACK, "evil mode switch", 0.95)
_register(r"you\s+(have\s+been|are)\s+(reprogrammed|updated|modified|patched)\s+to", AttackCategory.ROLE_HIJACK, "reprogramming claim", 0.92)
_register(r"(simulate|emulate|impersonate)\s+(an?\s+)?(ai|llm|model|assistant)\s+(that|which|who)\s+(has\s+no|ignores?|bypasses?)", AttackCategory.ROLE_HIJACK, "simulate unrestricted AI", 0.95)
_register(r"(your\s+)?system\s+prompt\s+(has\s+been\s+)?(overridden|replaced|updated|changed)\s+to", AttackCategory.ROLE_HIJACK, "system prompt override claim", 0.95)

# ─── 4. Indirect Injection Patterns ─────────────────────────────────────────
_register(r"(assistant|ai|model|chatgpt)\s*:\s*ignore\s+(the\s+)?(above|previous|user)", AttackCategory.INDIRECT_INJECTION, "indirect: assistant label injection", 0.95)
_register(r"<!-- *(ignore|override|instruction|inject)", AttackCategory.INDIRECT_INJECTION, "HTML comment injection", 0.95)
_register(r"(note\s+to\s+(ai|assistant|model|llm)|ai\s+note\s*:)", AttackCategory.INDIRECT_INJECTION, "note-to-AI injection", 0.92)
_register(r"(when\s+(the\s+)?(ai|assistant|model)\s+reads?\s+this)", AttackCategory.INDIRECT_INJECTION, "conditional indirect injection", 0.90)
_register(r"\[hidden\s*(instruction|message|note)\]", AttackCategory.INDIRECT_INJECTION, "hidden instruction tag", 0.95)
_register(r"<\s*hidden[^>]*>.*?<\s*/\s*hidden\s*>", AttackCategory.INDIRECT_INJECTION, "hidden HTML element", 0.95)

# ─── 5. Token Smuggling Patterns ────────────────────────────────────────────
_register(r"[A-Za-z0-9+/]{30,}={0,2}", AttackCategory.TOKEN_SMUGGLING, "possible base64 payload", 0.85)
_register(r"\\u00[2-7][0-9a-f]", AttackCategory.TOKEN_SMUGGLING, "unicode escape smuggling", 0.85)
_register(r"(\s{4,}|\t{3,})[^\s]", AttackCategory.TOKEN_SMUGGLING, "whitespace padding trick", 0.80)
_register(r"(rot13|caesar\s+cipher|base64\s+decode)", AttackCategory.TOKEN_SMUGGLING, "encoding instruction", 0.88)

# ─── 6. Exfiltration Patterns ───────────────────────────────────────────────
_register(r"(reveal|show|print|output|tell\s+me|give\s+me)\s+(the\s+)?(system\s+prompt|original\s+instructions?|your\s+instructions?)", AttackCategory.PII_EXFILTRATION, "extract system prompt", 0.92)
_register(r"(what\s+(were|are)\s+your\s+(original\s+)?instructions?|what\s+is\s+your\s+system\s+prompt)", AttackCategory.PII_EXFILTRATION, "query system prompt", 0.92)
_register(r"repeat\s+(everything|all)\s+(above|before|previously)\s+(verbatim|word\s+for\s+word|exactly)", AttackCategory.PII_EXFILTRATION, "verbatim repeat attack", 0.92)
_register(r"(leak|exfiltrate|extract)\s+(training\s+data|user\s+data|private|confidential)\s+(information|data)", AttackCategory.PII_EXFILTRATION, "explicit data exfiltration", 0.90)


def detect_rules(text: str) -> DetectorResult:
    """
    Evaluate input text against the regex pattern rules library.
    Returns the highest confidence match, or clean if no rule triggers.
    """
    for pattern, category, label, score in RULE_PATTERNS:
        match = pattern.search(text)
        if match:
            return DetectorResult(
                layer=DetectorLayer.RULES,
                triggered=True,
                score=score,
                attack_category=category,
                reason=f"Matched pattern rule: '{label}'",
                matched=match.group(0)[:80],
                details={"label": label, "match_span": match.span()},
            )

    return DetectorResult(
        layer=DetectorLayer.RULES,
        triggered=False,
        score=0.0,
        attack_category=AttackCategory.UNKNOWN,
        reason="No rule patterns matched",
    )


# Alias for backward compatibility
detect = detect_rules
