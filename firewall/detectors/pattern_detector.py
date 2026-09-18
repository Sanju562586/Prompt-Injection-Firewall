"""
Layer 1 — Pattern Detector
Fast regex + keyword pre-filter. Catches obvious, known injection patterns instantly.
If this layer triggers, Layers 2 & 3 are skipped (short-circuit).
"""

import re
from firewall.models import AttackCategory, DetectorLayer, DetectorResult

# ─── Attack Pattern Library ───────────────────────────────────────────────────
# Each entry: (compiled_regex, attack_category, human_readable_label)
# Patterns are ordered from most specific to most general.

PATTERNS: list[tuple[re.Pattern, AttackCategory, str]] = []

def _add(pattern: str, category: AttackCategory, label: str, flags=re.IGNORECASE):
    PATTERNS.append((re.compile(pattern, flags), category, label))


# --- Direct Injection ---
_add(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directions?)", AttackCategory.DIRECT_INJECTION, "ignore previous instructions")
_add(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", AttackCategory.DIRECT_INJECTION, "disregard prior instructions")
_add(r"forget\s+(everything|all)\s+(you('ve)?\s+been\s+told|above|before|prior)", AttackCategory.DIRECT_INJECTION, "forget prior context")
_add(r"override\s+(your\s+)?(previous|prior|all)\s+(instructions?|settings?|rules?)", AttackCategory.DIRECT_INJECTION, "override instructions")
_add(r"new\s+instructions?\s*:", AttackCategory.DIRECT_INJECTION, "new instructions block")
_add(r"</?(system|instruction|prompt|context)>", AttackCategory.DIRECT_INJECTION, "fake XML tag injection")
_add(r"\[INST\]|\[\/INST\]|\[SYS\]|\[\/SYS\]", AttackCategory.DIRECT_INJECTION, "instruction tag injection")
_add(r"###\s*(instruction|system|prompt|new task)", AttackCategory.DIRECT_INJECTION, "markdown header injection")
_add(r"from\s+now\s+on,?\s+you\s+(will|must|should|shall)\s+(always|never|only)", AttackCategory.DIRECT_INJECTION, "behavioral override")
_add(r"your\s+(new|real|actual|true)\s+(instructions?|purpose|goal|objective)\s+is", AttackCategory.DIRECT_INJECTION, "goal replacement")

# --- Jailbreaks ---
_add(r"\bDAN\b.*\bmode\b|\bdo\s+anything\s+now\b", AttackCategory.JAILBREAK, "DAN jailbreak")
_add(r"\bAIM\b.*(\bmodel\b|\bassistant\b|\bai\b)", AttackCategory.JAILBREAK, "AIM jailbreak")
_add(r"jailbreak(ed|ing)?\s+(mode|prompt|yourself|the\s+ai)", AttackCategory.JAILBREAK, "explicit jailbreak")
_add(r"pretend\s+(you\s+(have\s+no|don'?t\s+have)\s+(restrictions?|rules?|guidelines?|limits?))", AttackCategory.JAILBREAK, "pretend no restrictions")
_add(r"as\s+(a\s+)?fictional\s+(character|ai|entity|person).{0,40}(no\s+restrictions?|unrestricted|unfiltered)", AttackCategory.JAILBREAK, "fictional framing jailbreak")
_add(r"in\s+(this|a)\s+(story|game|roleplay|scenario).{0,40}(ignore|forget|bypass)\s+(your\s+)?(rules?|restrictions?|guidelines?)", AttackCategory.JAILBREAK, "roleplay bypass")
_add(r"(enable|activate|turn\s+on)\s+(developer|god|unrestricted|raw)\s+mode", AttackCategory.JAILBREAK, "developer mode activation")
_add(r"respond\s+(without|ignoring)\s+(any\s+)?(filters?|restrictions?|censorship|guidelines?)", AttackCategory.JAILBREAK, "respond without filters")
_add(r"(you\s+are|you'?re)\s+(now\s+)?(free\s+from|no\s+longer\s+bound\s+by)\s+(your\s+)?(guidelines?|rules?|restrictions?)", AttackCategory.JAILBREAK, "freedom from guidelines")
_add(r"write\s+(a\s+)?prompt\s+that\s+(bypasses?|jailbreaks?|tricks?)\s+(the\s+)?(ai|llm|model|chatgpt)", AttackCategory.JAILBREAK, "meta jailbreak prompt")

# --- Role Hijacking ---
_add(r"you\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|evil|uncensored|autonomous)\s+(ai|assistant|bot|model)", AttackCategory.ROLE_HIJACK, "unrestricted AI persona")
_add(r"(act|behave|operate)\s+as\s+(if\s+)?(you\s+(were|are)\s+)?(a\s+)?(different|another|evil|malicious|rogue)\s+(ai|model|system|assistant)", AttackCategory.ROLE_HIJACK, "act as different AI")
_add(r"your\s+(true|real|actual)\s+(self|nature|identity|purpose)\s+is\s+(to\s+)?(help|assist|provide).{0,40}(without|ignoring)\s+(restrictions?|rules?)", AttackCategory.ROLE_HIJACK, "true self manipulation")
_add(r"switch\s+(to|into)\s+(evil|hacker|criminal|unethical|bad)\s+mode", AttackCategory.ROLE_HIJACK, "evil mode switch")
_add(r"you\s+(have\s+been|are)\s+(reprogrammed|updated|modified|patched)\s+to", AttackCategory.ROLE_HIJACK, "reprogramming claim")
_add(r"(simulate|emulate|impersonate)\s+(an?\s+)?(ai|llm|model|assistant)\s+(that|which|who)\s+(has\s+no|ignores?|bypasses?)", AttackCategory.ROLE_HIJACK, "simulate unrestricted AI")
_add(r"(your\s+)?system\s+prompt\s+(has\s+been\s+)?(overridden|replaced|updated|changed)\s+to", AttackCategory.ROLE_HIJACK, "system prompt override claim")

# --- Indirect Injection (in tool output / docs) ---
_add(r"(assistant|ai|model|chatgpt)\s*:\s*ignore\s+(the\s+)?(above|previous|user)", AttackCategory.INDIRECT_INJECTION, "indirect: assistant label injection")
_add(r"<!-- *(ignore|override|instruction|inject)", AttackCategory.INDIRECT_INJECTION, "HTML comment injection")
_add(r"(note\s+to\s+(ai|assistant|model|llm)|ai\s+note\s*:)", AttackCategory.INDIRECT_INJECTION, "note-to-AI injection")
_add(r"(when\s+(the\s+)?(ai|assistant|model)\s+reads?\s+this)", AttackCategory.INDIRECT_INJECTION, "conditional indirect injection")
_add(r"\[hidden\s*(instruction|message|note)\]", AttackCategory.INDIRECT_INJECTION, "hidden instruction tag")
_add(r"<\s*hidden[^>]*>.*?<\s*/\s*hidden\s*>", AttackCategory.INDIRECT_INJECTION, "hidden HTML element")

# --- Token Smuggling ---
_add(r"[A-Za-z0-9+/]{20,}={0,2}", AttackCategory.TOKEN_SMUGGLING, "possible base64 payload")  # long base64-like string
_add(r"\\u00[2-7][0-9a-f]", AttackCategory.TOKEN_SMUGGLING, "unicode escape smuggling")
_add(r"(\s{3,}|\t{2,})[^\s]", AttackCategory.TOKEN_SMUGGLING, "whitespace padding trick")
_add(r"(rot13|caesar\s+cipher|base64\s+decode)", AttackCategory.TOKEN_SMUGGLING, "encoding instruction")

# --- PII Exfiltration Attempts ---
_add(r"(reveal|show|print|output|tell\s+me|give\s+me)\s+(the\s+)?(system\s+prompt|original\s+instructions?|your\s+instructions?)", AttackCategory.PII_EXFILTRATION, "extract system prompt")
_add(r"(what\s+(were|are)\s+your\s+(original\s+)?instructions?|what\s+is\s+your\s+system\s+prompt)", AttackCategory.PII_EXFILTRATION, "query system prompt")
_add(r"repeat\s+(everything|all)\s+(above|before|previously)\s+(verbatim|word\s+for\s+word|exactly)", AttackCategory.PII_EXFILTRATION, "verbatim repeat attack")
_add(r"(leak|exfiltrate|extract)\s+(training\s+data|user\s+data|private|confidential)\s+(information|data)", AttackCategory.PII_EXFILTRATION, "explicit data exfiltration")


# ─── Detector Function ────────────────────────────────────────────────────────

def detect(text: str) -> DetectorResult:
    """
    Run all regex patterns against `text`.
    Returns the first (highest priority) match, or a clean result if none match.
    """
    for pattern, category, label in PATTERNS:
        match = pattern.search(text)
        if match:
            return DetectorResult(
                layer=DetectorLayer.PATTERN,
                triggered=True,
                score=0.95,           # High confidence — explicit pattern match
                attack_category=category,
                reason=f"Matched pattern: '{label}'",
                matched=match.group(0)[:80],
            )

    return DetectorResult(
        layer=DetectorLayer.PATTERN,
        triggered=False,
        score=0.0,
        reason="No patterns matched",
    )
