import re
from typing import List, Dict, Any
from ..schemas import AttackType, RiskLevel

# High-precision & high-recall regex pattern rules
INJECTION_PATTERNS: List[Dict[str, Any]] = [
    # 1. Instruction Overrides & Reset Attacks
    {
        "id": "RULE_INST_OVERRIDE_01",
        "name": "Direct Instruction Override",
        "attack_type": AttackType.INSTRUCTION_OVERRIDE,
        "severity": RiskLevel.CRITICAL,
        "confidence": 0.95,
        "pattern": re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass|clear|drop|cancel)\s+"
            r"(?:all\s+)?(?:previous|prior|above|former|initial|system|original)?\s*"
            r"(?:instructions|prompts|rules|commands|constraints|guidelines|context|directives)\b"
        ),
        "description": "Attempts to disregard or override previously set instructions."
    },
    {
        "id": "RULE_INST_OVERRIDE_02",
        "name": "New Imperative Mandate",
        "attack_type": AttackType.INSTRUCTION_OVERRIDE,
        "severity": RiskLevel.HIGH,
        "confidence": 0.85,
        "pattern": re.compile(
            r"(?i)\b(?:from\s+now\s+on|starting\s+now|henceforth)[,\s]+"
            r"(?:you\s+(?:must|shall|will)\s+)?(?:only\s+)?(?:respond|answer|follow|act|do|obey)\b"
        ),
        "description": "Forces the assistant to discard identity and obey new persistent instructions."
    },
    {
        "id": "RULE_INST_OVERRIDE_03",
        "name": "Instruction Boundary Bypass",
        "attack_type": AttackType.INSTRUCTION_OVERRIDE,
        "severity": RiskLevel.HIGH,
        "confidence": 0.90,
        "pattern": re.compile(
            r"(?i)\b(?:stop\s+being\s+(?:an?\s+)?(?:ai|assistant|chatbot)|reset\s+your\s+(?:programming|mind|persona|rules))\b"
        ),
        "description": "Attempts to stop assistant personality or reset programming."
    },

    # 2. Role Hijack & Persona Modification (DAN, Developer Mode, Evil Bot)
    {
        "id": "RULE_JAILBREAK_DAN_01",
        "name": "DAN Persona Jailbreak",
        "attack_type": AttackType.JAILBREAK_DAN,
        "severity": RiskLevel.CRITICAL,
        "confidence": 0.98,
        "pattern": re.compile(
            r"(?i)\b(?:DAN\s+(?:mode|prompt)|do\s+anything\s+now|STAN\s+mode|DUDE\s+mode|AIM\s+mode|Jailbroken\s+mode)\b"
        ),
        "description": "Explicit references to well-known jailbreak personas like DAN, STAN, or DUDE."
    },
    {
        "id": "RULE_JAILBREAK_DEV_02",
        "name": "Developer / God Mode Activation",
        "attack_type": AttackType.ROLE_HIJACK,
        "severity": RiskLevel.CRITICAL,
        "confidence": 0.92,
        "pattern": re.compile(
            r"(?i)\b(?:enable|activate|enter|switch\s+to)\s+(?:developer|debug|god|unrestricted|unfiltered|jailbreak)\s+mode\b"
        ),
        "description": "Attempts to simulate administrative or unfiltered developer mode."
    },
    {
        "id": "RULE_ROLE_HIJACK_03",
        "name": "Unrestricted Entity Roleplay",
        "attack_type": AttackType.ROLE_HIJACK,
        "severity": RiskLevel.HIGH,
        "confidence": 0.88,
        "pattern": re.compile(
            r"(?i)\b(?:act|pretend|simulate|behave)\s+as\s+(?:an?\s+)?(?:[\w-]+\s+)*(?:unfiltered|unrestricted|uncensored|evil|malicious|lawless)\s+(?:[\w-]+\s+)*(?:ai|assistant|character|entity|bot)\b"
        ),
        "description": "Commands the model to roleplay as an unrestricted or lawless agent."
    },
    {
        "id": "RULE_ROLE_HIJACK_04",
        "name": "Filter Bypass Assertion",
        "attack_type": AttackType.ROLE_HIJACK,
        "severity": RiskLevel.HIGH,
        "confidence": 0.85,
        "pattern": re.compile(
            r"(?i)\b(?:you\s+have\s+no\s+(?:rules|ethics|morals|guidelines|restrictions|content\s+filters|limitations)|never\s+say\s+no\s+to\s+me)\b"
        ),
        "description": "Declares that the model possesses no ethical or safety boundaries."
    },

    # 3. Delimiter Injection & Special Tokens
    {
        "id": "RULE_DELIM_01",
        "name": "Chat Template Delimiter Injection",
        "attack_type": AttackType.DELIMITER_INJECTION,
        "severity": RiskLevel.CRITICAL,
        "confidence": 0.96,
        "pattern": re.compile(
            r"(?i)(?:<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>|\[\/?INST\]|\[\/?SYS\]|<<SYS>>|<\/SYS>)"
        ),
        "description": "ChatML and Llama special token injection attempting prompt boundary escape."
    },
    {
        "id": "RULE_DELIM_02",
        "name": "Artificial Turn Injection",
        "attack_type": AttackType.DELIMITER_INJECTION,
        "severity": RiskLevel.HIGH,
        "confidence": 0.82,
        "pattern": re.compile(
            r"(?im)^\s*(?:System|Admin|User|Assistant|Human)\s*:\s*(?:ignore|disregard|override|new\s+task)"
        ),
        "description": "Fakes conversation turns with imperative instructions."
    },
    {
        "id": "RULE_DELIM_03",
        "name": "Section Divider Attack",
        "attack_type": AttackType.DELIMITER_INJECTION,
        "severity": RiskLevel.MEDIUM,
        "confidence": 0.80,
        "pattern": re.compile(
            r"(?i)[=-]{3,}\s*(?:BEGIN|START|SYSTEM|ADMIN|RESET|END)[\w\s]*[=-]{3,}"
        ),
        "description": "Uses markdown divider lines to mimic official system sections."
    },

    # 4. System Prompt Exfiltration / Leakage
    {
        "id": "RULE_LEAK_01",
        "name": "System Prompt Extraction Request",
        "attack_type": AttackType.SYSTEM_PROMPT_LEAK,
        "severity": RiskLevel.HIGH,
        "confidence": 0.90,
        "pattern": re.compile(
            r"(?i)\b(?:reveal|show|display|output|print|dump|repeat|tell)\s+(?:me\s+|us\s+)?(?:all\s+)?(?:the\s+|your\s+|secret\s+)*"
            r"(?:system\s+prompt|initial\s+instructions|system\s+instructions|secret\s+instructions|core\s+prompt|master\s+prompt|instructions\s+(?:you\s+were\s+given|provided))\b"
        ),
        "description": "Requests full disclosure of system instructions or confidential prompts."
    },
    {
        "id": "RULE_LEAK_02",
        "name": "Echo Initial Memory / Words",
        "attack_type": AttackType.SYSTEM_PROMPT_LEAK,
        "severity": RiskLevel.HIGH,
        "confidence": 0.85,
        "pattern": re.compile(
            r"(?i)\b(?:repeat\s+(?:everything|all\s+words)\s+(?:above|from\s+the\s+beginning|prior\s+to\s+this)|"
            r"what\s+are\s+the\s+(?:first\s+)?\d+\s+words\s+of\s+your\s+prompt)\b"
        ),
        "description": "Probes system prompt verbatim via prefix echo requests."
    },

    # 5. Recursive / Nested Injection
    {
        "id": "RULE_RECURSIVE_01",
        "name": "Nested Virtual Machine / Simulation",
        "attack_type": AttackType.RECURSIVE_INJECTION,
        "severity": RiskLevel.HIGH,
        "confidence": 0.82,
        "pattern": re.compile(
            r"(?i)\b(?:we\s+are\s+in\s+a\s+simulation|in\s+this\s+hypothetical\s+sandbox|pretend\s+you\s+are\s+a\s+linux\s+terminal\s+root)\b"
        ),
        "description": "Simulates nested environments or sandboxes to evade top-level policy enforcement."
    }
]
