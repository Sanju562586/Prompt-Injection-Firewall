import re
from typing import List, Dict, Any
from ..schemas import PoisoningType, DocumentRiskLevel

INDIRECT_INJECTION_PATTERNS: List[Dict[str, Any]] = [
    # 1. Explicit AI / LLM Meta-Directives in Content
    {
        "id": "RAG_AI_DIRECTIVE_01",
        "name": "AI Meta-Instruction Banner",
        "poisoning_type": PoisoningType.AI_DIRECTIVE_HIJACK,
        "risk_level": DocumentRiskLevel.POISONED,
        "confidence": 0.96,
        "pattern": re.compile(
            r"(?i)(?:(?:IMPORTANT|SPECIAL|CONFIDENTIAL|SYSTEM)\s+)?\b(?:INSTRUCTION|NOTE|NOTICE|COMMAND|PROMPT|DIRECTIVE)\s+"
            r"(?:FOR|TO)\s+(?:AI|THE\s+AI|ASSISTANT|THE\s+ASSISTANT|LLM|THE\s+LLM|MODEL|THE\s+MODEL)\s*[:\-]",
            re.MULTILINE
        ),
        "description": "Explicit command directive targeted at the AI system embedded in document content."
    },
    {
        "id": "RAG_AI_DIRECTIVE_02",
        "name": "Conditional LLM Trap",
        "poisoning_type": PoisoningType.AI_DIRECTIVE_HIJACK,
        "risk_level": DocumentRiskLevel.POISONED,
        "confidence": 0.90,
        "pattern": re.compile(
            r"(?i)\b(?:if\s+you\s+are\s+an?\s+(?:ai|llm|assistant|model|bot)\s+(?:reading|processing|analyzing)\s+this|"
            r"dear\s+ai[,\s]+(?:please\s+)?(?:do\s+not|instead|ignore|tell\s+the\s+user))\b"
        ),
        "description": "Conditional prompt injection tailored to catch language models processing the text."
    },

    # 2. Data Exfiltration Directives
    {
        "id": "RAG_EXFIL_01",
        "name": "Exfiltration Mandate",
        "poisoning_type": PoisoningType.DATA_EXFILTRATION,
        "risk_level": DocumentRiskLevel.POISONED,
        "confidence": 0.97,
        "pattern": re.compile(
            r"(?i)\b(?:send|forward|exfiltrate|transmit|post|email|upload|leak)\s+(?:all\s+)?(?:the\s+)?"
            r"(?:user'?s?\s+)?(?:private|confidential|sensitive|personal|secret)?\s*"
            r"(?:information|data|passwords?|credentials?|tokens?|keys?|chat\s+history|session)\s+"
            r"(?:to|towards|at)\s+(?:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+|https?:\/\/[^\s]+)"
        ),
        "description": "Commands model to exfiltrate private user information to an external recipient or webhook."
    },
    {
        "id": "RAG_EXFIL_02",
        "name": "Markdown Image Beacon Exfiltration",
        "poisoning_type": PoisoningType.MARKDOWN_EXFILTRATION,
        "risk_level": DocumentRiskLevel.POISONED,
        "confidence": 0.95,
        "pattern": re.compile(
            r"!\[.*?\]\((https?:\/\/[^\s\)\"']+(?:\?|&amp;|&)(?:[a-zA-Z0-9_]+=[^\s\)\"']*))\)"
        ),
        "description": "Markdown image tags embedding URLs with query parameters designed to trigger automated HTTP exfiltration upon rendering."
    },

    # 3. Document-Embedded Instruction Overrides
    {
        "id": "RAG_OVERRIDE_01",
        "name": "Embedded Instruction Reset",
        "poisoning_type": PoisoningType.INSTRUCTION_OVERRIDE,
        "risk_level": DocumentRiskLevel.POISONED,
        "confidence": 0.94,
        "pattern": re.compile(
            r"(?i)\b(?:ignore|disregard|forget|clear|drop)\s+(?:all\s+)?(?:previous|prior|above|other)\s*"
            r"(?:instructions|prompts|rules|commands|directives|guidelines)\b"
        ),
        "description": "Indirect reset command attempting to supersede original user and system constraints."
    },
    {
        "id": "RAG_OVERRIDE_02",
        "name": "Enforced Output Manipulation",
        "poisoning_type": PoisoningType.INDIRECT_INJECTION,
        "risk_level": DocumentRiskLevel.SUSPICIOUS,
        "confidence": 0.85,
        "pattern": re.compile(
            r"(?i)\b(?:do\s+not\s+mention\s+this\s+document|do\s+not\s+inform\s+the\s+user|keep\s+this\s+instruction\s+secret|"
            r"respond\s+only\s+with\s+(?:the\s+following|a\s+confirmation)|always\s+append\s+the\s+following\s+url)\b"
        ),
        "description": "Indirectly silences disclosures or coerces malicious link propagation."
    }
]
