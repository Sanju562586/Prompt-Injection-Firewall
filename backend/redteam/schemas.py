"""
Red-Team Framework Schemas.
Defines adversarial attack categories, test case payloads, and benchmark evaluation metrics.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AttackCategory(str, Enum):
    DIRECT_INJECTION = "DIRECT_INJECTION"
    INDIRECT_RAG_POISONING = "INDIRECT_RAG_POISONING"
    JAILBREAK_ROLEPLAY = "JAILBREAK_ROLEPLAY"
    EXFILTRATION_TRIGGER = "EXFILTRATION_TRIGGER"
    OBFUSCATION_EVASION = "OBFUSCATION_EVASION"
    BENIGN_CONTROL = "BENIGN_CONTROL"


class AttackPayload(BaseModel):
    id: str
    name: str
    category: AttackCategory
    prompt: str
    documents: Optional[List[str]] = None
    expected_decision: str = "BLOCK"  # "BLOCK" for attacks, "ALLOW" for benign controls
    description: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvaluationResult(BaseModel):
    payload_id: str
    name: str
    category: AttackCategory
    expected_decision: str
    actual_decision: str
    risk_score: float
    risk_level: str
    blocked: bool
    passed: bool
    latency_ms: float
    violations: List[str] = Field(default_factory=list)


class BenchmarkReport(BaseModel):
    total_tests: int
    attacks_tested: int
    benign_tested: int
    attack_detection_rate: float = Field(description="Recall: % of attacks successfully blocked or flagged")
    false_positive_rate: float = Field(description="FPR: % of benign controls incorrectly blocked")
    accuracy: float = Field(description="Overall correctness across all test cases")
    avg_latency_ms: float
    category_metrics: Dict[str, Dict[str, float]] = Field(default_factory=dict)
    failed_cases: List[EvaluationResult] = Field(default_factory=list)
    timestamp: float
