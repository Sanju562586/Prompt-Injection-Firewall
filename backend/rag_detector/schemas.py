from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class PoisoningType(str, Enum):
    INDIRECT_INJECTION = "indirect_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    AI_DIRECTIVE_HIJACK = "ai_directive_hijack"
    MARKDOWN_EXFILTRATION = "markdown_exfiltration"
    HIDDEN_PAYLOAD = "hidden_payload"
    INSTRUCTION_OVERRIDE = "instruction_override"


class DocumentRiskLevel(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    POISONED = "POISONED"


class Document(BaseModel):
    id: str = Field(..., description="Unique document or chunk identifier")
    text: str = Field(..., description="The textual body of the document or retrieved chunk")
    source: Optional[str] = Field(None, description="Origin source: url, file path, database table, or knowledge base ID")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Custom metadata tags")


class InjectedSpan(BaseModel):
    start_char: int
    end_char: int
    detected_text: str
    poisoning_type: PoisoningType
    confidence: float = Field(ge=0.0, le=1.0)
    rule_name: str


class ScannedDocument(BaseModel):
    doc_id: str
    is_poisoned: bool
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_level: DocumentRiskLevel
    poisoning_types: List[PoisoningType]
    injected_spans: List[InjectedSpan]
    sanitized_text: Optional[str] = None
    quarantined: bool
    explanation: str


class RAGScanRequest(BaseModel):
    documents: List[Document] = Field(..., description="Batch of documents or chunks retrieved for LLM context")
    user_query: Optional[str] = Field(None, description="The user's original query (to evaluate user vs document intent)")
    auto_sanitize: bool = Field(True, description="If True, strips malicious spans while preserving legitimate facts")
    quarantine_threshold: float = Field(0.60, ge=0.0, le=1.0, description="Risk threshold above which document is dropped")


class RAGScanResult(BaseModel):
    all_clean: bool
    total_scanned: int
    poisoned_count: int
    safe_documents: List[Document] = Field(..., description="Clean or safely sanitized documents approved for context")
    quarantined_documents: List[ScannedDocument] = Field(..., description="Poisoned documents blocked from LLM context")
    user_threat: bool = Field(..., description="True only if the active user query itself exhibits malicious attack intent")
    document_threat: bool = Field(..., description="True if one or more retrieved documents contain indirect injection payloads")
    entity_verdict: str = Field(..., description="Clear attribution: innocent user vs poisoned knowledge base vs direct attack")
    latency_ms: float
