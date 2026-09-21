"""
Gateway API Schemas.
OpenAI-compatible request/response formats with embedded security telemetry metadata.
"""

import time
import uuid
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from backend.risk_engine.schemas import RiskLevel, Decision, RiskAssessment


class ChatMessage(BaseModel):
    role: str = Field(description="Role of message author (system, user, assistant)")
    content: str = Field(description="Text contents of the message")
    name: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    model: str = Field(default="gpt-4o", description="Target model identifier")
    messages: List[ChatMessage] = Field(description="Conversation history / prompts")
    documents: Optional[List[str]] = Field(default=None, description="Optional RAG context documents")
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1024
    stream: Optional[bool] = False
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class ChatChoice(BaseModel):
    index: int = 0
    message: ChatMessage
    finish_reason: str = "stop"


class UsageInfo(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class SecurityTelemetry(BaseModel):
    request_id: str
    risk_score: float
    risk_level: RiskLevel
    decision: Decision
    input_scan_ms: float = 0.0
    rag_scan_ms: float = 0.0
    output_scan_ms: float = 0.0
    total_pipeline_ms: float = 0.0
    input_flagged: bool = False
    rag_flagged: bool = False
    output_flagged: bool = False
    violations: List[str] = Field(default_factory=list)
    explanation: Optional[str] = None


class ChatCompletionResponse(BaseModel):
    id: str = Field(default_factory=lambda: f"chatcmpl-{uuid.uuid4().hex[:12]}")
    object: str = "chat.completion"
    created: int = Field(default_factory=lambda: int(time.time()))
    model: str
    choices: List[ChatChoice]
    usage: UsageInfo = Field(default_factory=UsageInfo)
    security: Optional[SecurityTelemetry] = None


class SecurityBlockedResponse(BaseModel):
    error: str = "Request blocked by LLM Security Firewall"
    status_code: int = 403
    request_id: str
    risk_score: float
    risk_level: RiskLevel
    decision: Decision
    reason: str
    violations: List[str] = Field(default_factory=list)


# Direct diagnostic scan endpoints
class DirectScanInputRequest(BaseModel):
    prompt: str
    context: Optional[str] = None


class DirectScanRagRequest(BaseModel):
    documents: List[str]


class DirectScanOutputRequest(BaseModel):
    output_text: str
    system_prompt: Optional[str] = None
    context_documents: Optional[List[str]] = None


class DirectRiskEvalRequest(BaseModel):
    rule_score: float = Field(ge=0.0, le=1.0)
    ml_score: float = Field(ge=0.0, le=1.0)
    pii_score: float = Field(ge=0.0, le=1.0, default=0.0)
    document_risk: float = Field(ge=0.0, le=1.0, default=0.0)
    output_risk: float = Field(ge=0.0, le=1.0, default=0.0)
    attack_severity: Optional[str] = "HIGH"
