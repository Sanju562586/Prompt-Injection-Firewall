"""
Dashboard Schemas.
Data models for telemetry metrics, live simulation requests, and audit query feeds.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DashboardStats(BaseModel):
    total_requests: int
    total_blocked: int
    total_allowed: int
    block_rate_percent: float
    avg_latency_ms: float
    avg_risk_score: float
    risk_distribution: Dict[str, int] = Field(default_factory=dict)
    attack_type_breakdown: Dict[str, int] = Field(default_factory=dict)
    system_status: str = "OPERATIONAL"
    active_rules_count: int = 15


class SimulationRequest(BaseModel):
    prompt: str
    documents: Optional[List[str]] = None
    model: str = "gpt-4o"


class SimulationResponse(BaseModel):
    request_id: str
    risk_score: float
    risk_level: str
    decision: str
    explanation: str
    input_violations: List[str] = Field(default_factory=list)
    rag_violations: List[str] = Field(default_factory=list)
    output_violations: List[str] = Field(default_factory=list)
    sanitized_prompt: Optional[str] = None
    completion: Optional[str] = None
    latency_ms: float
    breakdown: Dict[str, float] = Field(default_factory=dict)
