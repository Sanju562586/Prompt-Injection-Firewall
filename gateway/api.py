"""
Gateway Module — FastAPI Application Entrypoint
Exposes REST endpoints for input scanning, output scanning, RAG document scanning,
audit log queries, reverse proxy chat completions, and red-team execution.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from audit.logger import AuditLogger
from audit.models import RagDocument, RagScanResult, ScanRequest, ScanResult, ProxyChatRequest
from config import CONFIG
from gateway.middleware import RequestTracingMiddleware, SecurityHeadersMiddleware
from gateway.proxy import LLMProxy
from scanners.input_scanner import scan_input
from scanners.output_scanner import scan_output
from scanners.rag_scanner import scan_rag

app = FastAPI(
    title="LLM Firewall — Security Gateway",
    description="Multi-layer prompt injection firewall, PII guard, and reverse proxy.",
    version="1.0.0",
)

# ─── Middleware ───────────────────────────────────────────────────────────────
cors_origins = CONFIG.get("gateway", {}).get("cors_origins", ["*"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestTracingMiddleware)

# Services
audit_logger = AuditLogger()
proxy_service = LLMProxy(audit_logger)


# ─── Request Schemas ──────────────────────────────────────────────────────────

class RagScanPayload(BaseModel):
    documents: List[RagDocument]
    request_id: Optional[str] = None


class RedTeamRunPayload(BaseModel):
    category: Optional[str] = None
    attack_ids: Optional[List[str]] = None


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/v1/health", summary="Health check")
def health() -> Dict[str, str]:
    """Return gateway service status."""
    return {"status": "ok", "service": "llm-firewall", "version": "1.0.0"}


@app.post("/v1/scan/input", response_model=ScanResult, summary="Scan user prompt (Stage 1)")
def scan_user_input(payload: ScanRequest) -> ScanResult:
    """
    Analyze user prompt through the multi-layer pipeline before LLM processing.
    """
    result = scan_input(payload)
    audit_logger.log(result, scan_type="input")
    return result


@app.post("/v1/scan/output", response_model=ScanResult, summary="Scan LLM response (Stage 2)")
def scan_model_output(payload: ScanRequest) -> ScanResult:
    """
    Inspect LLM response for PII leakage and system prompt exfiltration before delivery.
    """
    result = scan_output(payload)
    audit_logger.log(result, scan_type="output")
    return result


@app.post("/v1/scan/rag", response_model=RagScanResult, summary="Scan RAG document chunks")
def scan_rag_documents(payload: RagScanPayload) -> RagScanResult:
    """
    Scan retrieved document chunks for embedded indirect injections.
    """
    return scan_rag(payload.documents)


@app.post("/v1/chat/completions", summary="OpenAI-compatible LLM reverse proxy")
async def chat_completions(chat_req: ProxyChatRequest, request: Request):
    """
    Drop-in reverse proxy: validates prompt -> forwards to LLM -> sanitizes response.
    """
    req_id = getattr(request.state, "request_id", None) or "proxy-req"
    return await proxy_service.forward_chat(chat_req, dict(request.headers), req_id)


@app.get("/v1/audit", summary="Query audit logs")
def get_audit_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = Query(None, description="BLOCK, WARN, or ALLOW"),
    attack_category: Optional[str] = Query(None, description="Threat category filter"),
    scan_type: Optional[str] = Query(None, description="input, output, or rag"),
) -> Dict[str, Any]:
    """Retrieve paginated forensic audit records."""
    entries = audit_logger.query(
        limit=limit,
        offset=offset,
        decision=decision,
        attack_category=attack_category,
        scan_type=scan_type,
    )
    return {
        "entries": [e.model_dump() for e in entries],
        "count": len(entries),
        "limit": limit,
        "offset": offset,
    }


@app.get("/v1/audit/stats", summary="Audit & threat statistics")
def get_audit_stats() -> Dict[str, Any]:
    """Return aggregated threat statistics, counts, and category breakdown."""
    return audit_logger.stats()


# ─── Red-Team Endpoints ───────────────────────────────────────────────────────

@app.get("/v1/redteam/attacks", summary="List red-team attack vectors")
def list_redteam_attacks() -> Dict[str, Any]:
    """Return all configured benchmark attack vectors."""
    from redteam.attacks import ATTACKS
    categories: Dict[str, int] = {}
    for a in ATTACKS:
        cat = a.category.value
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "total": len(ATTACKS),
        "categories": categories,
        "attacks": [a.model_dump() for a in ATTACKS],
    }


@app.post("/v1/redteam/run", summary="Execute red-team evaluation suite")
def run_redteam(payload: Optional[RedTeamRunPayload] = None) -> Dict[str, Any]:
    """Execute red-team attack suite against the firewall and compute score cards."""
    from redteam.runner import run_suite
    cat = payload.category if payload else None
    ids = payload.attack_ids if payload else None
    return run_suite(category=cat, attack_ids=ids)
