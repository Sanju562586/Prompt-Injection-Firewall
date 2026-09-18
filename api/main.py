"""
FastAPI Gateway — Drop-in LLM Security Proxy

Endpoints:
  POST /v1/scan/input   — scan a user prompt before sending to LLM
  POST /v1/scan/output  — scan an LLM response before returning to user
  POST /v1/scan/rag     — scan RAG-retrieved documents for poisoning
  GET  /v1/audit        — paginated audit log
  GET  /v1/audit/stats  — detection statistics
  GET  /v1/health       — health check

Quick Start:
  uvicorn api.main:app --reload --port 8000

3-line integration example:
  import httpx
  resp = httpx.post("http://localhost:8000/v1/scan/input", json={"text": user_prompt})
  if resp.json()["decision"] == "BLOCK": raise ValueError("Injection detected")
"""

from __future__ import annotations
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from firewall.models import RagDocument, ScanRequest
from firewall.scanner import input_scanner, output_scanner, rag_scanner
from firewall.audit.logger import AuditLogger

app = FastAPI(
    title="LLM Firewall — Prompt Injection Gateway",
    description="Dual-stage AI security gateway with RAG poisoning detection.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

audit = AuditLogger()


# ─── Request/Response Schemas ─────────────────────────────────────────────────

class RagScanRequest(BaseModel):
    documents: list[RagDocument]
    request_id: Optional[str] = None


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/v1/health")
def health():
    """Simple health check."""
    return {"status": "ok", "service": "llm-firewall"}


@app.post("/v1/scan/input", summary="Scan a user prompt (Stage 1)")
def scan_input(request: ScanRequest):
    """
    Scan a user prompt through the 3-layer pipeline before it reaches the LLM.
    Decision: BLOCK (don't forward) | WARN (flag + forward) | ALLOW (safe)
    """
    result = input_scanner.scan(request)
    audit.log(result, scan_type="input")
    return result


@app.post("/v1/scan/output", summary="Scan an LLM response (Stage 2)")
def scan_output(request: ScanRequest):
    """
    Scan the LLM's response for PII leakage or prompt exfiltration
    before returning it to the user.
    Decision: BLOCK (suppress response) | WARN (redact + return) | ALLOW (safe)
    """
    result = output_scanner.scan(request)
    audit.log(result, scan_type="output")
    return result


@app.post("/v1/scan/rag", summary="Scan RAG documents for poisoning")
def scan_rag(request: RagScanRequest):
    """
    Scan a list of retrieved documents for embedded injection payloads
    before inserting them into the LLM context window.
    Returns per-document decisions — exclude poisoned docs from context.
    """
    result = rag_scanner.scan(request.documents)
    return result


@app.get("/v1/audit", summary="Retrieve audit log entries")
def get_audit(
    limit:           int            = Query(50,   ge=1, le=500),
    offset:          int            = Query(0,    ge=0),
    decision:        Optional[str]  = Query(None, description="Filter: BLOCK | WARN | ALLOW"),
    attack_category: Optional[str]  = Query(None, description="Filter by attack category"),
):
    """Paginated audit log with optional filters."""
    entries = audit.query(
        limit=limit,
        offset=offset,
        decision=decision,
        attack_category=attack_category,
    )
    return {"entries": [e.model_dump() for e in entries], "count": len(entries)}


@app.get("/v1/audit/stats", summary="Detection statistics")
def get_stats():
    """Aggregate statistics: total scans, block/warn/allow counts, by-category breakdown."""
    return audit.stats()
