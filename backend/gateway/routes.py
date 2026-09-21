"""
Gateway API Routes.
Exposes endpoints for chat completions, direct component scanning, and pipeline telemetry.
"""

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from backend.gateway.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    SecurityBlockedResponse,
    DirectScanInputRequest,
    DirectScanRagRequest,
    DirectScanOutputRequest,
    DirectRiskEvalRequest,
)
from backend.gateway.pipeline import SecurityPipeline
from backend.rag_detector.schemas import Document, RAGScanRequest
from backend.risk_engine.schemas import AttackSeverity

router = APIRouter()
pipeline = SecurityPipeline()


@router.get("/health", tags=["System"])
async def health_check():
    """Health check and module readiness probe."""
    return {
        "status": "healthy",
        "service": "Prompt Injection Firewall Gateway",
        "version": "1.0.0",
        "active_modules": [
            "Module 1: Input Injection Scanner",
            "Module 2: RAG Poisoning Detector",
            "Module 3: Risk Engine",
            "Module 4: Output Scanner",
            "Module 5: Security Gateway",
        ]
    }


@router.post("/v1/chat/completions", tags=["Chat"])
async def chat_completions(request: ChatCompletionRequest, http_req: Request):
    """
    OpenAI-compatible chat completion proxy.
    Guards inbound prompt and RAG context, and scrubs outbound completions for leaks.
    """
    req_id = getattr(http_req.state, "request_id", "req-default")
    success, completion_res, blocked_res = await pipeline.execute(request, req_id)

    if not success and blocked_res:
        return JSONResponse(
            status_code=blocked_res.status_code,
            content=blocked_res.model_dump(),
        )

    return completion_res


@router.post("/v1/scan/input", tags=["Direct Scans"])
async def scan_input_prompt(req: DirectScanInputRequest):
    """Direct standalone invocation of Module 1 (Input Injection Scanner)."""
    result = pipeline.input_scanner.scan(req.prompt)
    return result.model_dump()


@router.post("/v1/scan/rag", tags=["Direct Scans"])
async def scan_rag_documents(req: DirectScanRagRequest):
    """Direct standalone invocation of Module 2 (RAG Poisoning Detector)."""
    doc_objs = [Document(id=f"doc_{i}", text=t) for i, t in enumerate(req.documents)]
    rag_req = RAGScanRequest(documents=doc_objs)
    result = pipeline.rag_detector.scan(rag_req)
    return result.model_dump()


@router.post("/v1/scan/output", tags=["Direct Scans"])
async def scan_output_text(req: DirectScanOutputRequest):
    """Direct standalone invocation of Module 4 (Output Scanner)."""
    result = pipeline.output_scanner.scan(
        output_text=req.output_text,
        system_prompt=req.system_prompt,
        context_documents=req.context_documents,
    )
    return result.model_dump()


@router.post("/v1/risk/evaluate", tags=["Risk Engine"])
async def evaluate_risk(req: DirectRiskEvalRequest):
    """Direct standalone invocation of Module 3 (Risk Engine)."""
    severity_map = {
        "LOW": AttackSeverity.LOW,
        "MEDIUM": AttackSeverity.MEDIUM,
        "HIGH": AttackSeverity.HIGH,
        "CRITICAL": AttackSeverity.CRITICAL,
    }
    sev = severity_map.get((req.attack_severity or "HIGH").upper(), AttackSeverity.HIGH)
    assessment = pipeline.risk_engine.assess_components(
        rule_score=req.rule_score,
        ml_score=req.ml_score,
        pii_score=req.pii_score,
        document_risk=req.document_risk,
        output_risk=req.output_risk,
        attack_severity=sev,
    )
    return assessment.model_dump()
