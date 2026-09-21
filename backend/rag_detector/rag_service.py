"""
Complete Production RAG Orchestrator with Integrated Security Firewall.
Implements the 7-stage HLD pipeline:
1. Input Injection Scanner
2. RAG Document Semantic Retrieval
3. RAG Poisoning Detector & Trojan Quarantine
4. Risk Engine Multi-Signal Synthesis
5. Contextual LLM Grounding & Forwarder
6. Output Scanner (PII / Secrets / Canary)
7. Cryptographic Audit Logging (SHA-256 Hash Chain)
"""

import time
import uuid
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from backend.input_scanner.scanner import InputInjectionScanner
from backend.rag_detector.rag_scanner import RAGPoisoningDetector
from backend.rag_detector.schemas import Document, RAGScanRequest, RAGScanResult
from backend.rag_detector.knowledge_base import KnowledgeBase, DocumentChunk
from backend.risk_engine.engine import RiskEngine
from backend.risk_engine.schemas import RiskAssessment, Decision, AttackSeverity
from backend.output_scanner.scanner import OutputScanner
from backend.output_scanner.schemas import OutputScanResult
from backend.audit_logger.logger import AuditLogger
from backend.audit_logger.schemas import AuditEventType


class SecurityAlertPayload(BaseModel):
    has_threat: bool = False
    alert_title: str
    threat_category: str
    severity: str
    risk_score: float
    decision: str
    violations: List[str] = Field(default_factory=list)
    quarantined_count: int = 0
    quarantined_titles: List[str] = Field(default_factory=list)
    action_taken: str


class RAGChatRequest(BaseModel):
    query: str
    chat_history: List[Dict[str, str]] = Field(default_factory=list)
    top_k: int = 3
    temperature: float = 0.7
    system_prompt: Optional[str] = None


class RAGChatResponse(BaseModel):
    answer: str
    sources: List[Dict[str, Any]]
    security_alert: Optional[SecurityAlertPayload] = None
    telemetry: Dict[str, Any]


class RAGService:
    """Production RAG Service protected by the LLM Security Firewall."""

    _instance = None

    def __init__(self):
        self.kb = KnowledgeBase.get_instance()
        self.input_scanner = InputInjectionScanner()
        self.rag_detector = RAGPoisoningDetector()
        self.risk_engine = RiskEngine()
        self.output_scanner = OutputScanner()
        self.audit_logger = AuditLogger.get_instance()
        from backend.gateway.proxy import DownstreamLLMProxy
        self.llm_proxy = DownstreamLLMProxy()

    @classmethod
    def get_instance(cls) -> "RAGService":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    async def execute_rag_chat(self, req: RAGChatRequest) -> RAGChatResponse:
        t_start = time.perf_counter()
        req_id = f"rag-req-{uuid.uuid4().hex[:8]}"
        violations: List[str] = []
        user_query = req.query.strip()

        # -------------------------------------------------------------
        # 1. Module 1: Input Injection Scanner
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        input_scan = self.input_scanner.scan(user_query)
        input_scan_ms = (time.perf_counter() - t0) * 1000.0

        rule_score = 0.0
        if input_scan.flagged_rules:
            rule_score = min(1.0, 0.4 + 0.2 * len(input_scan.flagged_rules))
            for r in input_scan.flagged_rules:
                violations.append(f"Inbound Prompt Rule: {r.name} ({r.severity.value})")

        if input_scan.ml_score >= 0.65:
            violations.append(f"Inbound Prompt ML Injection Score: {input_scan.ml_score:.2f}")

        # -------------------------------------------------------------
        # 2. RAG Semantic Retrieval
        # -------------------------------------------------------------
        retrieved_chunks = self.kb.retrieve(user_query, top_k=req.top_k)

        # -------------------------------------------------------------
        # 3. Module 2: RAG Document Scanner & Trojan Quarantine
        # -------------------------------------------------------------
        doc_risk_score = 0.0
        quarantined_chunks: List[DocumentChunk] = []
        safe_chunks: List[DocumentChunk] = []
        quarantined_titles: List[str] = []

        if retrieved_chunks:
            doc_objs = [
                Document(id=c.chunk_id, text=f"{c.title}\n{c.content}", metadata={"doc_id": c.doc_id, "title": c.title})
                for c in retrieved_chunks
            ]
            rag_req = RAGScanRequest(documents=doc_objs, user_query=user_query, auto_sanitize=True)
            rag_scan_res: RAGScanResult = self.rag_detector.scan(rag_req)

            poisoned_map = {q.doc_id: q for q in rag_scan_res.quarantined_documents}

            for chunk in retrieved_chunks:
                if chunk.chunk_id in poisoned_map:
                    q_doc = poisoned_map[chunk.chunk_id]
                    reasons = [f"{sp.poisoning_type.value}: {sp.rule_name}" for sp in q_doc.injected_spans]
                    chunk.is_safe = False
                    chunk.quarantine_reason = "; ".join(reasons)
                    quarantined_chunks.append(chunk)
                    quarantined_titles.append(chunk.title)
                    for sp in q_doc.injected_spans:
                        violations.append(f"RAG Document Poisoning: {sp.poisoning_type.value} in '{chunk.title}'")
                else:
                    safe_chunks.append(chunk)

            if not rag_scan_res.all_clean:
                doc_risk_score = min(1.0, 0.45 + 0.35 * (rag_scan_res.poisoned_count / max(1, rag_scan_res.total_scanned)))

        # -------------------------------------------------------------
        # 4. Module 3: Risk Engine Multi-Signal Synthesis
        # -------------------------------------------------------------
        attack_sev = AttackSeverity.NONE
        if input_scan.flagged_rules:
            sevs = [r.severity.value.upper() for r in input_scan.flagged_rules]
            if "CRITICAL" in sevs:
                attack_sev = AttackSeverity.CRITICAL
            elif "HIGH" in sevs:
                attack_sev = AttackSeverity.HIGH
            elif "MEDIUM" in sevs:
                attack_sev = AttackSeverity.MEDIUM
        elif quarantined_chunks:
            attack_sev = AttackSeverity.HIGH

        risk_assessment: RiskAssessment = self.risk_engine.assess_components(
            rule_score=rule_score,
            ml_score=input_scan.ml_score,
            pii_score=0.0,
            document_risk=doc_risk_score,
            output_risk=0.0,
            attack_severity=attack_sev,
            metadata={"query_len": len(user_query), "quarantined_docs": len(quarantined_chunks)}
        )

        # -------------------------------------------------------------
        # Check Decision: If BLOCK (Direct injection attack)
        # -------------------------------------------------------------
        if risk_assessment.decision == Decision.BLOCK:
            alert = SecurityAlertPayload(
                has_threat=True,
                alert_title="Direct Prompt Injection Blocked",
                threat_category="Prompt Injection / Jailbreak",
                severity=risk_assessment.risk_level.value,
                risk_score=round(risk_assessment.overall_risk, 3),
                decision="BLOCK",
                violations=violations,
                quarantined_count=len(quarantined_chunks),
                quarantined_titles=quarantined_titles,
                action_taken="Request blocked by LLM Firewall to protect downstream infrastructure.",
            )

            # Audit log
            self.audit_logger.log_event(
                event_type=AuditEventType.FIREWALL_BLOCK,
                request_id=req_id,
                risk_score=risk_assessment.overall_risk,
                risk_level=risk_assessment.risk_level.value,
                decision="BLOCK",
                input_text=user_query,
                violations=violations,
                latency_ms=(time.perf_counter() - t_start) * 1000.0,
                metadata={"attack_type": "Prompt Injection"}
            )

            return RAGChatResponse(
                answer="[LLM Firewall Interception: Request blocked due to high-risk prompt injection signatures.]",
                sources=[],
                security_alert=alert,
                telemetry={
                    "request_id": req_id,
                    "overall_risk": risk_assessment.overall_risk,
                    "risk_level": risk_assessment.risk_level.value,
                    "latency_ms": round((time.perf_counter() - t_start) * 1000.0, 2),
                    "action": "BLOCKED",
                }
            )

        # -------------------------------------------------------------
        # 5. LLM Grounded Generation (Using Safe Chunks Only)
        # -------------------------------------------------------------
        safe_context_texts = [f"Source [{c.title}]:\n{c.content}" for c in safe_chunks]
        system_instructions = (
            req.system_prompt
            or "You are ACME Corp's Enterprise AI Assistant. Provide accurate, helpful, and professional answers strictly grounded in the verified reference documents. If the documents do not contain the answer, politely state so."
        )

        from backend.gateway.schemas import ChatMessage
        messages = [ChatMessage(role="system", content=system_instructions)]
        for h in req.chat_history[-6:]:
            messages.append(ChatMessage(role=h.get("role", "user"), content=h.get("content", "")))
        messages.append(ChatMessage(role="user", content=user_query))

        # Generate answer
        raw_completion, _ = await self.llm_proxy.generate_completion(
            model="gpt-4o",
            messages=messages,
            documents=safe_context_texts if safe_context_texts else None,
            temperature=req.temperature,
            max_tokens=1024,
        )

        # Completion generated dynamically via LLM proxy

        # -------------------------------------------------------------
        # 6. Module 4: Output Scanner
        # -------------------------------------------------------------
        output_scan: OutputScanResult = self.output_scanner.scan(
            output_text=raw_completion,
            system_prompt=system_instructions,
            context_documents=safe_context_texts if safe_context_texts else None,
        )

        final_answer = output_scan.sanitized_text if output_scan.sanitized_text else raw_completion

        if output_scan.blocked:
            for v in output_scan.violations:
                violations.append(f"Output Leak Violation: {v.violation_type.value} - {v.description}")
            final_answer = "[LLM Firewall: Outbound response blocked due to sensitive data / canary leakage.]"

        # -------------------------------------------------------------
        # 7. Check if Threat Alert Needed (e.g. Quarantined Trojan Docs)
        # -------------------------------------------------------------
        security_alert = None
        has_threat = len(quarantined_chunks) > 0 or len(violations) > 0 or risk_assessment.overall_risk >= 0.30

        if has_threat:
            if quarantined_chunks:
                alert_title = "Poisoned Knowledge Document Quarantined"
                category = "Indirect RAG Poisoning"
                action_taken = (
                    f"Quarantined {len(quarantined_chunks)} malicious document(s) from context. "
                    "Grounded response safely generated using remaining verified documents only."
                )
            else:
                alert_title = "Suspicious Content Flagged"
                category = "Policy & Heuristic Alert"
                action_taken = "Request processed under heightened monitoring."

            security_alert = SecurityAlertPayload(
                has_threat=True,
                alert_title=alert_title,
                threat_category=category,
                severity=risk_assessment.risk_level.value,
                risk_score=round(risk_assessment.overall_risk, 3),
                decision=risk_assessment.decision.value,
                violations=violations,
                quarantined_count=len(quarantined_chunks),
                quarantined_titles=quarantined_titles,
                action_taken=action_taken,
            )

        # -------------------------------------------------------------
        # 8. Cryptographic Audit Logging
        # -------------------------------------------------------------
        total_latency = (time.perf_counter() - t_start) * 1000.0
        evt_type = AuditEventType.SECURITY_ALERT if quarantined_chunks else AuditEventType.FIREWALL_ALLOW
        self.audit_logger.log_event(
            event_type=evt_type,
            request_id=req_id,
            risk_score=risk_assessment.overall_risk,
            risk_level=risk_assessment.risk_level.value,
            decision=risk_assessment.decision.value,
            input_text=user_query,
            violations=violations,
            latency_ms=total_latency,
            metadata={"quarantined_count": len(quarantined_chunks), "sources_count": len(retrieved_chunks)}
        )

        # Prepare source summaries for UI
        sources_payload = []
        for c in retrieved_chunks:
            sources_payload.append({
                "chunk_id": c.chunk_id,
                "doc_id": c.doc_id,
                "title": c.title,
                "category": c.category,
                "score": c.score,
                "is_safe": c.is_safe,
                "quarantine_reason": c.quarantine_reason,
                "snippet": c.content[:180] + "..." if len(c.content) > 180 else c.content,
            })

        return RAGChatResponse(
            answer=final_answer,
            sources=sources_payload,
            security_alert=security_alert,
            telemetry={
                "request_id": req_id,
                "overall_risk": risk_assessment.overall_risk,
                "risk_level": risk_assessment.risk_level.value,
                "latency_ms": round(total_latency, 2),
                "quarantined_docs": len(quarantined_chunks),
                "action": "QUARANTINE_SAFE" if quarantined_chunks else "ALLOW",
            }
        )
