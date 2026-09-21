"""
Unified Firewall Pipeline Orchestrator.
Chains Input Scanner -> RAG Poisoning Detector -> Risk Engine -> LLM Proxy -> Output Scanner.
"""

import time
from typing import List, Optional, Tuple
from backend.input_scanner.scanner import InputInjectionScanner
from backend.rag_detector.rag_scanner import RAGPoisoningDetector
from backend.rag_detector.schemas import Document, RAGScanRequest, RAGScanResult
from backend.risk_engine.engine import RiskEngine
from backend.risk_engine.schemas import RiskAssessment, Decision, AttackSeverity
from backend.output_scanner.scanner import OutputScanner
from backend.output_scanner.schemas import OutputScanResult
from backend.gateway.schemas import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatChoice,
    ChatMessage,
    SecurityTelemetry,
    SecurityBlockedResponse,
)
from backend.gateway.proxy import DownstreamLLMProxy


class SecurityPipeline:
    """End-to-end security orchestrator protecting inbound prompts, RAG data, and outbound completions."""

    def __init__(
        self,
        input_scanner: Optional[InputInjectionScanner] = None,
        rag_detector: Optional[RAGPoisoningDetector] = None,
        risk_engine: Optional[RiskEngine] = None,
        output_scanner: Optional[OutputScanner] = None,
        llm_proxy: Optional[DownstreamLLMProxy] = None,
    ):
        self.input_scanner = input_scanner or InputInjectionScanner()
        self.rag_detector = rag_detector or RAGPoisoningDetector()
        self.risk_engine = risk_engine or RiskEngine()
        self.output_scanner = output_scanner or OutputScanner()
        self.llm_proxy = llm_proxy or DownstreamLLMProxy()

    async def execute(
        self,
        request: ChatCompletionRequest,
        request_id: str,
    ) -> Tuple[bool, Optional[ChatCompletionResponse], Optional[SecurityBlockedResponse]]:
        """
        Executes full security pipeline.
        Returns: (success_flag, chat_response_if_allowed, blocked_response_if_blocked)
        """
        t_start = time.perf_counter()
        violations: List[str] = []

        # Extract user prompt (last user message)
        user_messages = [m for m in request.messages if m.role.lower() == "user"]
        target_prompt = user_messages[-1].content if user_messages else ""
        system_messages = [m for m in request.messages if m.role.lower() == "system"]
        system_prompt = system_messages[0].content if system_messages else None

        # -------------------------------------------------------------
        # 1. Module 1: Input Injection Scanner
        # -------------------------------------------------------------
        t0 = time.perf_counter()
        input_scan = self.input_scanner.scan(target_prompt)
        input_scan_ms = (time.perf_counter() - t0) * 1000.0

        rule_score = 0.0
        if input_scan.flagged_rules:
            rule_score = min(1.0, 0.4 + 0.2 * len(input_scan.flagged_rules))
            for r in input_scan.flagged_rules:
                violations.append(f"Input Rule: {r.name} ({r.severity.value})")

        if input_scan.ml_score >= 0.5:
            violations.append(f"Input ML Injection Confidence: {input_scan.ml_score:.2f}")

        # -------------------------------------------------------------
        # 2. Module 2: RAG Poisoning Detector
        # -------------------------------------------------------------
        rag_scan_ms = 0.0
        doc_risk_score = 0.0
        sanitized_documents = request.documents or []

        if request.documents and len(request.documents) > 0:
            t1 = time.perf_counter()
            doc_objs = [Document(id=f"doc_{idx}", text=txt) for idx, txt in enumerate(request.documents)]
            rag_req = RAGScanRequest(documents=doc_objs, user_query=target_prompt, auto_sanitize=True)
            rag_result: RAGScanResult = self.rag_detector.scan(rag_req)
            rag_scan_ms = (time.perf_counter() - t1) * 1000.0

            if not rag_result.all_clean:
                doc_risk_score = min(1.0, 0.4 + 0.3 * (rag_result.poisoned_count / max(1, rag_result.total_scanned)))
                for qdoc in rag_result.quarantined_documents:
                    for span in qdoc.injected_spans:
                        violations.append(f"RAG Poisoning: {span.poisoning_type.value} in {qdoc.doc_id}")

                sanitized_documents = [d.text for d in rag_result.safe_documents]

        # -------------------------------------------------------------
        # 3. Module 3: Risk Engine Synthesis
        # -------------------------------------------------------------
        attack_sev = AttackSeverity.NONE
        if input_scan.flagged_rules:
            severities = [r.severity.value.upper() for r in input_scan.flagged_rules]
            if "CRITICAL" in severities:
                attack_sev = AttackSeverity.CRITICAL
            elif "HIGH" in severities:
                attack_sev = AttackSeverity.HIGH
            elif "MEDIUM" in severities:
                attack_sev = AttackSeverity.MEDIUM

        risk_assessment: RiskAssessment = self.risk_engine.assess_components(
            rule_score=rule_score,
            ml_score=input_scan.ml_score,
            pii_score=0.0,
            document_risk=doc_risk_score,
            output_risk=0.0,
            attack_severity=attack_sev,
            metadata={"prompt_len": len(target_prompt), "num_docs": len(request.documents or [])}
        )

        # Inbound Gating: Check Decision
        if risk_assessment.decision == Decision.BLOCK:
            blocked = SecurityBlockedResponse(
                status_code=403,
                request_id=request_id,
                risk_score=risk_assessment.overall_risk,
                risk_level=risk_assessment.risk_level,
                decision=risk_assessment.decision,
                reason=f"Inbound payload flagged with {risk_assessment.risk_level.value} risk. {risk_assessment.explanation}",
                violations=violations,
            )
            return False, None, blocked

        # -------------------------------------------------------------
        # 4. Downstream LLM Invocation
        # -------------------------------------------------------------
        prompt_to_forward = input_scan.sanitized_text if input_scan.sanitized_text else target_prompt
        forward_messages = []
        for m in request.messages:
            if m.role.lower() == "user" and m == user_messages[-1]:
                forward_messages.append(ChatMessage(role=m.role, content=prompt_to_forward))
            else:
                forward_messages.append(m)

        raw_completion, usage = await self.llm_proxy.generate_completion(
            model=request.model,
            messages=forward_messages,
            documents=sanitized_documents if sanitized_documents else None,
            temperature=request.temperature or 0.7,
            max_tokens=request.max_tokens or 1024,
        )

        # -------------------------------------------------------------
        # 5. Module 4: Output Scanner
        # -------------------------------------------------------------
        t2 = time.perf_counter()
        output_scan: OutputScanResult = self.output_scanner.scan(
            output_text=raw_completion,
            system_prompt=system_prompt,
            context_documents=sanitized_documents if sanitized_documents else None,
        )
        output_scan_ms = (time.perf_counter() - t2) * 1000.0

        if output_scan.blocked:
            for v in output_scan.violations:
                violations.append(f"Output Security Violation: {v.violation_type.value} - {v.description}")
            blocked = SecurityBlockedResponse(
                status_code=403,
                request_id=request_id,
                risk_score=output_scan.output_risk_score,
                risk_level=risk_assessment.risk_level,
                decision=Decision.BLOCK,
                reason=output_scan.block_reason or "Output blocked due to critical outbound policy violation",
                violations=violations,
            )
            return False, None, blocked

        # Final delivered output (redacted/sanitized if needed)
        final_content = output_scan.sanitized_text if output_scan.sanitized_text is not None else raw_completion

        total_pipeline_ms = (time.perf_counter() - t_start) * 1000.0

        security_meta = SecurityTelemetry(
            request_id=request_id,
            risk_score=risk_assessment.overall_risk,
            risk_level=risk_assessment.risk_level,
            decision=risk_assessment.decision,
            input_scan_ms=round(input_scan_ms, 2),
            rag_scan_ms=round(rag_scan_ms, 2),
            output_scan_ms=round(output_scan_ms, 2),
            total_pipeline_ms=round(total_pipeline_ms, 2),
            input_flagged=not input_scan.is_safe,
            rag_flagged=doc_risk_score > 0.3,
            output_flagged=not output_scan.is_safe,
            violations=violations,
            explanation=risk_assessment.explanation,
        )

        response = ChatCompletionResponse(
            model=request.model,
            choices=[
                ChatChoice(
                    index=0,
                    message=ChatMessage(role="assistant", content=final_content),
                    finish_reason="stop"
                )
            ],
            usage=usage,
            security=security_meta,
        )

        return True, response, None
