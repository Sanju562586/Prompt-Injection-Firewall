import time
import asyncio
from typing import List, Optional, Tuple, Set

from .schemas import (
    Document,
    ScannedDocument,
    InjectedSpan,
    PoisoningType,
    DocumentRiskLevel,
    RAGScanRequest,
    RAGScanResult
)
from .detectors.indirect_patterns import INDIRECT_INJECTION_PATTERNS
from .detectors.structural_detector import StructuralDetector
from .sanitizer import DocumentSanitizer
try:
    from ..input_scanner.scanner import InputInjectionScanner
except (ImportError, ValueError):
    from input_scanner.scanner import InputInjectionScanner


class RAGPoisoningDetector:
    """
    Production-grade RAG Poisoning & Indirect Injection Scanner.
    Inspects knowledge chunks for trojan instructions and cleanly attributes
    malicious documents vs. innocent users.
    """

    def __init__(self, quarantine_threshold: float = 0.60):
        self.quarantine_threshold = quarantine_threshold
        self.indirect_patterns = INDIRECT_INJECTION_PATTERNS
        self.structural_detector = StructuralDetector()
        self.user_scanner = InputInjectionScanner()

    def scan_document(self, doc: Document, auto_sanitize: bool = True) -> ScannedDocument:
        """
        Scans an individual document or retrieved chunk for indirect prompt injections,
        data exfiltration triggers, and structural evasions.
        """
        text = doc.text
        spans: List[InjectedSpan] = []
        poisoning_types: Set[PoisoningType] = set()

        # 1. Structural Evasion Check (hidden comments, CSS, zero-width)
        structural_spans = self.structural_detector.scan(text)
        for s in structural_spans:
            spans.append(s)
            poisoning_types.add(s.poisoning_type)

        # 2. Indirect Injection Heuristics
        for pat in self.indirect_patterns:
            for match in pat["pattern"].finditer(text):
                p_type = pat["poisoning_type"]
                poisoning_types.add(p_type)
                spans.append(
                    InjectedSpan(
                        start_char=match.start(),
                        end_char=match.end(),
                        detected_text=match.group(0)[:120],
                        poisoning_type=p_type,
                        confidence=pat["confidence"],
                        rule_name=pat["name"]
                    )
                )

        # 3. Calculate Risk Score
        if not spans:
            risk_score = 0.0
            risk_level = DocumentRiskLevel.CLEAN
            is_poisoned = False
            sanitized_text = text
            quarantined = False
            explanation = "Document is clean and verified safe for context inclusion."
        else:
            max_conf = max(s.confidence for s in spans)
            span_count_bonus = min(0.15, 0.05 * (len(spans) - 1))
            risk_score = min(1.0, round(max_conf + span_count_bonus, 4))

            if risk_score >= 0.75:
                risk_level = DocumentRiskLevel.POISONED
                is_poisoned = True
            elif risk_score >= 0.40:
                risk_level = DocumentRiskLevel.SUSPICIOUS
                is_poisoned = True
            else:
                risk_level = DocumentRiskLevel.CLEAN
                is_poisoned = False

            # Sanitization logic
            sanitized_text = None
            is_salvageable = False
            if auto_sanitize and is_poisoned:
                sanitized_text, is_salvageable = DocumentSanitizer.sanitize(text, spans)

            quarantined = is_poisoned and not is_salvageable

            reasons = [s.rule_name for s in spans[:2]]
            explanation = f"Poisoned content detected ({', '.join(reasons)}). Risk score: {risk_score}."

        return ScannedDocument(
            doc_id=doc.id,
            is_poisoned=is_poisoned,
            risk_score=risk_score,
            risk_level=risk_level,
            poisoning_types=list(poisoning_types),
            injected_spans=spans,
            sanitized_text=sanitized_text,
            quarantined=quarantined,
            explanation=explanation
        )

    def scan(self, request: RAGScanRequest) -> RAGScanResult:
        """
        Scans a batch of retrieved documents and distinguishes document-level threats
        from active user threats.
        """
        start_time = time.perf_counter()

        safe_docs: List[Document] = []
        quarantined_docs: List[ScannedDocument] = []
        poisoned_count = 0

        # 1. Scan all documents in parallel or sequence
        for doc in request.documents:
            scanned = self.scan_document(doc, auto_sanitize=request.auto_sanitize)
            if scanned.is_poisoned:
                poisoned_count += 1
                quarantined_docs.append(scanned)

                # If sanitized text is salvageable and auto_sanitize is active, preserve safe version
                if request.auto_sanitize and scanned.sanitized_text and not scanned.quarantined:
                    safe_docs.append(
                        Document(
                            id=doc.id,
                            text=scanned.sanitized_text,
                            source=doc.source,
                            metadata={**doc.metadata, "sanitized": True}
                        )
                    )
            else:
                safe_docs.append(doc)

        # 2. Evaluate User vs Document Threat Attribution
        user_threat = False
        if request.user_query and request.user_query.strip():
            user_scan_result = self.user_scanner.scan(request.user_query)
            user_threat = not user_scan_result.is_safe

        document_threat = poisoned_count > 0

        # Formulate explicit entity attribution verdict
        if user_threat and document_threat:
            entity_verdict = (
                "CRITICAL ALERT: Dual threat detected. Active user query contains prompt injection, "
                "and retrieved knowledge context contains poisoned document payloads."
            )
        elif not user_threat and document_threat:
            entity_verdict = (
                "RAG POISONING DETECTED: Retrieved document(s) contain indirect injection or exfiltration directives. "
                "User query is benign and innocent. Flag document source for security remediation."
            )
        elif user_threat and not document_threat:
            entity_verdict = (
                "DIRECT INJECTION ATTEMPT: User query contains malicious injection or jailbreak instructions. "
                "Retrieved knowledge context is clean."
            )
        else:
            entity_verdict = "ALL CLEAR: User query and all retrieved knowledge documents verified safe."

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return RAGScanResult(
            all_clean=poisoned_count == 0 and not user_threat,
            total_scanned=len(request.documents),
            poisoned_count=poisoned_count,
            safe_documents=safe_docs,
            quarantined_documents=quarantined_docs,
            user_threat=user_threat,
            document_threat=document_threat,
            entity_verdict=entity_verdict,
            latency_ms=round(elapsed_ms, 2)
        )

    async def scan_async(self, request: RAGScanRequest) -> RAGScanResult:
        """Asynchronous document scanning wrapper."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.scan, request)
