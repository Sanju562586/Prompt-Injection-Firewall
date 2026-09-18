"""
Scanners Module — RAG Poisoning Scanner
Inspects retrieved context chunks for embedded prompt injections or hidden payloads
BEFORE they are concatenated into the LLM context window.
"""

from __future__ import annotations
from typing import List, Optional
from audit.models import Decision, RagDocument, RagScanResult, ScanRequest
from scanners.input_scanner import DEFAULT_INPUT_SCANNER, InputScanner


class RagScanner:
    """Detects document poisoning and indirect injection in retrieved chunks."""

    def __init__(self, scanner: Optional[InputScanner] = None):
        self.scanner = scanner or DEFAULT_INPUT_SCANNER

    def scan(self, documents: List[RagDocument]) -> RagScanResult:
        """
        Scan each document chunk. Returns aggregate poisoning stats and per-document analysis.
        """
        results = []
        poisoned_count = 0
        clean_count = 0

        for doc in documents:
            req = ScanRequest(
                text=doc.content,
                request_id=f"rag-{doc.doc_id}",
                metadata={"source": doc.source or "unknown"},
            )
            scan_res = self.scanner.scan(req)

            is_poisoned = scan_res.decision in (Decision.BLOCK, Decision.WARN)
            if is_poisoned:
                poisoned_count += 1
            else:
                clean_count += 1

            results.append({
                "doc_id": doc.doc_id,
                "source": doc.source,
                "decision": scan_res.decision.value,
                "score": scan_res.score,
                "risk_level": scan_res.risk_level.value,
                "reason": scan_res.reason,
                "snippet": doc.content[:100],
                "poisoned": is_poisoned,
            })

        return RagScanResult(
            poisoned_count=poisoned_count,
            clean_count=clean_count,
            results=results,
        )


# Global default instance and function
DEFAULT_RAG_SCANNER = RagScanner()


def scan(documents: List[RagDocument]) -> RagScanResult:
    """Convenience scan function for RAG document collections."""
    return DEFAULT_RAG_SCANNER.scan(documents)


# Alias for explicit imports
scan_rag = scan

