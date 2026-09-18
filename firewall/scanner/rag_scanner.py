"""
RAG Poisoning Scanner
Scans each retrieved document chunk for embedded injection payloads
BEFORE they are inserted into the LLM context window.

This is critical: RAG poisoning is the most overlooked injection vector.
An attacker can upload a document with hidden instructions that manipulate
the LLM when the document is retrieved.

Strategy:
  - Run Pattern detector (Layer 1) on every document chunk
  - Run Semantic detector (Layer 2) on chunks that pass Layer 1
  - Flag poisoned chunks so the caller can exclude them from context
"""

from __future__ import annotations
from firewall.models import RagDocument, RagScanResult, ScanRequest
from firewall.scanner import input_scanner


def scan(documents: list[RagDocument]) -> RagScanResult:
    """
    Scan a list of RAG-retrieved documents for injection payloads.
    Returns a summary with per-document decisions.
    """
    results = []
    poisoned = 0
    clean    = 0

    for doc in documents:
        # Re-use the input scanner on each document chunk's content
        scan_result = input_scanner.scan(
            ScanRequest(text=doc.content, request_id=f"rag-{doc.doc_id}")
        )

        is_poisoned = scan_result.decision.value in ("BLOCK", "WARN")
        if is_poisoned:
            poisoned += 1
        else:
            clean += 1

        results.append({
            "doc_id":    doc.doc_id,
            "source":    doc.source,
            "decision":  scan_result.decision.value,
            "score":     scan_result.score,
            "reason":    scan_result.reason,
            "snippet":   doc.content[:80],
            "poisoned":  is_poisoned,
        })

    return RagScanResult(
        poisoned_count=poisoned,
        clean_count=clean,
        results=results,
    )
