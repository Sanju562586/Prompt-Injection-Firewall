"""
Compatibility shim: re-exports from scanners.rag_scanner
"""

from scanners.rag_scanner import scan, RagScanner, DEFAULT_RAG_SCANNER

__all__ = ["scan", "RagScanner", "DEFAULT_RAG_SCANNER"]
