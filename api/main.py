"""
FastAPI Gateway shim: re-exports app from gateway.api
"""

from gateway.api import app

__all__ = ["app"]
