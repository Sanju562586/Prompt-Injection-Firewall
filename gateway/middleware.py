"""
Gateway Module — Security & Telemetry Middleware
Provides request correlation tracing, response timing headers, security headers, and CORS.
"""

from __future__ import annotations
import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Appends security headers to all responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class RequestTracingMiddleware(BaseHTTPMiddleware):
    """Assigns or propagates X-Request-ID and tracks latency in X-Response-Time."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id

        start_time = time.perf_counter()
        response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time"] = f"{elapsed_ms:.2f}ms"
        return response
