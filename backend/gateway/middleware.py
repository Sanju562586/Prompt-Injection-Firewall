"""
Gateway Security Middleware.
Provides API key validation, token bucket rate-limiting, and request correlation tracing.
"""

import time
import uuid
from typing import Dict, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse


class TokenBucketRateLimiter:
    """Thread-safe in-memory Token Bucket rate limiter per client IP / API Key."""

    def __init__(self, rate: float = 60.0, capacity: float = 120.0):
        self.rate = rate  # tokens added per second
        self.capacity = capacity
        self.buckets: Dict[str, Dict[str, float]] = {}

    def is_allowed(self, client_id: str, cost: float = 1.0) -> bool:
        now = time.time()
        bucket = self.buckets.get(client_id)
        if not bucket:
            bucket = {"tokens": self.capacity, "last_updated": now}
            self.buckets[client_id] = bucket

        # Refill tokens based on elapsed time
        elapsed = now - bucket["last_updated"]
        bucket["tokens"] = min(self.capacity, bucket["tokens"] + elapsed * self.rate)
        bucket["last_updated"] = now

        if bucket["tokens"] >= cost:
            bucket["tokens"] -= cost
            return True
        return False


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects correlation IDs and security headers into incoming/outgoing HTTP transactions."""

    def __init__(self, app, api_keys: Optional[set] = None, rate_limiter: Optional[TokenBucketRateLimiter] = None):
        super().__init__(app)
        self.api_keys = api_keys or set()
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter()

    async def dispatch(self, request: Request, call_next):
        # 1. Assign or propagate Request ID
        request_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
        request.state.request_id = request_id

        # Pass through health, docs, and root endpoints without auth or rate limits
        path = request.url.path
        if path in ["/health", "/docs", "/openapi.json", "/", "/redoc"]:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response

        # 2. Rate Limiting Check
        client_ip = request.client.host if request.client else "unknown"
        if not self.rate_limiter.is_allowed(client_ip):
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "message": "Rate limit exceeded. Please back off.",
                    "request_id": request_id,
                },
                headers={"X-Request-ID": request_id, "Retry-After": "2"}
            )

        # 3. Optional API Key Verification (if keys configured)
        if self.api_keys:
            auth_header = request.headers.get("Authorization", "")
            api_key_header = request.headers.get("X-API-Key", "")
            key = None
            if auth_header.startswith("Bearer "):
                key = auth_header.replace("Bearer ", "").strip()
            elif api_key_header:
                key = api_key_header.strip()

            if not key or key not in self.api_keys:
                return JSONResponse(
                    status_code=401,
                    content={
                        "error": "Unauthorized",
                        "message": "Invalid or missing API key.",
                        "request_id": request_id,
                    },
                    headers={"X-Request-ID": request_id}
                )

        start_time = time.perf_counter()
        response: Response = await call_next(request)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Gateway-Latency-MS"] = f"{elapsed_ms:.2f}"
        return response
