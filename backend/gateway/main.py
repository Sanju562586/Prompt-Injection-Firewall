"""
FastAPI Gateway Application Entrypoint.
Initializes FastAPI, binds CORS, security headers, rate limiting, and mounts API routes and Dashboard.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from backend.gateway.middleware import SecurityHeadersMiddleware, TokenBucketRateLimiter
from backend.gateway.routes import router as gateway_router
from backend.dashboard.routes import router as dashboard_router

def create_app() -> FastAPI:
    """Factory function for FastAPI LLM Security Firewall application."""
    app = FastAPI(
        title="Prompt Injection Firewall & Security Gateway",
        description="Comprehensive Enterprise LLM Defense Gateway: Input Scanner, RAG Detector, Risk Engine, Output Scanner, Audit Logger, Red-Team, and Dashboard.",
        version="1.0.0",
    )

    # Enable CORS for frontend dashboard and external clients
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Attach Security, correlation ID, and rate-limiting middleware
    app.add_middleware(
        SecurityHeadersMiddleware,
        rate_limiter=TokenBucketRateLimiter(rate=100.0, capacity=200.0),
    )

    # Mount API routes and Dashboard
    app.include_router(gateway_router)
    app.include_router(dashboard_router)

    @app.get("/", tags=["System"])
    async def root():
        return RedirectResponse(url="/dashboard")

    return app

app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.gateway.main:app", host="0.0.0.0", port=8000, reload=True)
