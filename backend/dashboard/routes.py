"""
Dashboard API Routes.
Exposes telemetry, rules management, live interactive simulator, and web dashboard endpoints.
"""

import os
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Query
from fastapi.responses import HTMLResponse, JSONResponse
from backend.dashboard.schemas import SimulationRequest
from backend.dashboard.service import DashboardService

router = APIRouter()
service = DashboardService()


@router.get("/api/dashboard/stats", tags=["Dashboard"])
async def get_dashboard_stats():
    """Returns aggregated firewall health and threat statistics."""
    return service.get_stats().model_dump()


@router.get("/api/dashboard/events", tags=["Dashboard"])
async def get_audit_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = None,
    risk_level: Optional[str] = None,
):
    """Returns paginated and filtered audit events."""
    return service.get_events(limit=limit, offset=offset, decision=decision, risk_level=risk_level)


@router.get("/api/dashboard/rules", tags=["Dashboard"])
async def list_active_rules():
    """Lists configured regex rules, confidence weights, and severities."""
    return service.get_rules()


@router.post("/api/dashboard/simulate", tags=["Dashboard"])
async def simulate_threat(req: SimulationRequest):
    """Executes live simulation and returns layered defense breakdown."""
    res = await service.simulate(req)
    return res.model_dump()


@router.post("/api/dashboard/benchmark", tags=["Dashboard"])
async def run_benchmark():
    """Triggers automated Red-Team evaluation suite and returns empirical metrics."""
    report = await service.run_benchmark()
    return report.model_dump()


@router.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard UI"])
async def serve_dashboard_ui():
    """Serves the interactive single-page dashboard UI."""
    html_path = Path(__file__).parent / "static" / "index.html"
    if html_path.exists():
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Prompt Injection Firewall Dashboard</h1><p>UI loading...</p>")
