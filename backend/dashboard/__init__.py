"""
Dashboard Module.
Interactive mission control, real-time telemetry stats, live attack sandbox, and red-team trigger.
"""

from backend.dashboard.schemas import (
    DashboardStats,
    SimulationRequest,
    SimulationResponse,
)
from backend.dashboard.service import DashboardService
from backend.dashboard.routes import router

__all__ = [
    "DashboardStats",
    "SimulationRequest",
    "SimulationResponse",
    "DashboardService",
    "router",
]
