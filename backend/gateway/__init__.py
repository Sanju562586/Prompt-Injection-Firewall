"""
Gateway Module.
OpenAI-compatible security reverse proxy and API interface.
"""

from backend.gateway.schemas import (
    ChatMessage,
    ChatCompletionRequest,
    ChatCompletionResponse,
    SecurityBlockedResponse,
    SecurityTelemetry,
)
from backend.gateway.pipeline import SecurityPipeline
from backend.gateway.main import app, create_app

__all__ = [
    "ChatMessage",
    "ChatCompletionRequest",
    "ChatCompletionResponse",
    "SecurityBlockedResponse",
    "SecurityTelemetry",
    "SecurityPipeline",
    "app",
    "create_app",
]
