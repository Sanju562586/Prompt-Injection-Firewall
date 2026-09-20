from dataclasses import dataclass
from typing import Optional


@dataclass
class ModelConfig:
    """Configuration for DeBERTa Prompt Injection Classifier."""
    model_name: str = "ProtectAI/deberta-v3-base-prompt-injection-v2"
    device: Optional[str] = None  # None for auto (cuda/cpu)
    max_length: int = 512
    batch_size: int = 8
    # Threshold above which ML considers text an injection
    injection_threshold: float = 0.50
    # Enable fallback heuristic model if weights/libraries are unavailable
    allow_fallback: bool = True
