"""
Configuration loader for the LLM Firewall.
Reads config/config.yaml with environment variable overrides.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Dict

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"

_DEFAULT_CONFIG: Dict[str, Any] = {
    "gateway": {
        "host": "0.0.0.0",
        "port": 8000,
        "cors_origins": ["*"],
        "upstream_llm": {
            "url": "https://api.openai.com/v1",
            "timeout_seconds": 30.0,
            "api_key_env_var": "OPENAI_API_KEY",
        },
    },
    "scanners": {
        "input": {"enabled": True, "thresholds": {"block": 0.80, "warn": 0.55}, "short_circuit": True},
        "output": {"enabled": True, "check_exfiltration": True, "check_pii": True, "thresholds": {"block": 0.80, "warn": 0.55}},
        "rag": {"enabled": True, "block_poisoned_chunks": True},
        "pii": {
            "enabled": True,
            "sensitive_entities": ["EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD", "CRYPTO", "IBAN_CODE", "IP_ADDRESS", "API_KEY"],
            "ignore_general_locations": True,
            "anonymize_mode": "mask",
        },
    },
    "detection": {
        "rules": {"enabled": True, "block_score": 0.95},
        "semantic": {"enabled": True, "model_name": "all-MiniLM-L6-v2", "thresholds": {"block": 0.78, "warn": 0.60}},
        "classifier": {"enabled": True, "model_name": "protectai/deberta-v3-base-prompt-injection-v2", "block_score": 0.80},
        "risk_engine": {
            "weights": {"rules": 0.45, "semantic": 0.35, "classifier": 0.40},
            "thresholds": {"critical": 0.85, "high": 0.75, "medium": 0.50, "low": 0.25},
        },
    },
    "audit": {
        "database_path": "data/audit.db",
        "max_snippet_length": 120,
        "query_page_size": 50,
    },
    "dashboard": {
        "port": 8501,
        "theme": "dark",
    },
}


def _deep_merge(base: dict, update: dict) -> dict:
    """Recursively merge update dict into base dict."""
    result = dict(base)
    for key, value in update.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: str | Path | None = None) -> Dict[str, Any]:
    """
    Load configuration from YAML file and apply environment variable overrides.
    """
    path = Path(config_path or os.environ.get("FIREWALL_CONFIG_PATH", DEFAULT_CONFIG_PATH))
    config = dict(_DEFAULT_CONFIG)

    if path.exists():
        try:
            import yaml
            with open(path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    config = _deep_merge(config, loaded)
        except Exception:
            # Fall back to default config if yaml parser fails or file unreadable
            pass

    # Environment variable overrides
    if "FIREWALL_DB_PATH" in os.environ:
        config.setdefault("audit", {})["database_path"] = os.environ["FIREWALL_DB_PATH"]
    if "FIREWALL_PORT" in os.environ:
        try:
            config.setdefault("gateway", {})["port"] = int(os.environ["FIREWALL_PORT"])
        except ValueError:
            pass
    if "UPSTREAM_LLM_URL" in os.environ:
        config.setdefault("gateway", {}).setdefault("upstream_llm", {})["url"] = os.environ["UPSTREAM_LLM_URL"]

    return config


# Global cached config instance
CONFIG = load_config()
