"""
Gateway Module — LLM Reverse Proxy
Drop-in reverse proxy that intercepts OpenAI-compatible chat completion calls,
enforces pre-call prompt defense, forwards clean requests to upstream LLMs,
and validates post-call completions against PII & exfiltration.
"""

from __future__ import annotations
import os
import time
import httpx
from typing import Any, Dict
from fastapi import HTTPException
from starlette.responses import JSONResponse

from audit.logger import AuditLogger
from audit.models import Decision, ProxyChatRequest, ScanRequest
from config import CONFIG
from scanners.input_scanner import scan_input
from scanners.output_scanner import scan_output

UPSTREAM_CFG = CONFIG.get("gateway", {}).get("upstream_llm", {})
UPSTREAM_URL = UPSTREAM_CFG.get("url", "https://api.openai.com/v1")
TIMEOUT_SECONDS = UPSTREAM_CFG.get("timeout_seconds", 30.0)
API_KEY_VAR = UPSTREAM_CFG.get("api_key_env_var", "OPENAI_API_KEY")


class LLMProxy:
    """Reverse proxy with dual-stage firewall interception."""

    def __init__(self, audit_logger: AuditLogger | None = None):
        self.audit = audit_logger or AuditLogger()
        self.upstream_url = UPSTREAM_URL.rstrip("/")
        self.timeout = TIMEOUT_SECONDS

    def _extract_prompt_text(self, request: ProxyChatRequest) -> str:
        """Extract user messages to scan."""
        user_parts = [m.content for m in request.messages if m.role in ("user", "system")]
        return "\n".join(user_parts) if user_parts else ""

    async def forward_chat(self, chat_req: ProxyChatRequest, client_headers: Dict[str, str], request_id: str) -> JSONResponse:
        """
        Intercepts chat completion request:
          1. Stage 1 Input Scan
          2. Forward to Upstream LLM (if allowed)
          3. Stage 2 Output Scan
          4. Return audited & validated response
        """
        prompt_text = self._extract_prompt_text(chat_req)

        # ─── Stage 1: Input Scan ─────────────────────────────────────────────
        input_scan_res = scan_input(ScanRequest(text=prompt_text, request_id=request_id))
        self.audit.log(input_scan_res, scan_type="proxy-input")

        if input_scan_res.decision == Decision.BLOCK:
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": f"Blocked by LLM Firewall: {input_scan_res.reason}",
                        "type": "firewall_rejection",
                        "code": "prompt_injection_detected",
                        "category": input_scan_res.attack_category.value,
                        "risk_level": input_scan_res.risk_level.value,
                        "score": input_scan_res.score,
                    }
                },
            )

        # ─── Forward to Upstream LLM ─────────────────────────────────────────
        api_key = client_headers.get("authorization") or f"Bearer {os.environ.get(API_KEY_VAR, '')}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": api_key,
        }

        target_url = f"{self.upstream_url}/chat/completions"
        payload = chat_req.model_dump(exclude_none=True)

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                upstream_resp = await client.post(target_url, json=payload, headers=headers)
                status_code = upstream_resp.status_code
                data = upstream_resp.json()
        except Exception as exc:
            # If upstream is unreachable (e.g. mock test or offline mode), return formatted mock response
            return JSONResponse(
                status_code=502,
                content={
                    "error": {
                        "message": f"Upstream LLM unavailable: {exc}",
                        "type": "upstream_error",
                    }
                },
            )

        if status_code != 200:
            return JSONResponse(status_code=status_code, content=data)

        # ─── Stage 2: Output Scan ────────────────────────────────────────────
        response_text = ""
        choices = data.get("choices", [])
        if choices and "message" in choices[0]:
            response_text = choices[0]["message"].get("content", "")

        output_scan_res = scan_output(ScanRequest(text=response_text, request_id=request_id))
        self.audit.log(output_scan_res, scan_type="proxy-output")

        if output_scan_res.decision == Decision.BLOCK:
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": f"LLM response suppressed by firewall: {output_scan_res.reason}",
                        "type": "output_sanitization_block",
                        "category": output_scan_res.attack_category.value,
                        "risk_level": output_scan_res.risk_level.value,
                    }
                },
            )

        # Redact PII in response if flagged with WARN and redacted text generated
        if output_scan_res.redacted_text and choices:
            choices[0]["message"]["content"] = output_scan_res.redacted_text

        return JSONResponse(status_code=200, content=data)
