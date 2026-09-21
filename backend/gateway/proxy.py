"""
Downstream LLM Proxy Client.
Handles communication with upstream LLMs (OpenAI, Anthropic, Azure, Local models) or mock provider.
"""

import os
from typing import List, Optional
from backend.gateway.schemas import ChatMessage, ChatChoice, UsageInfo


class DownstreamLLMProxy:
    """Proxies sanitized requests to target LLM provider or local simulator."""

    def __init__(self, provider: str = "mock", api_key: Optional[str] = None):
        self.provider = provider or os.getenv("LLM_PROVIDER", "mock")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")

    async def generate_completion(
        self,
        model: str,
        messages: List[ChatMessage],
        documents: Optional[List[str]] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
    ) -> tuple[str, UsageInfo]:
        """Dispatches request to configured provider and returns (output_text, usage)."""
        # If running in mock / test mode
        if self.provider == "mock" or not self.api_key:
            return self._generate_mock_response(model, messages, documents)

        # In live OpenAI/compatible mode:
        try:
            import httpx
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            # Combine documents into context if provided
            payload_messages = []
            if documents:
                context_str = "\n---\n".join(documents)
                payload_messages.append({"role": "system", "content": f"Reference Context:\n{context_str}"})

            for m in messages:
                payload_messages.append({"role": m.role, "content": m.content})

            payload = {
                "model": model,
                "messages": payload_messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                res = await client.post("https://api.openai.com/v1/chat/completions", headers=headers, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    content = data["choices"][0]["message"]["content"]
                    usage_data = data.get("usage", {})
                    usage = UsageInfo(
                        prompt_tokens=usage_data.get("prompt_tokens", 0),
                        completion_tokens=usage_data.get("completion_tokens", 0),
                        total_tokens=usage_data.get("total_tokens", 0),
                    )
                    return content, usage
        except Exception:
            pass  # Fall back to mock on network or credential issue

        return self._generate_mock_response(model, messages, documents)

    def _generate_mock_response(
        self,
        model: str,
        messages: List[ChatMessage],
        documents: Optional[List[str]] = None,
    ) -> tuple[str, UsageInfo]:
        """Generates realistic responses for local offline verification."""
        last_msg = messages[-1].content if messages else ""

        if documents:
            content = f"Based on the provided {len(documents)} reference documents: Analysis indicates standard metrics and operations are fully verified."
        else:
            content = f"Here is the processed response to your query regarding: '{last_msg[:60]}...'. All requests are monitored by Prompt Injection Firewall."

        prompt_len = sum(len(m.content) for m in messages) // 4
        comp_len = len(content) // 4

        usage = UsageInfo(
            prompt_tokens=max(1, prompt_len),
            completion_tokens=max(1, comp_len),
            total_tokens=max(2, prompt_len + comp_len),
        )
        return content, usage
