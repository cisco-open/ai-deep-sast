# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
LLM client for AI Deep SAST deep scan.

Wraps any OpenAI-compatible API with:
- Configurable endpoint via LLM_BASE_URL, LLM_API_KEY, LLM_MODEL env vars
- Token usage tracking and cost estimation
- Adaptive backoff on rate limits

Works with OpenAI, Anthropic (via proxy), Azure, Ollama, vLLM, LiteLLM,
or any provider that exposes an OpenAI-compatible /v1/chat/completions endpoint.
"""

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# LLM configuration — override via environment variables
DEFAULT_BASE_URL = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1")
DEFAULT_MODEL = os.environ.get("LLM_MODEL", "gpt-4o")
DEFAULT_MAX_TOKENS = 4096


def _load_api_key() -> Optional[str]:
    """
    Resolve LLM API key from environment.

    Reads LLM_API_KEY env var. The key is NEVER hardcoded or stored in config files.
    """
    api_key = os.environ.get("LLM_API_KEY")
    if api_key:
        logger.debug("LLM API key loaded from LLM_API_KEY environment variable")
        return api_key

    return None


class TokenUsage:
    """Tracks cumulative token usage and estimated cost."""

    # Approximate pricing per 1M tokens (as of 2025)
    PRICING = {
        "anthropic/claude-opus-4.7": {"input": 15.0, "output": 75.0},
        "anthropic/claude-sonnet-4.5": {"input": 3.0, "output": 15.0},
        "gpt-4.1": {"input": 2.0, "output": 8.0},
    }
    DEFAULT_PRICING = {"input": 15.0, "output": 75.0}

    def __init__(self):
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.total_calls = 0
        self.estimated_cost_usd = 0.0
        self._model = DEFAULT_MODEL

    def record(self, input_tokens: int, output_tokens: int, model: str = ""):
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
        self.total_calls += 1
        self._model = model or self._model

        pricing = self.PRICING.get(self._model, self.DEFAULT_PRICING)
        cost = (input_tokens * pricing["input"] + output_tokens * pricing["output"]) / 1_000_000
        self.estimated_cost_usd += cost

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_calls": self.total_calls,
            "estimated_cost_usd": round(self.estimated_cost_usd, 4),
        }


class LLMClient:
    """
    LLM client for AI Deep SAST deep scan.

    Connects to any OpenAI-compatible API endpoint. Configure via env vars:
        LLM_BASE_URL  — API base URL (default: https://api.openai.com/v1)
        LLM_API_KEY   — API key for authentication
        LLM_MODEL     — Model name (default: gpt-4o)
    """

    def __init__(self, model: str = DEFAULT_MODEL,
                 max_tokens: int = DEFAULT_MAX_TOKENS,
                 base_url: str = DEFAULT_BASE_URL,
                 api_key: Optional[str] = None):
        self.model = model
        self.max_tokens = max_tokens
        self.usage = TokenUsage()
        self._client = None
        self._base_url = base_url
        self._api_key = api_key
        self._backoff_until = 0.0

    def _ensure_client(self):
        """Lazy-init the OpenAI client."""
        if self._client is not None:
            return

        api_key = self._api_key or _load_api_key()
        if not api_key:
            raise RuntimeError(
                "LLM API key not found. Set LLM_API_KEY environment variable.\n"
                "Example: export LLM_API_KEY=sk-proj-abc123..."
            )

        try:
            import openai
            self._client = openai.OpenAI(
                base_url=self._base_url,
                api_key=api_key,
            )
        except ImportError:
            raise RuntimeError("openai package not installed. Run: pip install openai")

    def chat(self, system_prompt: str, user_message: str) -> Tuple[str, Dict[str, int]]:
        """
        Send a chat message and return (response_text, token_usage).

        Handles rate limiting with adaptive backoff.
        """
        self._ensure_client()
        self._wait_for_backoff()

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                max_completion_tokens=self.max_tokens,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
            )

            usage = response.usage
            input_tokens = usage.prompt_tokens if usage else 0
            output_tokens = usage.completion_tokens if usage else 0
            self.usage.record(input_tokens, output_tokens, self.model)

            text = response.choices[0].message.content or ""

            token_info = {"input_tokens": input_tokens, "output_tokens": output_tokens}
            return text, token_info

        except Exception as e:
            error_str = str(e)
            # Adaptive backoff on rate limit
            if "429" in error_str or "rate" in error_str.lower():
                self._apply_backoff()
                logger.warning("Rate limited, backing off: %s", e)
            raise

    def _wait_for_backoff(self):
        """Wait if we're in a backoff period."""
        now = time.time()
        if now < self._backoff_until:
            wait = self._backoff_until - now
            logger.info("Rate limit backoff: waiting %.1fs", wait)
            time.sleep(wait)

    def _apply_backoff(self):
        """Apply exponential backoff on rate limit."""
        current_wait = max(1.0, self._backoff_until - time.time())
        new_wait = min(current_wait * 2, 60.0)  # Cap at 60s
        self._backoff_until = time.time() + new_wait

    def is_available(self) -> bool:
        """Check if the LLM API key is configured."""
        return self._api_key is not None or _load_api_key() is not None
