"""
Multi-provider AI abstraction layer for IIFVDCAS.

Supported providers:
  - nvidia_nim   : NVIDIA NIM (OpenAI-compatible, custom base_url)
  - openai       : OpenAI GPT-4o / GPT-4 etc.
  - anthropic    : Anthropic Claude
  - gemini       : Google Gemini
  - ollama       : Local Ollama (OpenAI-compatible, no key needed)
"""

from __future__ import annotations
import logging
from abc import ABC, abstractmethod
from typing import List, Dict

logger = logging.getLogger(__name__)

# ─── Default models per provider ─────────────────────────────────────────────
DEFAULTS: Dict[str, Dict] = {
    "nvidia_nim": {
        "model":    "meta/llama-3.1-70b-instruct",
        "base_url": "https://integrate.api.nvidia.com/v1",
    },
    "openai": {
        "model":    "gpt-4o-mini",
        "base_url": None,
    },
    "anthropic": {
        "model":    "claude-3-5-haiku-20241022",
        "base_url": None,
    },
    "gemini": {
        "model":    "gemini-2.0-flash",
        "base_url": None,
    },
    "ollama": {
        "model":    "llama3",
        "base_url": "http://localhost:11434/v1",
    },
}


# ─── Abstract base ────────────────────────────────────────────────────────────
class AIProvider(ABC):
    """All providers implement this single method."""

    @abstractmethod
    def complete(self, messages: List[Dict], max_tokens: int = 600) -> str:
        """Return the assistant's reply as a plain string."""
        ...


# ─── OpenAI-compatible (NIM / OpenAI / Ollama) ───────────────────────────────
class OpenAICompatibleProvider(AIProvider):
    def __init__(self, api_key: str, model: str, base_url: str | None):
        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError(
                "openai package not installed. Run: pip install openai"
            )
        self.client = OpenAI(
            api_key=api_key or "ollama",  # Ollama ignores the key
            base_url=base_url,
        )
        self.model = model

    def complete(self, messages: List[Dict], max_tokens: int = 600) -> str:
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=0.3,
        )
        return resp.choices[0].message.content.strip()


# ─── Anthropic ────────────────────────────────────────────────────────────────
class AnthropicProvider(AIProvider):
    def __init__(self, api_key: str, model: str):
        try:
            import anthropic
        except ImportError:
            raise RuntimeError(
                "anthropic package not installed. Run: pip install anthropic"
            )
        self._anthropic = anthropic
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def complete(self, messages: List[Dict], max_tokens: int = 600) -> str:
        # Anthropic separates system prompt from messages
        system_msg = ""
        user_msgs = []
        for m in messages:
            if m["role"] == "system":
                system_msg = m["content"]
            else:
                user_msgs.append(m)

        kwargs: dict = dict(
            model=self.model,
            max_tokens=max_tokens,
            messages=user_msgs,
            temperature=0.3,
        )
        if system_msg:
            kwargs["system"] = system_msg

        resp = self.client.messages.create(**kwargs)
        return resp.content[0].text.strip()


# ─── Google Gemini ────────────────────────────────────────────────────────────
class GeminiProvider(AIProvider):
    def __init__(self, api_key: str, model: str):
        try:
            import google.generativeai as genai
        except ImportError:
            raise RuntimeError(
                "google-generativeai not installed. Run: pip install google-generativeai"
            )
        genai.configure(api_key=api_key)
        self.genai = genai
        self.model_name = model

    def complete(self, messages: List[Dict], max_tokens: int = 600) -> str:
        # Convert OpenAI-style messages to a single prompt string
        parts = []
        for m in messages:
            role = m["role"].upper()
            content = m["content"]
            if role == "SYSTEM":
                parts.append(f"[System]: {content}")
            elif role == "USER":
                parts.append(f"[User]: {content}")
            else:
                parts.append(f"[Assistant]: {content}")

        prompt = "\n\n".join(parts)

        model = self.genai.GenerativeModel(self.model_name)
        config = self.genai.types.GenerationConfig(
            max_output_tokens=max_tokens,
            temperature=0.3,
        )
        resp = model.generate_content(prompt, generation_config=config)
        return resp.text.strip()


# ─── Factory ──────────────────────────────────────────────────────────────────
def get_provider(
    provider_name: str,
    api_key: str,
    model: str | None = None,
    base_url: str | None = None,
) -> AIProvider:
    """
    Instantiate the correct AI provider.

    provider_name: nvidia_nim | openai | anthropic | gemini | ollama
    api_key:       provider API key (empty string OK for Ollama)
    model:         override model name (uses sensible default if None)
    base_url:      override base URL (relevant for nvidia_nim / ollama)
    """
    name = (provider_name or "").lower().strip()
    defaults = DEFAULTS.get(name, DEFAULTS["openai"])
    resolved_model    = model    or defaults["model"]
    resolved_base_url = base_url or defaults.get("base_url")

    logger.info(
        "[AI] provider=%s model=%s base_url=%s",
        name, resolved_model, resolved_base_url or "default",
    )

    if name in ("nvidia_nim", "openai", "ollama"):
        return OpenAICompatibleProvider(
            api_key=api_key,
            model=resolved_model,
            base_url=resolved_base_url,
        )
    elif name == "anthropic":
        return AnthropicProvider(api_key=api_key, model=resolved_model)
    elif name == "gemini":
        return GeminiProvider(api_key=api_key, model=resolved_model)
    else:
        raise ValueError(
            f"Unknown AI provider '{name}'. "
            "Choose: nvidia_nim | openai | anthropic | gemini | ollama"
        )
