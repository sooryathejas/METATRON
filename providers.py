#!/usr/bin/env python3
"""
METATRON - providers.py
Unified LLM provider abstraction.
Supports: Ollama (local), Anthropic (Claude), OpenAI, Google (Gemini).
Each provider implements send() → str using a messages-based interface.
"""

from abc import ABC, abstractmethod
import requests
import config


# ─────────────────────────────────────────────
# BASE PROVIDER
# ─────────────────────────────────────────────

class BaseProvider(ABC):
    """Abstract base for all LLM providers."""

    def __init__(self, model: str, temperature: float, max_tokens: int, timeout: int):
        self.model       = model
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self.timeout     = timeout

    @abstractmethod
    def send(self, messages: list) -> str:
        """Send a list of message dicts and return the response text.
        messages: [{"role": "system"|"user"|"assistant", "content": "..."}]
        """
        ...

    @abstractmethod
    def ping(self) -> bool:
        """Quick health check — returns True if provider is reachable."""
        ...

    def label(self) -> str:
        return f"{self.__class__.__name__}({self.model})"


# ─────────────────────────────────────────────
# OLLAMA (LOCAL)
# ─────────────────────────────────────────────

class OllamaProvider(BaseProvider):

    def __init__(self, model: str, temperature: float, max_tokens: int, timeout: int):
        super().__init__(model, temperature, max_tokens, timeout)
        self.url = config.OLLAMA_URL

    def send(self, messages: list) -> str:
        try:
            payload = {
                "model":  self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "num_predict":  self.max_tokens,
                    "temperature":  self.temperature,
                    "top_p":        0.9,
                }
            }
            print(f"\n[*] Sending to {self.model} (Ollama)...")
            resp = requests.post(self.url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            response = data.get("message", {}).get("content", "").strip()
            return response or "[!] Model returned empty response."

        except requests.exceptions.ConnectionError:
            return "[!] Cannot connect to Ollama. Is it running? Try: ollama serve"
        except requests.exceptions.Timeout:
            return "[!] Ollama timed out. Model may be loading, try again."
        except requests.exceptions.HTTPError as e:
            return f"[!] Ollama HTTP error: {e}"
        except Exception as e:
            return f"[!] Unexpected error: {e}"

    def ping(self) -> bool:
        try:
            base = self.url.rsplit("/api", 1)[0]
            r = requests.get(base, timeout=5)
            return r.status_code == 200
        except Exception:
            return False


# ─────────────────────────────────────────────
# ANTHROPIC (CLAUDE)
# ─────────────────────────────────────────────

class AnthropicProvider(BaseProvider):

    def send(self, messages: list) -> str:
        try:
            import anthropic
        except ImportError:
            return "[!] anthropic SDK not installed. Run: pip install anthropic"

        api_key = config.get_api_key("anthropic")
        if not api_key:
            return "[!] ANTHROPIC_API_KEY not set in .env"

        try:
            client = anthropic.Anthropic(api_key=api_key)
            print(f"\n[*] Sending to {self.model} (Anthropic)...")

            # Anthropic uses system as a top-level param, not in messages
            system_text = ""
            user_messages = []
            for msg in messages:
                if msg["role"] == "system":
                    system_text = msg["content"]
                else:
                    user_messages.append(msg)

            kwargs = {
                "model":      self.model,
                "max_tokens": self.max_tokens,
                "temperature": self.temperature,
                "messages":   user_messages,
            }
            if system_text:
                kwargs["system"] = system_text

            message = client.messages.create(**kwargs)
            text = message.content[0].text.strip()
            return text or "[!] Model returned empty response."

        except anthropic.AuthenticationError:
            return "[!] Anthropic API key is invalid."
        except anthropic.RateLimitError:
            return "[!] Anthropic rate limit exceeded. Wait and retry."
        except anthropic.APIError as e:
            return f"[!] Anthropic API error: {e}"
        except Exception as e:
            return f"[!] Unexpected error (Anthropic): {e}"

    def ping(self) -> bool:
        try:
            import anthropic
            api_key = config.get_api_key("anthropic")
            if not api_key:
                return False
            client = anthropic.Anthropic(api_key=api_key)
            client.models.list(limit=1)
            return True
        except Exception:
            return False


# ─────────────────────────────────────────────
# OPENAI
# ─────────────────────────────────────────────

class OpenAIProvider(BaseProvider):

    def send(self, messages: list) -> str:
        try:
            from openai import OpenAI
        except ImportError:
            return "[!] openai SDK not installed. Run: pip install openai"

        api_key = config.get_api_key("openai")
        if not api_key:
            return "[!] OPENAI_API_KEY not set in .env"

        try:
            client = OpenAI(api_key=api_key)
            print(f"\n[*] Sending to {self.model} (OpenAI)...")

            response = client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_completion_tokens=self.max_tokens,
                temperature=self.temperature,
            )
            text = response.choices[0].message.content.strip()
            return text or "[!] Model returned empty response."

        except Exception as e:
            err = str(e)
            if "authentication" in err.lower() or "api key" in err.lower():
                return "[!] OpenAI API key is invalid."
            if "rate" in err.lower():
                return "[!] OpenAI rate limit exceeded. Wait and retry."
            return f"[!] OpenAI error: {e}"

    def ping(self) -> bool:
        try:
            from openai import OpenAI
            api_key = config.get_api_key("openai")
            if not api_key:
                return False
            client = OpenAI(api_key=api_key)
            client.models.list()
            return True
        except Exception:
            return False


# ─────────────────────────────────────────────
# GOOGLE (GEMINI)
# ─────────────────────────────────────────────

class GoogleProvider(BaseProvider):

    def send(self, messages: list) -> str:
        try:
            from google import genai
        except ImportError:
            return "[!] google-genai SDK not installed. Run: pip install google-genai"

        api_key = config.get_api_key("google")
        if not api_key:
            return "[!] GOOGLE_API_KEY not set in .env"

        try:
            client = genai.Client(api_key=api_key)
            print(f"\n[*] Sending to {self.model} (Google Gemini)...")

            # Gemini expects a flat prompt; merge system + user messages
            parts = []
            for msg in messages:
                parts.append(msg["content"])
            full_prompt = "\n\n".join(parts)

            response = client.models.generate_content(
                model=self.model,
                contents=full_prompt,
                config=genai.types.GenerateContentConfig(
                    max_output_tokens=self.max_tokens,
                    temperature=self.temperature,
                ),
            )
            text = response.text.strip()
            return text or "[!] Model returned empty response."

        except Exception as e:
            err = str(e)
            if "api key" in err.lower() or "403" in err:
                return "[!] Google API key is invalid."
            return f"[!] Google Gemini error: {e}"

    def ping(self) -> bool:
        try:
            from google import genai
            api_key = config.get_api_key("google")
            if not api_key:
                return False
            client = genai.Client(api_key=api_key)
            client.models.list(config={"page_size": 1})
            return True
        except Exception:
            return False


# ─────────────────────────────────────────────
# FACTORY
# ─────────────────────────────────────────────

_PROVIDER_MAP = {
    "ollama":    OllamaProvider,
    "anthropic": AnthropicProvider,
    "openai":    OpenAIProvider,
    "google":    GoogleProvider,
}


def get_provider(
    name: str = None,
    model: str = None,
    temperature: float = None,
    max_tokens: int = None,
    timeout: int = None,
) -> BaseProvider:
    """
    Factory — returns a configured provider instance.
    Falls back to config.py defaults for any parameter not given.
    """
    name        = name        or config.ACTIVE_PROVIDER
    model       = model       or config.ACTIVE_MODEL
    temperature = temperature if temperature is not None else config.TEMPERATURE
    max_tokens  = max_tokens  or config.MAX_TOKENS
    timeout     = timeout     or config.LLM_TIMEOUT

    cls = _PROVIDER_MAP.get(name)
    if cls is None:
        raise ValueError(f"Unknown provider: '{name}'. Available: {list(_PROVIDER_MAP.keys())}")

    return cls(
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )


def list_providers() -> list:
    """
    Return a list of dicts describing each provider and its status.
    Used by the settings menu.
    """
    result = []
    for key, info in config.PROVIDERS.items():
        has_key = config.has_api_key(key)
        is_active = (key == config.ACTIVE_PROVIDER)
        result.append({
            "key":     key,
            "name":    info["name"],
            "models":  info["models"],
            "has_key": has_key,
            "active":  is_active,
        })
    return result
