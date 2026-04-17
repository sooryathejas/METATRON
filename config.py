#!/usr/bin/env python3
"""
METATRON - config.py
Centralized configuration loaded from .env file.
All settings live here — no more hardcoded values scattered across modules.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# load .env from project root
_env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(_env_path)


# ─────────────────────────────────────────────
# LLM PROVIDER
# ─────────────────────────────────────────────

ACTIVE_PROVIDER = os.getenv("ACTIVE_PROVIDER", "ollama")   # ollama | anthropic | openai | google
ACTIVE_MODEL    = os.getenv("ACTIVE_MODEL",    "metatron-qwen")

# API keys (empty string = not configured)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY    = os.getenv("OPENAI_API_KEY",    "")
GOOGLE_API_KEY    = os.getenv("GOOGLE_API_KEY",    "")

# Ollama
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")

# Generation parameters
MAX_TOKENS     = int(os.getenv("MAX_TOKENS",     "8192"))
MAX_TOOL_LOOPS = int(os.getenv("MAX_TOOL_LOOPS", "9"))
TEMPERATURE    = float(os.getenv("TEMPERATURE",   "0.7"))
LLM_TIMEOUT    = int(os.getenv("LLM_TIMEOUT",    "600"))


# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

DB_HOST     = os.getenv("DB_HOST",     "localhost")
DB_USER     = os.getenv("DB_USER",     "metatron")
DB_PASSWORD = os.getenv("DB_PASSWORD", "123")
DB_NAME     = os.getenv("DB_NAME",     "metatron")


# ─────────────────────────────────────────────
# PROVIDER CATALOG
# ─────────────────────────────────────────────

PROVIDERS = {
    "ollama": {
        "name":    "Ollama (Local)",
        "models":  ["metatron-qwen"],
        "key_var": None,
    },
    "anthropic": {
        "name":    "Anthropic (Claude)",
        "models":  ["claude-sonnet-4-20250514", "claude-opus-4-20250514", "claude-haiku-4-20250514"],
        "key_var": "ANTHROPIC_API_KEY",
    },
    "openai": {
        "name":    "OpenAI",
        "models":  ["gpt-4.1-mini", "gpt-4.1", "gpt-4.1-nano"],
        "key_var": "OPENAI_API_KEY",
    },
    "google": {
        "name":    "Google (Gemini)",
        "models":  ["gemini-2.5-pro-preview-05-06", "gemini-2.5-flash-preview-04-17", "gemini-2.0-flash"],
        "key_var": "GOOGLE_API_KEY",
    },
}


def get_api_key(provider: str) -> str:
    """Get the API key for a provider, or empty string if not set."""
    key_var = PROVIDERS.get(provider, {}).get("key_var")
    if key_var is None:
        return ""
    return globals().get(key_var, "")


def has_api_key(provider: str) -> bool:
    """Check if a provider has a configured API key."""
    if provider == "ollama":
        return True
    return bool(get_api_key(provider))
