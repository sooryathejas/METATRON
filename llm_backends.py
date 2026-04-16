#!/usr/bin/env python3
"""
METATRON - llm_backends.py
Unified LLM interface supporting FLM (OpenAI-compatible) and Ollama backends.
"""

import os
import requests
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

BACKEND = os.getenv("METATRON_LLM_BACKEND", "flm").lower()

FLM_BASE_URL = os.getenv("FLM_BASE_URL", "http://localhost:11434/v1")
FLM_API_KEY = os.getenv("FLM_API_KEY", "dummy")
FLM_MODEL = os.getenv("FLM_MODEL", "qwen3.5:4b")
FLM_TIMEOUT = int(os.getenv("FLM_TIMEOUT", "600"))

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "metatron-qwen")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "600"))

MAX_TOKENS = 8192

# ─────────────────────────────────────────────
# FLM BACKEND (OpenAI-compatible)
# ─────────────────────────────────────────────

_flm_client = None

def _get_flm_client():
    global _flm_client
    if _flm_client is None:
        _flm_client = OpenAI(
            base_url=FLM_BASE_URL,
            api_key=FLM_API_KEY,
            timeout=FLM_TIMEOUT,
        )
    return _flm_client


def ask_flm(messages: list, max_tokens: int = MAX_TOKENS, temperature: float = 0.7, top_p: float = 0.9) -> str:
    try:
        client = _get_flm_client()
        print(f"\n[*] Sending to FLM ({FLM_MODEL})...")
        response = client.chat.completions.create(
            model=FLM_MODEL,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
        )
        content = response.choices[0].message.content
        return content.strip() if content else "[!] Model returned empty response."
    except Exception as e:
        return f"[!] FLM error: {e}"


# ─────────────────────────────────────────────
# OLLAMA BACKEND
# ─────────────────────────────────────────────

def ask_ollama(messages: list, max_tokens: int = MAX_TOKENS, temperature: float = 0.7, top_p: float = 0.9) -> str:
    try:
        payload = {
            "model": OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
                "top_p": top_p,
            }
        }
        print(f"\n[*] Sending to Ollama ({OLLAMA_MODEL})...")
        resp = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        response = data.get("message", {}).get("content", "").strip()
        if not response:
            return "[!] Model returned empty response."
        return response
    except requests.exceptions.ConnectionError:
        return "[!] Cannot connect to Ollama. Is it running? Try: ollama serve"
    except requests.exceptions.Timeout:
        return "[!] Ollama timed out. Model may be loading, try again."
    except requests.exceptions.HTTPError as e:
        return f"[!] Ollama HTTP error: {e}"
    except Exception as e:
        return f"[!] Unexpected error: {e}"


# ─────────────────────────────────────────────
# UNIFIED INTERFACE
# ─────────────────────────────────────────────

def ask_llm(messages: list, max_tokens: int = MAX_TOKENS, temperature: float = 0.7, top_p: float = 0.9) -> str:
    if BACKEND == "flm":
        return ask_flm(messages, max_tokens, temperature, top_p)
    elif BACKEND == "ollama":
        return ask_ollama(messages, max_tokens, temperature, top_p)
    else:
        raise ValueError(f"Unknown METATRON_LLM_BACKEND: {BACKEND}. Use 'flm' or 'ollama'.")
