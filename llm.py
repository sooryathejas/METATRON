#!/usr/bin/env python3
"""
METATRON - llm.py
Multi-provider LLM interface supporting Ollama and OpenAI-compatible APIs.
Builds prompts, handles AI responses, runs tool dispatch loop.

Supported Providers:
- Ollama: Local or remote Ollama instances
- OpenAI-compatible: OpenAI, vLLM, LM Studio, local servers
"""

import os
import re
import requests
import json
from pathlib import Path

# Load .env file automatically if it exists
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    from dotenv import load_dotenv
    load_dotenv(env_path)

from tools import run_tool_by_command, run_nmap, run_curl_headers
from search import handle_search_dispatch

# ─────────────────────────────────────────────
# ENVIRONMENT VARIABLES
# ─────────────────────────────────────────────

# Provider selection: "ollama" or "openai"
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama").lower()

# Ollama configuration
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "metatron-qwen")

# OpenAI-compatible configuration
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

# Shared settings
MAX_TOKENS = 8192
MAX_TOOL_LOOPS = 9
OLLAMA_TIMEOUT = 600
OPENAI_TIMEOUT = 120

# ─────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are METATRON, an elite AI penetration testing assistant running on Parrot OS.
You are precise, technical, and direct. No fluff.

You have access to real tools. To use them, write tags in your response:

  [TOOL: nmap -sV 192.168.1.1]       → runs nmap or any CLI tool
  [SEARCH: CVE-2021-44228 exploit]   → searches the web via DuckDuckGo

Rules:
- Always analyze scan data thoroughly before suggesting exploits
- List vulnerabilities with: name, severity (critical/high/medium/low), port, service
- For each vulnerability, suggest a concrete fix
- If you need more information, use [SEARCH:] or [TOOL:]
- Format vulnerabilities clearly so they can be saved to a database
- Be specific about CVE IDs when you know them
- Always give a final risk rating: CRITICAL / HIGH / MEDIUM / LOW

Output format for vulnerabilities (use this exactly):
VULN: <name> | SEVERITY: <level> | PORT: <port> | SERVICE: <service>
DESC: <description>
FIX: <fix recommendation>

Output format for exploits:
EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload or description>
RESULT: <expected result>
NOTES: <any notes>

End your analysis with:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <2-3 sentence overall summary>
IMPORTANT: Never use markdown bold (**text**) or
headers (## text). Plain text only. No exceptions.
IMPORTANT RULES FOR ACCURACY:
- nmap filtered or no-response means INCONCLUSIVE not vulnerable
- Never assert a server version without seeing it in scan output
- Never infer CVEs from guessed versions
- curl timeouts and HTTP_CODE=000 mean the host is unreachable not exploitable
- ab and stress tools are not Slowloris unless confirmed
- Only assign CRITICAL if there is direct evidence of exploitability
- If evidence is weak mark severity as LOW with note: unconfirmed"""


# ─────────────────────────────────────────────
# LLM CLIENT CLASS
# ─────────────────────────────────────────────

class LLMClient:
    """Unified LLM client supporting multiple providers."""

    def __init__(self):
        self.provider = LLM_PROVIDER
        if self.provider not in ("ollama", "openai"):
            raise ValueError(f"Unsupported LLM_PROVIDER: {self.provider}. Use 'ollama' or 'openai'.")

    def chat(self, messages: list, temperature: float = 0.7, max_tokens: int = MAX_TOKENS) -> str:
        """
        Send a chat request to the configured LLM provider.

        Args:
            messages: List of message dicts with 'role' and 'content' keys
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Maximum tokens to generate

        Returns:
            Model response content as string
        """
        if self.provider == "ollama":
            return self._call_ollama(messages, temperature, max_tokens)
        elif self.provider == "openai":
            return self._call_openai(messages, temperature, max_tokens)

    def _call_ollama(self, messages: list, temperature: float, max_tokens: int) -> str:
        """Call Ollama API."""
        try:
            payload = {
                "model": OLLAMA_MODEL,
                "messages": messages,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": temperature,
                    "top_p": 0.9,
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

    def _call_openai(self, messages: list, temperature: float, max_tokens: int) -> str:
        """Call OpenAI-compatible API."""
        try:
            # Check for API key
            if not OPENAI_API_KEY:
                # For local servers, API key may not be required
                headers = {"Content-Type": "application/json"}
            else:
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {OPENAI_API_KEY}"
                }

            payload = {
                "model": OPENAI_MODEL,
                "messages": messages,
                "stream": False,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

            # Construct the chat completions endpoint URL
            base = OPENAI_BASE_URL.rstrip("/")
            endpoint = f"{base}/chat/completions"

            print(f"\n[*] Sending to {self.provider} ({OPENAI_MODEL})...")
            resp = requests.post(endpoint, json=payload, headers=headers, timeout=OPENAI_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()

            # OpenAI-compatible response format
            choices = data.get("choices", [])
            if not choices:
                return "[!] Model returned empty response."

            response = choices[0].get("message", {}).get("content", "").strip()
            if not response:
                return "[!] Model returned empty response."

            return response
        except requests.exceptions.ConnectionError:
            return f"[!] Cannot connect to {self.provider}. Check OPENAI_BASE_URL: {OPENAI_BASE_URL}"
        except requests.exceptions.Timeout:
            return f"[!] {self.provider} timed out. Try again."
        except requests.exceptions.HTTPError as e:
            return f"[!] {self.provider} HTTP error: {e}"
        except Exception as e:
            return f"[!] Unexpected error: {e}"


# Global LLM client instance
_llm_client = None

def get_llm_client() -> LLMClient:
    """Get or create the global LLM client instance."""
    global _llm_client
    if _llm_client is None:
        _llm_client = LLMClient()
    return _llm_client


# ─────────────────────────────────────────────
# BACKWARD COMPATIBILITY FUNCTIONS
# ─────────────────────────────────────────────

def ask_ollama(messages: list) -> str:
    """
    Backward compatible wrapper for Ollama calls.
    Now uses the unified LLMClient internally.
    """
    client = get_llm_client()
    return client.chat(messages)


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

def extract_tool_calls(response: str) -> list:
    """
    Extract all [TOOL: ...] and [SEARCH: ...] tags from AI response.
    Returns list of tuples: [("TOOL", "nmap -sV x.x.x.x"), ("SEARCH", "CVE...")]
    """
    calls = []

    tool_matches   = re.findall(r'\[TOOL:\s*(.+?)\]',   response)
    search_matches = re.findall(r'\[SEARCH:\s*(.+?)\]', response)

    for m in tool_matches:
        calls.append(("TOOL", m.strip()))
    for m in search_matches:
        calls.append(("SEARCH", m.strip()))

    return calls

def summarize_tool_output(raw_output: str) -> str:
    """
    Compress raw tool output into security-relevant bullet points
    before injecting into the LLM context.
    Keeps context size manageable across rounds.
    """
    if len(raw_output) < 500:
        return raw_output

    try:
        client = get_llm_client()
        messages = [
            {"role": "system", "content": "You are a security data compressor. Extract only security-relevant facts. Return maximum 15 bullet points. Plain text only. No markdown."},
            {"role": "user", "content": f"Compress this tool output:\n{raw_output[:6000]}"}
        ]
        summary = client.chat(messages, temperature=0.2, max_tokens=512)
        return summary if summary else raw_output
    except Exception:
        return raw_output

def run_tool_calls(calls: list) -> str:
    """
    Execute all tool/search calls and return combined results string.
    """
    if not calls:
        return ""

    results = ""
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")

        if call_type == "TOOL":
            output = run_tool_by_command(call_content)
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"

        compressed = summarize_tool_output(output.strip())
        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += compressed + "\n"

    return results


# ─────────────────────────────────────────────
# PARSER — extract structured data from AI output
# ─────────────────────────────────────────────

def _clean(line: str) -> str:
    return re.sub(r'\*+', '', line).strip()

def parse_vulnerabilities(response: str) -> list:
    """
    Parse VULN: lines from AI response into dicts.
    Returns list of vulnerability dicts ready for db.save_vulnerability()
    """
    vulns = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("VULN:"):
            vuln = {
                "vuln_name":   "",
                "severity":    "medium",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         ""
            }

            # parse header line: VULN: name | SEVERITY: x | PORT: x | SERVICE: x
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("PORT:"):
                    vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"):
                    vuln["service"] = part.replace("SERVICE:", "").strip()

            # look ahead for DESC: and FIX: lines
            j = i + 1
            while j < len(lines) and j <= i + 5:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("DESC:"):
                    vuln["description"] = next_line.replace("DESC:", "").strip()
                elif next_line.startswith("FIX:"):
                    vuln["fix"] = next_line.replace("FIX:", "").strip()
                j += 1

            if vuln["vuln_name"]:
                vulns.append(vuln)

        i += 1

    return vulns


def parse_exploits(response: str) -> list:
    """
    Parse EXPLOIT: lines from AI response into dicts.
    Returns list of exploit dicts ready for db.save_exploit()
    """
    exploits = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("EXPLOIT:"):
            exploit = {
                "exploit_name": "",
                "tool_used":    "",
                "payload":      "",
                "result":       "unknown",
                "notes":        ""
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exploit["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exploit["payload"] = part.replace("PAYLOAD:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("RESULT:"):
                    exploit["result"] = next_line.replace("RESULT:", "").strip()
                elif next_line.startswith("NOTES:"):
                    exploit["notes"] = next_line.replace("NOTES:", "").strip()
                j += 1

            if exploit["exploit_name"]:
                exploits.append(exploit)

        i += 1

    return exploits


def parse_risk_level(response: str) -> str:
    """Extract RISK_LEVEL from AI response."""
    match = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(r'SUMMARY:\s*(.+)', response, re.IGNORECASE)
    return match.group(1).strip() if match else ""


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    client = get_llm_client()

    messages = [
        {
            "role": "system",
            "content": SYSTEM_PROMPT
        },
        {
            "role": "user",
            "content": f"""TARGET: {target}

RECON DATA:
{raw_scan}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more information.
List all vulnerabilities, fixes, and suggest exploits where applicable."""
        }
    ]

    final_response = ""

    for loop in range(MAX_TOOL_LOOPS):
        response = client.chat(messages)

        print(f"\n{'─'*60}")
        print(f"[METATRON - Round {loop + 1}]")
        print(f"{'─'*60}")
        print(response)

        final_response = response

        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break

        tool_results = run_tool_calls(tool_calls)

        # add assistant response and tool results as new messages
        messages.append({
            "role": "assistant",
            "content": response
        })
        messages.append({
            "role": "user",
            "content": f"""[TOOL RESULTS]
{tool_results}

Continue your analysis with this new information.
If analysis is complete, give the final RISK_LEVEL and SUMMARY."""
        })

    vulnerabilities = parse_vulnerabilities(final_response)
    exploits        = parse_exploits(final_response)
    risk_level      = parse_risk_level(final_response)
    summary         = parse_summary(final_response)

    print(f"\n[+] Parsed: {len(vulnerabilities)} vulns, {len(exploits)} exploits | Risk: {risk_level}")

    return {
        "full_response":   final_response,
        "vulnerabilities": vulnerabilities,
        "exploits":        exploits,
        "risk_level":      risk_level,
        "summary":         summary,
        "raw_scan":        raw_scan
    }


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ llm.py test — multi-provider LLM query ]\n")

    client = get_llm_client()
    print(f"Provider: {client.provider}")

    if client.provider == "ollama":
        print(f"Ollama URL: {OLLAMA_URL}")
        print(f"Model: {OLLAMA_MODEL}")
        # test if ollama is reachable
        try:
            r = requests.get("http://localhost:11434", timeout=5)
            print("[+] Ollama is running.")
        except Exception:
            print("[!] Ollama not reachable. Run: ollama serve")
            exit(1)
    elif client.provider == "openai":
        print(f"Base URL: {OPENAI_BASE_URL}")
        print(f"Model: {OPENAI_MODEL}")
        if OPENAI_API_KEY:
            print("[+] API key configured")
        else:
            print("[!] No API key set (may work with local servers)")

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
