#!/usr/bin/env python3
"""
METATRON - llm.py
LLM interface — provider-agnostic.
Builds prompts, handles AI responses, runs tool dispatch loop.
Supports: Ollama (local), Anthropic (Claude), OpenAI, Google (Gemini).
Provider selection is handled by providers.py + config.py.
"""

import re
import requests
from tools import run_tool_by_command, run_nmap, run_curl_headers
from search import handle_search_dispatch
from providers import get_provider
import config

MAX_TOOL_LOOPS = config.MAX_TOOL_LOOPS

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
# LLM API CALL (provider-agnostic)
# ─────────────────────────────────────────────

def ask_llm(messages: list, provider_name: str = None,
            model: str = None) -> str:
    """
    Send messages to the active LLM provider.
    provider_name/model: optional overrides for per-scan switching.
    Returns the AI response string.
    """
    provider = get_provider(name=provider_name, model=model)
    return provider.send(messages)


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

def summarize_tool_output(raw_output: str, provider_name: str = None,
                          model: str = None) -> str:
    """
    Compress raw tool output into security-relevant bullet points
    before injecting into the LLM context.
    Keeps context size manageable across rounds.
    Uses the active provider (or override) for summarization.
    """
    if len(raw_output) < 500:
        return raw_output

    try:
        summarizer = get_provider(
            name=provider_name, model=model,
            max_tokens=512, temperature=0.2,
        )
        messages = [
            {"role": "system", "content": "You are a security data compressor. Extract only security-relevant facts. Return maximum 15 bullet points. Plain text only. No markdown."},
            {"role": "user", "content": f"Compress this tool output:\n{raw_output[:6000]}"},
        ]
        summary = summarizer.send(messages)
        return summary if summary else raw_output
    except Exception:
        return raw_output
def run_tool_calls(calls: list, provider_name: str = None,
                   model: str = None) -> str:
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

        compressed = summarize_tool_output(output.strip(),
                                           provider_name=provider_name,
                                           model=model)
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

def analyse_target(target: str, raw_scan: str,
                   provider_name: str = None, model: str = None) -> dict:
    """
    Full analysis pipeline:
    1. Build initial prompt with scan data
    2. Send to active LLM provider
    3. Run tool dispatch loop if AI requests tools
    4. Parse structured output
    5. Return everything ready for db.py to save

    provider_name/model: optional overrides for per-scan switching.

    Returns dict with:
      - full_response   : complete AI text
      - vulnerabilities : list of parsed vuln dicts
      - exploits        : list of parsed exploit dicts
      - risk_level      : CRITICAL/HIGH/MEDIUM/LOW
      - summary         : short summary text
      - raw_scan        : original scan dump
    """
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
        response = ask_llm(messages, provider_name=provider_name, model=model)

        print(f"\n{'─'*60}")
        print(f"[METATRON - Round {loop + 1}]")
        print(f"{'─'*60}")
        print(response)

        final_response = response

        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break

        tool_results = run_tool_calls(tool_calls,
                                      provider_name=provider_name, model=model)

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
    print("[ llm.py test — direct AI query ]\n")
    print(f"  Provider: {config.ACTIVE_PROVIDER}")
    print(f"  Model:    {config.ACTIVE_MODEL}\n")

    provider = get_provider()
    if provider.ping():
        print(f"[+] {provider.label()} is reachable.")
    else:
        print(f"[!] {provider.label()} is not reachable. Check config.")
        exit(1)

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
