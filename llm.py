#!/usr/bin/env python3
"""
METATRON - llm.py
LLM interface for penetration testing analysis.
Supports FLM (OpenAI-compatible) and Ollama backends via llm_backends.py.
Builds prompts, handles AI responses, runs tool dispatch loop.
"""

import os
import re
from dotenv import load_dotenv
from llm_backends import ask_llm
from tools import run_tool_by_command
from search import handle_search_dispatch

load_dotenv()

MAX_TOKENS = 8192
MAX_TOOL_LOOPS = 9

SYSTEM_PROMPT_PATH = os.getenv("METATRON_SYSTEM_PROMPT", "config/system_prompt.txt")

# ─────────────────────────────────────────────
# SYSTEM PROMPT LOADER
# ─────────────────────────────────────────────

def load_system_prompt() -> str:
    try:
        with open(SYSTEM_PROMPT_PATH, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(f"[!] System prompt not found at {SYSTEM_PROMPT_PATH}. Using fallback.")
        return "You are METATRON, an elite AI penetration testing assistant. Be precise and technical."


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
    """
    if len(raw_output) < 500:
        return raw_output

    try:
        messages = [
            {"role": "system", "content": "You are a security data compressor. Extract only security-relevant facts. Return maximum 15 bullet points. Plain text only. No markdown."},
            {"role": "user", "content": f"Compress this tool output:\n{raw_output[:6000]}"}
        ]
        summary = ask_llm(messages, max_tokens=512, temperature=0.2)
        return summary if summary and not summary.startswith("[!]") else raw_output
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


def _extract_vuln_fields(text: str, vuln: dict):
    """Helper to extract vuln_name/severity/port/service from a pipe-separated string."""
    parts = text.split("|")
    for idx, part in enumerate(parts):
        part = part.strip()
        if re.match(r'VULN\s*:', part, re.IGNORECASE):
            vuln["vuln_name"] = re.sub(r'(?i)^VULN\s*:', '', part).strip()
        elif re.match(r'SEVER\w*?:', part, re.IGNORECASE):
            vuln["severity"] = re.sub(r'(?i)^SEVER\w*?:', '', part).strip().lower()
        elif re.match(r'PORT\s*:', part, re.IGNORECASE):
            vuln["port"] = re.sub(r'(?i)^PORT\s*:', '', part).strip()
        elif re.match(r'SERVICE\s*:', part, re.IGNORECASE):
            vuln["service"] = re.sub(r'(?i)^SERVICE\s*:', '', part).strip()
        elif idx == 0 and vuln["vuln_name"] == "":
            # First part without VULN: prefix — treat as name if it's not a known field
            if not re.match(r'(SEVER\w*?|PORT|SERVICE|EXPLOIT|TOOL|PAYLOAD|RESULT|NOTES|DESC|FIX)\s*:', part, re.IGNORECASE):
                vuln["vuln_name"] = part


def _parse_vuln_block(lines: list, start_idx: int) -> tuple:
    """
    Parse DESC: and FIX: lines starting from start_idx.
    Returns (description, fix, next_index).
    """
    description = ""
    fix = ""
    j = start_idx
    while j < len(lines) and j <= start_idx + 5:
        next_line = _clean(lines[j])
        # stop at next vuln, exploit, risk level, summary, or numbered list item
        if re.match(r'^(\d+\.|VULN:|EXPLOIT:|RISK_LEVEL:|SUMMARY:)', next_line, re.IGNORECASE):
            break
        if re.match(r'DESC\s*:', next_line, re.IGNORECASE):
            description = re.sub(r'(?i)^DESC\s*:', '', next_line).strip()
        elif re.match(r'FIX\s*:', next_line, re.IGNORECASE):
            fix = re.sub(r'(?i)^FIX\s*:', '', next_line).strip()
        j += 1
    return description, fix, j


def parse_vulnerabilities(response: str) -> list:
    """
    Parse vulnerabilities from AI response.
    Supports both structured format (VULN: ...) and markdown/list format.
    Returns list of vulnerability dicts ready for db.save_vulnerability()
    """
    vulns = []
    lines = response.splitlines()

    # ── Pass 1: structured format ─────────────────────────────
    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if re.match(r'VULN\s*:', line, re.IGNORECASE):
            vuln = {
                "vuln_name":   "",
                "severity":    "medium",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         ""
            }
            _extract_vuln_fields(line, vuln)
            desc, fix, i = _parse_vuln_block(lines, i + 1)
            vuln["description"] = desc
            vuln["fix"] = fix
            if vuln["vuln_name"]:
                vulns.append(vuln)
            continue
        i += 1

    if vulns:
        return vulns

    # ── Pass 2: markdown / numbered list format ───────────────
    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        # Match lines like: 1. **name | SEVERITY: x | PORT: y | SERVICE: z**
        # _clean() already strips asterisks, so we match without them
        md_match = re.match(r'^\d+\.\s+(.+?)$', line)
        if md_match:
            inner = md_match.group(1).strip()
            vuln = {
                "vuln_name":   "",
                "severity":    "medium",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         ""
            }
            _extract_vuln_fields(inner, vuln)
            desc, fix, i = _parse_vuln_block(lines, i + 1)
            vuln["description"] = desc
            vuln["fix"] = fix
            # Skip false positives like "No other significant vulnerabilities were detected"
            skip_keywords = [
                "no other", "none detected", "no significant", "no vulnerabilities",
                "nothing detected", "not applicable", "n/a"
            ]
            name_lower = vuln["vuln_name"].lower()
            if vuln["vuln_name"] and not any(kw in name_lower for kw in skip_keywords):
                vulns.append(vuln)
            continue
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
                if re.match(r'EXPLOIT\s*:', part, re.IGNORECASE):
                    exploit["exploit_name"] = re.sub(r'(?i)^EXPLOIT\s*:', '', part).strip()
                elif re.match(r'TOOL\s*:', part, re.IGNORECASE):
                    exploit["tool_used"] = re.sub(r'(?i)^TOOL\s*:', '', part).strip()
                elif re.match(r'PAYLOAD\s*:', part, re.IGNORECASE):
                    exploit["payload"] = re.sub(r'(?i)^PAYLOAD\s*:', '', part).strip()

            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = _clean(lines[j])
                if re.match(r'(VULN|EXPLOIT|RISK_LEVEL|SUMMARY)\s*:', next_line, re.IGNORECASE):
                    break
                if re.match(r'RESULT\s*:', next_line, re.IGNORECASE):
                    exploit["result"] = re.sub(r'(?i)^RESULT\s*:', '', next_line).strip()
                elif re.match(r'NOTES\s*:', next_line, re.IGNORECASE):
                    exploit["notes"] = re.sub(r'(?i)^NOTES\s*:', '', next_line).strip()
                j += 1

            if exploit["exploit_name"]:
                exploits.append(exploit)

        i += 1

    return exploits


def parse_risk_level(response: str) -> str:
    """Extract RISK_LEVEL from AI response."""
    match = re.search(r'RISK[_\s]LEVEL[:\s]+(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(r'SUMMARY:\s*(.+)', response, re.IGNORECASE)
    return match.group(1).strip() if match else ""


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    system_prompt = load_system_prompt()

    messages = [
        {
            "role": "system",
            "content": system_prompt
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
        response = ask_llm(messages)

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

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
