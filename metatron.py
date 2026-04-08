#!/usr/bin/env python3
"""
METATRON - AI Penetration Testing Assistant
Consolidated single-file version (SQLite backend, all features included)

Run: python METATRON.py
Dependencies: pip install requests beautifulsoup4 duckduckgo-search reportlab
Optional (for scans): nmap, whois, whatweb, curl, dig, nikto (pre‑installed on Parrot OS)
Ollama required: https://ollama.com/   then: ollama pull huihui_ai/qwen3.5-abliterated:9b
"""

import sys
import os
import re
import json
import subprocess
import sqlite3
import datetime
from datetime import datetime as dt
from typing import List, Dict, Any, Optional, Tuple

# ---------- external libs ----------
try:
    import requests
    from bs4 import BeautifulSoup
    from duckduckgo_search import DDGS
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_CENTER
except ImportError as e:
    print(f"[!] Missing required library: {e}")
    print("Install all dependencies with: pip install requests beautifulsoup4 duckduckgo-search reportlab")
    sys.exit(1)

# ----------------------------------------------------------------------
# 1. DATABASE (SQLite)
# ----------------------------------------------------------------------
DB_FILE = "metatron.db"

def get_conn():
    """Return SQLite connection with foreign keys enabled."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Create all tables if they don't exist."""
    conn = get_conn()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS history (
            sl_no INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            status TEXT DEFAULT 'active'
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no INTEGER NOT NULL,
            vuln_name TEXT,
            severity TEXT,
            port TEXT,
            service TEXT,
            description TEXT,
            FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS fixes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no INTEGER NOT NULL,
            vuln_id INTEGER NOT NULL,
            fix_text TEXT,
            source TEXT DEFAULT 'ai',
            FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE CASCADE,
            FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS exploits_attempted (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no INTEGER NOT NULL,
            exploit_name TEXT,
            tool_used TEXT,
            payload TEXT,
            result TEXT,
            notes TEXT,
            FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS summary (
            sl_no INTEGER PRIMARY KEY,
            raw_scan TEXT,
            ai_analysis TEXT,
            risk_level TEXT,
            generated_at TEXT,
            FOREIGN KEY (sl_no) REFERENCES history(sl_no) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()

# --- DB write operations ---
def create_session(target: str) -> int:
    conn = get_conn()
    cur = conn.cursor()
    now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO history (target, scan_date, status) VALUES (?, ?, ?)",
                (target, now, "active"))
    conn.commit()
    sl_no = cur.lastrowid
    conn.close()
    return sl_no

def save_vulnerability(sl_no: int, vuln_name: str, severity: str,
                       port: str, service: str, description: str) -> int:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO vulnerabilities (sl_no, vuln_name, severity, port, service, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (sl_no, vuln_name, severity, port, service, description))
    conn.commit()
    vuln_id = cur.lastrowid
    conn.close()
    return vuln_id

def save_fix(sl_no: int, vuln_id: int, fix_text: str, source: str = "ai"):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
        VALUES (?, ?, ?, ?)
    """, (sl_no, vuln_id, fix_text, source))
    conn.commit()
    conn.close()

def save_exploit(sl_no: int, exploit_name: str, tool_used: str,
                 payload: str, result: str, notes: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO exploits_attempted (sl_no, exploit_name, tool_used, payload, result, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (sl_no, exploit_name, tool_used, payload, result, notes))
    conn.commit()
    conn.close()

def save_summary(sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str):
    conn = get_conn()
    cur = conn.cursor()
    now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        INSERT OR REPLACE INTO summary (sl_no, raw_scan, ai_analysis, risk_level, generated_at)
        VALUES (?, ?, ?, ?, ?)
    """, (sl_no, raw_scan, ai_analysis, risk_level, now))
    conn.commit()
    conn.close()

# --- DB read operations ---
def get_all_history():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def get_session(sl_no: int) -> dict:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM history WHERE sl_no = ?", (sl_no,))
    history = cur.fetchone()
    cur.execute("SELECT * FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    vulns = cur.fetchall()
    cur.execute("SELECT * FROM fixes WHERE sl_no = ?", (sl_no,))
    fixes = cur.fetchall()
    cur.execute("SELECT * FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    exploits = cur.fetchall()
    cur.execute("SELECT * FROM summary WHERE sl_no = ?", (sl_no,))
    summary = cur.fetchone()
    conn.close()
    return {"history": history, "vulns": vulns, "fixes": fixes,
            "exploits": exploits, "summary": summary}

def get_vulnerabilities(sl_no: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_fixes(sl_no: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM fixes WHERE sl_no = ?", (sl_no,))
    rows = cur.fetchall()
    conn.close()
    return rows

def get_exploits(sl_no: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    rows = cur.fetchall()
    conn.close()
    return rows

# --- DB edit / delete ---
def edit_vulnerability(vuln_id: int, field: str, value: str):
    allowed = {"vuln_name", "severity", "port", "service", "description"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(f"UPDATE vulnerabilities SET {field} = ? WHERE id = ?", (value, vuln_id))
    conn.commit()
    conn.close()
    print(f"[+] Updated vuln id={vuln_id}")

def edit_fix(fix_id: int, fix_text: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE fixes SET fix_text = ? WHERE id = ?", (fix_text, fix_id))
    conn.commit()
    conn.close()
    print(f"[+] Updated fix id={fix_id}")

def edit_exploit(exploit_id: int, field: str, value: str):
    allowed = {"exploit_name", "tool_used", "payload", "result", "notes"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}")
        return
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(f"UPDATE exploits_attempted SET {field} = ? WHERE id = ?", (value, exploit_id))
    conn.commit()
    conn.close()
    print(f"[+] Updated exploit id={exploit_id}")

def edit_summary_risk(sl_no: int, risk_level: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE summary SET risk_level = ? WHERE sl_no = ?", (risk_level, sl_no))
    conn.commit()
    conn.close()
    print(f"[+] Updated risk for SL#{sl_no}")

def delete_vulnerability(vuln_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM fixes WHERE vuln_id = ?", (vuln_id,))
    cur.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
    conn.commit()
    conn.close()
    print(f"[+] Deleted vulnerability id={vuln_id}")

def delete_exploit(exploit_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM exploits_attempted WHERE id = ?", (exploit_id,))
    conn.commit()
    conn.close()
    print(f"[+] Deleted exploit id={exploit_id}")

def delete_fix(fix_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM fixes WHERE id = ?", (fix_id,))
    conn.commit()
    conn.close()
    print(f"[+] Deleted fix id={fix_id}")

def delete_full_session(sl_no: int):
    conn = get_conn()
    cur = conn.cursor()
    # cascade will handle children if foreign keys are on, but we do explicit order to be safe
    cur.execute("DELETE FROM fixes WHERE sl_no = ?", (sl_no,))
    cur.execute("DELETE FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    cur.execute("DELETE FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    cur.execute("DELETE FROM summary WHERE sl_no = ?", (sl_no,))
    cur.execute("DELETE FROM history WHERE sl_no = ?", (sl_no,))
    conn.commit()
    conn.close()
    print(f"[+] Full session SL#{sl_no} deleted.")

# --- display helpers ---
def print_history(rows):
    print("\n" + "─"*65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─"*65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()

def print_session(data: dict):
    h = data["history"]
    if not h:
        print("[!] No session data.")
        return
    print(f"\n{'═'*60}")
    print(f"  SL# {h[0]} | Target: {h[1]} | {h[2]} | {h[3]}")
    print(f"{'═'*60}")
    print("\n[ VULNERABILITIES ]")
    if data["vulns"]:
        for v in data["vulns"]:
            print(f"  id={v[0]} | {v[2]} | Severity: {v[3]} | Port: {v[4]} | Service: {v[5]}")
            print(f"           {v[6]}")
    else:
        print("  None recorded.")
    print("\n[ FIXES ]")
    if data["fixes"]:
        for f in data["fixes"]:
            print(f"  id={f[0]} | vuln_id={f[2]} | [{f[4]}] {f[3]}")
    else:
        print("  None recorded.")
    print("\n[ EXPLOITS ATTEMPTED ]")
    if data["exploits"]:
        for e in data["exploits"]:
            print(f"  id={e[0]} | {e[2]} | Tool: {e[3]} | Result: {e[5]}")
            print(f"           Payload: {e[4]}")
            print(f"           Notes:   {e[6]}")
    else:
        print("  None recorded.")
    print("\n[ SUMMARY ]")
    if data["summary"]:
        s = data["summary"]
        print(f"  Risk Level : {s[3]}")
        print(f"  Generated  : {s[4]}")
        print(f"\n  AI Analysis:\n  {s[2][:500]}{'...' if len(str(s[2])) > 500 else ''}")
    else:
        print("  None recorded.")
    print()

# ----------------------------------------------------------------------
# 2. TOOLS (nmap, whois, whatweb, curl, dig, nikto)
# ----------------------------------------------------------------------
def run_tool(command: list, timeout: int = 120) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        output = result.stdout.strip()
        errors = result.stderr.strip()
        if output and errors:
            return output + "\n[STDERR]\n" + errors
        elif output:
            return output
        elif errors:
            return errors
        else:
            return "[!] Tool returned no output."
    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s: {' '.join(command)}"
    except FileNotFoundError:
        return f"[!] Tool not found: {command[0]} — install it with: sudo apt install {command[0]}"
    except Exception as e:
        return f"[!] Unexpected error: {e}"

def run_nmap(target: str) -> str:
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)

def run_whois(target: str) -> str:
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30)

def run_whatweb(target: str) -> str:
    print(f"  [*] whatweb -a 3 {target}")
    return run_tool(["whatweb", "-a", "3", target], timeout=60)

def run_curl_headers(target: str) -> str:
    print(f"  [*] curl -sI http://{target}")
    output = run_tool(["curl", "-sI", "--max-time", "10", "--location", f"http://{target}"], timeout=20)
    https_output = run_tool(["curl", "-sI", "--max-time", "10", "--location", "-k", f"https://{target}"], timeout=20)
    return f"[HTTP Headers]\n{output}\n\n[HTTPS Headers]\n{https_output}"

def run_dig(target: str) -> str:
    print(f"  [*] dig {target} ANY")
    a = run_tool(["dig", "+short", "A", target], timeout=15)
    mx = run_tool(["dig", "+short", "MX", target], timeout=15)
    ns = run_tool(["dig", "+short", "NS", target], timeout=15)
    txt = run_tool(["dig", "+short", "TXT", target], timeout=15)
    return f"[A Records]\n{a}\n\n[MX Records]\n{mx}\n\n[NS Records]\n{ns}\n\n[TXT Records]\n{txt}"

def run_nikto(target: str) -> str:
    print(f"  [*] nikto -h {target} (slow...)")
    return run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)

TOOLS_MENU = {
    "1": ("nmap", run_nmap),
    "2": ("whois", run_whois),
    "3": ("whatweb", run_whatweb),
    "4": ("curl headers", run_curl_headers),
    "5": ("dig DNS", run_dig),
    "6": ("nikto", run_nikto),
}

def run_default_recon(target: str) -> dict:
    print(f"\n[*] Starting recon on: {target}")
    print("─" * 50)
    results = {
        "nmap": run_nmap(target),
        "whois": run_whois(target),
        "whatweb": run_whatweb(target),
        "curl_headers": run_curl_headers(target),
        "dig": run_dig(target),
    }
    print("─" * 50)
    print("[+] Recon complete.\n")
    return results

def run_single_tool(tool_key: str, target: str) -> str:
    if tool_key in TOOLS_MENU:
        _, func = TOOLS_MENU[tool_key]
        return func(target)
    return f"[!] Unknown tool key: {tool_key}"

def format_recon_for_llm(results: dict) -> str:
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n[ {tool.upper()} OUTPUT ]\n{'='*50}\n{data.strip()}\n"
    return output

def run_tool_by_command(command_str: str) -> str:
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."
    blocked = ["rm", "dd", "mkfs", "shutdown", "reboot", "wget", "curl -o", "chmod"]
    if parts[0] in blocked:
        return f"[!] Blocked command: {parts[0]}"
    return run_tool(parts)

def interactive_tool_run(target: str) -> str:
    print("\n[ SELECT TOOLS TO RUN ]")
    for key, (name, _) in TOOLS_MENU.items():
        print(f"  [{key}] {name}")
    print("  [a] Run all (except nikto)")
    print("  [n] Run all + nikto (slow)")
    choice = input("\nChoice(s) e.g. 1 2 4 or a: ").strip().lower()
    if choice == "a":
        results = run_default_recon(target)
        return format_recon_for_llm(results)
    if choice == "n":
        results = run_default_recon(target)
        results["nikto"] = run_nikto(target)
        return format_recon_for_llm(results)
    combined = {}
    for key in choice.split():
        if key in TOOLS_MENU:
            name, func = TOOLS_MENU[key]
            print(f"\n[*] Running {name}...")
            combined[name] = func(target)
        else:
            print(f"[!] Unknown option: {key}")
    return format_recon_for_llm(combined)

# ----------------------------------------------------------------------
# 3. SEARCH (DuckDuckGo + page fetch)
# ----------------------------------------------------------------------
def web_search(query: str, max_results: int = 5) -> str:
    print(f"  [*] Searching: {query}")
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
        if not results:
            return "[!] No search results found."
        output = f"[WEB SEARCH RESULTS FOR: {query}]\n" + "─"*50 + "\n"
        for i, r in enumerate(results, 1):
            output += f"\n[{i}] {r['title']}\n    URL: {r['href']}\n    Snippet: {r['body']}\n"
        return output
    except Exception as e:
        return f"[!] Search failed: {e}"

def fetch_page(url: str, max_chars: int = 3000) -> str:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        text = soup.get_text(separator="\n", strip=True)
        lines = [l for l in text.splitlines() if l.strip()]
        clean = "\n".join(lines)
        if len(clean) > max_chars:
            clean = clean[:max_chars] + f"\n... [truncated at {max_chars} chars]"
        return clean
    except Exception as e:
        return f"[!] Fetch failed: {e}"

def search_cve(cve_id: str) -> str:
    print(f"  [*] Looking up {cve_id}...")
    ddg_results = web_search(f"{cve_id} vulnerability exploit details", max_results=3)
    mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    mitre_data = fetch_page(mitre_url, max_chars=2000)
    return f"{ddg_results}\n\n[MITRE CVE LOOKUP: {cve_id}]\n{mitre_data}"

def handle_search_dispatch(query: str) -> str:
    query = query.strip()
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    cve_match = cve_pattern.search(query)
    if cve_match:
        return search_cve(cve_match.group())
    if any(word in query.lower() for word in ["exploit", "poc", "payload", "rce", "lfi", "sqli"]):
        return web_search(query + " exploit poc github", max_results=5)
    if any(word in query.lower() for word in ["fix", "patch", "mitigate", "harden", "secure"]):
        return web_search(f"how to fix {query} security mitigation patch", max_results=3)
    return web_search(query, max_results=5)

# ----------------------------------------------------------------------
# 4. LLM (Ollama)
# ----------------------------------------------------------------------
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "metatron-qwen"   # custom name, ensure it exists (ollama create)
MAX_TOKENS = 4096
MAX_TOOL_LOOPS = 9
OLLAMA_TIMEOUT = 600

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
"""

def ask_ollama(prompt: str) -> str:
    try:
        payload = {
            "model": MODEL_NAME,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": MAX_TOKENS, "temperature": 0.7, "top_p": 0.9}
        }
        print(f"\n[*] Sending to {MODEL_NAME}...")
        resp = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        resp.raise_for_status()
        response = resp.json().get("response", "").strip()
        return response if response else "[!] Model returned empty response."
    except requests.exceptions.ConnectionError:
        return "[!] Cannot connect to Ollama. Is it running? Try: ollama serve"
    except Exception as e:
        return f"[!] Ollama error: {e}"

def extract_tool_calls(response: str) -> list:
    calls = []
    for m in re.findall(r'\[TOOL:\s*(.+?)\]', response):
        calls.append(("TOOL", m.strip()))
    for m in re.findall(r'\[SEARCH:\s*(.+?)\]', response):
        calls.append(("SEARCH", m.strip()))
    return calls

def run_tool_calls(calls: list) -> str:
    if not calls:
        return ""
    results = ""
    for typ, cont in calls:
        print(f"\n  [DISPATCH] {typ}: {cont}")
        if typ == "TOOL":
            out = run_tool_by_command(cont)
        elif typ == "SEARCH":
            out = handle_search_dispatch(cont)
        else:
            out = f"[!] Unknown type: {typ}"
        results += f"\n[{typ} RESULT: {cont}]\n" + "─"*40 + "\n" + out.strip() + "\n"
    return results

def parse_vulnerabilities(response: str) -> list:
    vulns = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("VULN:"):
            vuln = {"vuln_name": "", "severity": "medium", "port": "", "service": "", "description": "", "fix": ""}
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
            j = i+1
            while j < len(lines) and j <= i+5:
                nl = lines[j].strip()
                if nl.startswith("DESC:"):
                    vuln["description"] = nl.replace("DESC:", "").strip()
                elif nl.startswith("FIX:"):
                    vuln["fix"] = nl.replace("FIX:", "").strip()
                j += 1
            if vuln["vuln_name"]:
                vulns.append(vuln)
        i += 1
    return vulns

def parse_exploits(response: str) -> list:
    exploits = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("EXPLOIT:"):
            exp = {"exploit_name": "", "tool_used": "", "payload": "", "result": "unknown", "notes": ""}
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exp["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exp["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exp["payload"] = part.replace("PAYLOAD:", "").strip()
            j = i+1
            while j < len(lines) and j <= i+4:
                nl = lines[j].strip()
                if nl.startswith("RESULT:"):
                    exp["result"] = nl.replace("RESULT:", "").strip()
                elif nl.startswith("NOTES:"):
                    exp["notes"] = nl.replace("NOTES:", "").strip()
                j += 1
            if exp["exploit_name"]:
                exploits.append(exp)
        i += 1
    return exploits

def parse_risk_level(response: str) -> str:
    m = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    return m.group(1).upper() if m else "UNKNOWN"

def parse_summary(response: str) -> str:
    m = re.search(r'SUMMARY:\s*(.+)', response, re.IGNORECASE)
    return m.group(1).strip() if m else response[:500]

def analyse_target(target: str, raw_scan: str) -> dict:
    initial_prompt = f"""{SYSTEM_PROMPT}

TARGET: {target}

RECON DATA:
{raw_scan}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more information.
List all vulnerabilities, fixes, and suggest exploits where applicable.
"""
    full_conversation = initial_prompt
    final_response = ""
    for loop in range(MAX_TOOL_LOOPS):
        response = ask_ollama(full_conversation)
        print(f"\n{'─'*60}\n[METATRON - Round {loop+1}]\n{'─'*60}\n{response}")
        final_response = response
        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break
        tool_results = run_tool_calls(tool_calls)
        full_conversation += f"\n\n[YOUR PREVIOUS RESPONSE]\n{response}\n\n[TOOL RESULTS]\n{tool_results}\n\nContinue your analysis with this new information. If analysis is complete, give the final RISK_LEVEL and SUMMARY."
    vulns = parse_vulnerabilities(final_response)
    exploits = parse_exploits(final_response)
    risk = parse_risk_level(final_response)
    summary = parse_summary(final_response)
    print(f"\n[+] Parsed: {len(vulns)} vulns, {len(exploits)} exploits | Risk: {risk}")
    return {
        "full_response": final_response,
        "vulnerabilities": vulns,
        "exploits": exploits,
        "risk_level": risk,
        "summary": summary,
        "raw_scan": raw_scan
    }

# ----------------------------------------------------------------------
# 5. EXPORT (PDF / HTML)
# ----------------------------------------------------------------------
SEVERITY_COLORS = {"critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f", "low": "#27ae60", "unknown": "#7f8c8d"}
RISK_COLORS = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#27ae60", "UNKNOWN": "#7f8c8d"}

def export_pdf(data: dict, output_dir: str) -> str:
    h = data["history"]
    sl, tgt, date = h[0], h[1], str(h[2])
    risk = data["summary"][3] if data["summary"] else "UNKNOWN"
    ai_analysis = data["summary"][2] if data["summary"] else ""
    os.makedirs(output_dir, exist_ok=True)
    safe = tgt.replace("https://","").replace("http://","").replace("/","_").replace(".","_")
    filename = os.path.join(output_dir, f"metatron_SL{sl}_{safe}.pdf")
    doc = SimpleDocTemplate(filename, pagesize=A4, topMargin=15*mm, bottomMargin=15*mm, leftMargin=15*mm, rightMargin=15*mm)
    title_style = ParagraphStyle("t", fontSize=22, fontName="Helvetica-Bold", textColor=colors.HexColor("#c0392b"), spaceAfter=4)
    sub_style = ParagraphStyle("s", fontSize=10, fontName="Helvetica", textColor=colors.HexColor("#555555"), spaceAfter=2)
    h1_style = ParagraphStyle("h1", fontSize=13, fontName="Helvetica-Bold", textColor=colors.HexColor("#2c3e50"), spaceBefore=10, spaceAfter=4)
    body_style = ParagraphStyle("b", fontSize=9, fontName="Helvetica", textColor=colors.black, leading=13)
    code_style = ParagraphStyle("c", fontSize=7.5, fontName="Courier", textColor=colors.HexColor("#2c3e50"), backColor=colors.HexColor("#f4f4f4"), leading=11, leftIndent=6, rightIndent=6, spaceBefore=2, spaceAfter=2)
    footer_style = ParagraphStyle("f", fontSize=7, textColor=colors.HexColor("#aaaaaa"), alignment=TA_CENTER)
    story = []
    story.append(Paragraph("METATRON", title_style))
    story.append(Paragraph("AI Penetration Testing Report", sub_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#c0392b"), spaceAfter=8))
    risk_color = colors.HexColor(RISK_COLORS.get(risk.upper(), "#7f8c8d"))
    meta = [["Target", tgt], ["Scan Date", date], ["Session", f"SL# {sl}"], ["Risk Level", risk], ["Generated", dt.now().strftime("%Y-%m-%d %H:%M:%S")]]
    mt = Table(meta, colWidths=[35*mm, 130*mm])
    mt.setStyle(TableStyle([("FONTNAME", (0,0), (-1,-1), "Helvetica"), ("FONTSIZE", (0,0), (-1,-1), 9),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"), ("TEXTCOLOR", (0,0), (0,-1), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (1,3), (1,3), risk_color), ("FONTNAME", (1,3), (1,3), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white]),
        ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")), ("PADDING", (0,0), (-1,-1), 5)]))
    story.append(mt)
    story.append(Spacer(1, 10))
    story.append(Paragraph("Vulnerabilities", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["vulns"]:
        vd = [["#", "Vulnerability", "Severity", "Port", "Service"]]
        for v in data["vulns"]:
            vd.append([str(v[0]), str(v[2] or "-"), str(v[3] or "-").upper(), str(v[4] or "-"), str(v[5] or "-")])
        vt = Table(vd, colWidths=[10*mm, 72*mm, 24*mm, 18*mm, 28*mm], repeatRows=1)
        vts = [("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 8),
               ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#2c3e50")), ("TEXTCOLOR", (0,0), (-1,0), colors.white),
               ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")), ("PADDING", (0,0), (-1,-1), 5),
               ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white])]
        for i, v in enumerate(data["vulns"], 1):
            sc = colors.HexColor(SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d"))
            vts.append(("TEXTCOLOR", (2,i), (2,i), sc))
            vts.append(("FONTNAME", (2,i), (2,i), "Helvetica-Bold"))
        vt.setStyle(TableStyle(vts))
        story.append(vt)
        story.append(Spacer(1, 6))
        story.append(Paragraph("Vulnerability Details", h1_style))
        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=6))
        for v in data["vulns"]:
            sc = colors.HexColor(SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d"))
            lbl = ParagraphStyle("vl", fontSize=9, fontName="Helvetica-Bold", textColor=sc)
            story.append(Paragraph(f"[{(v[3] or 'UNKNOWN').upper()}] {v[2]}", lbl))
            if v[6]:
                story.append(Paragraph(str(v[6]), body_style))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No vulnerabilities recorded.", body_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Fixes & Mitigations", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["fixes"]:
        for f in data["fixes"]:
            story.append(Paragraph(f"Fix for vuln id={f[2]}:", body_style))
            story.append(Paragraph(str(f[3] or "-"), code_style))
            story.append(Spacer(1, 3))
    else:
        story.append(Paragraph("No fixes recorded.", body_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Exploits Attempted", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["exploits"]:
        ed = [["#", "Exploit", "Tool", "Result"]]
        for e in data["exploits"]:
            ed.append([str(e[0]), str(e[2] or "-")[:60], str(e[3] or "-")[:30], str(e[5] or "-")[:30]])
        et = Table(ed, colWidths=[10*mm, 80*mm, 40*mm, 28*mm])
        et.setStyle(TableStyle([("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"), ("FONTSIZE", (0,0), (-1,-1), 8),
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#2c3e50")), ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")), ("PADDING", (0,0), (-1,-1), 5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white])]))
        story.append(et)
    else:
        story.append(Paragraph("No exploits recorded.", body_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph("AI Analysis Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=6))
    if ai_analysis:
        for line in str(ai_analysis).split("\n"):
            line = line.strip()
            if line:
                story.append(Paragraph(line, body_style))
                story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("No AI analysis recorded.", body_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#dddddd"), spaceAfter=4))
    story.append(Paragraph("Generated by METATRON — AI Penetration Testing Assistant | For authorized use only.", footer_style))
    doc.build(story)
    return filename

def export_html(data: dict, output_dir: str) -> str:
    h = data["history"]
    sl, tgt, date = h[0], h[1], str(h[2])
    risk = data["summary"][3] if data["summary"] else "UNKNOWN"
    ai_analysis = data["summary"][2] if data["summary"] else ""
    rc = RISK_COLORS.get(risk.upper(), "#7f8c8d")
    os.makedirs(output_dir, exist_ok=True)
    safe = tgt.replace("https://","").replace("http://","").replace("/","_").replace(".","_")
    filename = os.path.join(output_dir, f"metatron_SL{sl}_{safe}.html")
    vuln_rows = ""
    for v in data["vulns"]:
        sc = SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d")
        vuln_rows += f"<tr><td>{v[0]}</td><td><strong>{v[2]}</strong><br><small>{v[6] or ''}</small></td><td style='color:{sc};font-weight:bold'>{(v[3] or 'unknown').upper()}</td><td>{v[4] or '-'}</td><td>{v[5] or '-'}</td></tr>"
    fix_rows = ""
    for f in data["fixes"]:
        fix_rows += f"<tr><td>{f[0]}</td><td>vuln #{f[2]}</td><td><code>{f[3] or '-'}</code></td><td>{f[4] or 'ai'}</td></tr>"
    exp_rows = ""
    for e in data["exploits"]:
        exp_rows += f"<tr><td>{e[0]}</td><td>{e[2] or '-'}</td><td>{e[3] or '-'}</td><td><code>{str(e[4] or '-')[:80]}</code></td><td>{e[5] or '-'}</td></tr>"
    ai_html = "".join(f"<p>{line}</p>" for line in str(ai_analysis).split("\n") if line.strip())
    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Metatron Report — {tgt}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}body{{background:#0d0d0d;color:#e0e0e0;font-family:'Segoe UI',sans-serif;padding:30px}}
.container{{max-width:960px;margin:auto}}.header{{border-left:5px solid #c0392b;padding-left:16px;margin-bottom:30px}}
.header h1{{font-size:2.2em;color:#c0392b}}.header p{{color:#888;font-size:.95em}}
.meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:30px}}
.meta-card{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:14px}}
.meta-card .label{{font-size:.75em;color:#888;text-transform:uppercase;margin-bottom:4px}}
.meta-card .value{{font-size:1.1em;font-weight:bold}}.risk{{color:{rc}}}
section{{margin-bottom:30px}}section h2{{font-size:1.2em;color:#c0392b;border-bottom:1px solid #333;padding-bottom:8px;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;font-size:.88em}}th{{background:#1e1e1e;color:#aaa;text-align:left;padding:10px;border-bottom:2px solid #333}}
td{{padding:10px;border-bottom:1px solid #222;vertical-align:top}}tr:hover td{{background:#1a1a1a}}
code{{background:#1e1e1e;padding:2px 6px;border-radius:3px;font-family:monospace;font-size:.85em;color:#e74c3c}}
.ai-box{{background:#111;border:1px solid #333;border-radius:6px;padding:16px;font-size:.9em;line-height:1.7;color:#ccc}}
.footer{{text-align:center;color:#444;font-size:.78em;margin-top:40px;border-top:1px solid #222;padding-top:16px}}
</style></head>
<body><div class="container">
<div class="header"><h1>🔱 METATRON</h1><p>AI Penetration Testing Report</p></div>
<div class="meta-grid"><div class="meta-card"><div class="label">Target</div><div class="value">{tgt}</div></div>
<div class="meta-card"><div class="label">Session</div><div class="value">SL# {sl}</div></div>
<div class="meta-card"><div class="label">Scan Date</div><div class="value">{date}</div></div>
<div class="meta-card"><div class="label">Risk Level</div><div class="value risk">{risk}</div></div></div>
<section><h2>Vulnerabilities</h2>{'<table><thead><tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>Port</th><th>Service</th></tr></thead><tbody>' + vuln_rows + '</tbody></table>' if data["vulns"] else '<p>None recorded.</p>'}</section>
<section><h2>Fixes &amp; Mitigations</h2>{'<table><thead><tr><th>#</th><th>Vuln</th><th>Fix</th><th>Source</th></tr></thead><tbody>' + fix_rows + '</tbody></table>' if data["fixes"] else '<p>None recorded.</p>'}</section>
<section><h2>Exploits Attempted</h2>{'<table><thead><tr><th>#</th><th>Exploit</th><th>Tool</th><th>Payload</th><th>Result</th></tr></thead><tbody>' + exp_rows + '</tbody></table>' if data["exploits"] else '<p>None recorded.</p>'}</section>
<section><h2>AI Analysis Summary</h2><div class="ai-box">{ai_html if ai_html else '<p>None recorded.</p>'}</div></section>
<div class="footer">Generated by METATRON — For authorized use only.</div>
</div></body></html>"""
    with open(filename, "w") as f:
        f.write(html)
    return filename

def export_menu(data: dict):
    if not data["history"]:
        print("[!] No session data to export.")
        return
    sl, tgt = data["history"][0], data["history"][1]
    print(f"\n\033[33m{'─'*20} EXPORT SL#{sl} — {tgt} {'─'*20}\033[0m")
    print("  [1] PDF report\n  [2] HTML report\n  [3] Both\n  [4] Back")
    choice = input("\033[36mExport format: \033[0m").strip()
    out_dir = os.path.expanduser("~/METATRON/reports")
    os.makedirs(out_dir, exist_ok=True)
    if choice == "1":
        p = export_pdf(data, out_dir)
        print(f"\033[92m[+] PDF saved: {p}\033[0m")
    elif choice == "2":
        p = export_html(data, out_dir)
        print(f"\033[92m[+] HTML saved: {p}\033[0m")
    elif choice == "3":
        p1 = export_pdf(data, out_dir)
        p2 = export_html(data, out_dir)
        print(f"\033[92m[+] PDF: {p1}\033[0m\n\033[92m[+] HTML: {p2}\033[0m")
    elif choice == "4":
        return
    else:
        print("\033[93m[!] Invalid choice.\033[0m")

# ----------------------------------------------------------------------
# 6. MAIN MENU (CLI)
# ----------------------------------------------------------------------
def banner():
    os.system("clear")
    print("""
\033[91m
    ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗
    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
    ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
    \033[90mAI Penetration Testing Assistant  |  SQLite backend  |  Parrot OS\033[0m
    \033[90m─────────────────────────────────────────────────────────────────────\033[0m
""")

def prompt(text):
    return input(f"\033[36m{text}\033[0m").strip()

def success(text):
    print(f"\033[92m[+] {text}\033[0m")

def warn(text):
    print(f"\033[93m[!] {text}\033[0m")

def error(text):
    print(f"\033[91m[✗] {text}\033[0m")

def confirm(question: str) -> bool:
    return prompt(f"{question} [y/N]").lower() == "y"

def new_scan():
    print("\n\033[33m" + "─"*20 + " NEW SCAN " + "─"*20 + "\033[0m")
    target = prompt("[?] Enter target IP or domain: ")
    if not target:
        warn("No target entered.")
        return
    history = get_all_history()
    if any(row[1] == target for row in history):
        warn(f"Target '{target}' has been scanned before.")
        if not confirm("Continue with a new scan?"):
            return
    sl_no = create_session(target)
    success(f"Session created — SL# {sl_no}")
    raw_scan = interactive_tool_run(target)
    if not raw_scan.strip():
        warn("No scan data collected. Aborting.")
        delete_full_session(sl_no)
        return
    print("\n\033[33m" + "─"*20 + " AI ANALYSIS " + "─"*20 + "\033[0m")
    result = analyse_target(target, raw_scan)
    print("\n\033[33m" + "─"*20 + " SAVING TO DATABASE " + "─"*20 + "\033[0m")
    for vuln in result["vulnerabilities"]:
        vid = save_vulnerability(sl_no, vuln["vuln_name"], vuln["severity"], vuln["port"], vuln["service"], vuln["description"])
        if vuln.get("fix"):
            save_fix(sl_no, vid, vuln["fix"], source="ai")
        success(f"Saved vuln: {vuln['vuln_name']} [{vuln['severity']}]")
    for exp in result["exploits"]:
        save_exploit(sl_no, exp["exploit_name"], exp["tool_used"], exp["payload"], exp["result"], exp["notes"])
        success(f"Saved exploit: {exp['exploit_name']}")
    save_summary(sl_no, result["raw_scan"], result["full_response"], result["risk_level"])
    success(f"All data saved. SL# {sl_no} | Risk: {result['risk_level']}")
    data = get_session(sl_no)
    print_session(data)
    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)

def view_history():
    print("\n\033[33m" + "─"*20 + " SCAN HISTORY " + "─"*20 + "\033[0m")
    rows = get_all_history()
    if not rows:
        warn("No scans in database yet.")
        return
    print_history(rows)
    sl_str = prompt("Enter SL# to view details (or Enter to go back): ")
    if not sl_str:
        return
    try:
        sl_no = int(sl_str)
    except ValueError:
        error("Invalid SL#.")
        return
    data = get_session(sl_no)
    if not data["history"]:
        error(f"SL# {sl_no} not found.")
        return
    print_session(data)
    if confirm("Export this session?"):
        export_menu(data)
    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)

def edit_delete_menu(sl_no: int):
    while True:
        print(f"\n\033[33m{'─'*20} EDIT / DELETE — SL# {sl_no} {'─'*20}\033[0m")
        print("  [1] Edit a vulnerability\n  [2] Edit a fix\n  [3] Edit an exploit\n  [4] Edit risk level")
        print("  [5] Delete a vulnerability\n  [6] Delete a fix\n  [7] Delete an exploit\n  [8] Delete FULL session (all tables)\n  [9] Back")
        choice = prompt("Choice: ")
        if choice == "1":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities.")
                continue
            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]} | port {v[4]} | {v[5]}")
            vid = prompt("Enter vulnerability id to edit: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue
            field = prompt("Field to edit (vuln_name/severity/port/service/description): ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_vulnerability(int(vid), field, value)
        elif choice == "2":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes.")
                continue
            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")
            fid = prompt("Enter fix id to edit: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue
            new_text = prompt("New fix text: ")
            edit_fix(int(fid), new_text)
        elif choice == "3":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits.")
                continue
            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | tool: {e[3]} | result: {e[5]}")
            eid = prompt("Enter exploit id to edit: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue
            field = prompt("Field to edit (exploit_name/tool_used/payload/result/notes): ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_exploit(int(eid), field, value)
        elif choice == "4":
            print("  Options: CRITICAL / HIGH / MEDIUM / LOW")
            risk = prompt("New risk level: ").upper()
            if risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                error("Invalid risk level.")
                continue
            edit_summary_risk(sl_no, risk)
        elif choice == "5":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities.")
                continue
            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]}")
            vid = prompt("Enter vulnerability id to delete: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue
            if confirm(f"Delete vulnerability id={vid} and its linked fixes?"):
                delete_vulnerability(int(vid))
        elif choice == "6":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes.")
                continue
            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")
            fid = prompt("Enter fix id to delete: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue
            if confirm(f"Delete fix id={fid}?"):
                delete_fix(int(fid))
        elif choice == "7":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits.")
                continue
            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | result: {e[5]}")
            eid = prompt("Enter exploit id to delete: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue
            if confirm(f"Delete exploit id={eid}?"):
                delete_exploit(int(eid))
        elif choice == "8":
            if confirm(f"\n\033[91mPermanently delete ENTIRE session SL# {sl_no} from all tables?\033[0m"):
                delete_full_session(sl_no)
                success(f"Session SL#{sl_no} wiped.")
                return
        elif choice == "9":
            break
        else:
            warn("Invalid choice.")

def main_menu():
    while True:
        banner()
        print("  \033[92m[1]\033[0m  New Scan")
        print("  \033[92m[2]\033[0m  View History")
        print("  \033[92m[3]\033[0m  Exit")
        print("\033[90m" + "─"*60 + "\033[0m")
        choice = prompt("metatron> ")
        if choice == "1":
            new_scan()
            input("\n\033[90mPress Enter to continue...\033[0m")
        elif choice == "2":
            view_history()
            input("\n\033[90mPress Enter to continue...\033[0m")
        elif choice == "3":
            print("\n\033[91m[*] Shutting down Metatron. Stay legal.\033[0m\n")
            sys.exit(0)
        else:
            warn("Invalid choice.")

# ----------------------------------------------------------------------
# 7. ENTRY POINT
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # ensure database exists
    init_db()
    # quick check for Ollama (optional)
    try:
        requests.get("http://localhost:11434", timeout=2)
    except:
        warn("Ollama not reachable. Make sure it's running (ollama serve) and the model 'metatron-qwen' is created.")
    main_menu()
