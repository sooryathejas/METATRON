#!/usr/bin/env python3
"""
METATRON - tools.py
Recon tool runners — all output returned as strings to feed into the LLM.
Tools used: nmap, whois, whatweb, curl, dig, nikto
OS: Parrot OS (all these tools are pre-installed or easily available)
"""

import subprocess
import re
from urllib.parse import urljoin, urlparse


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────

def run_tool(command: list, timeout: int = 120) -> str:
    """
    Execute a shell command, return combined stdout + stderr as string.
    Never crashes the program — always returns something.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
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
        return f"[!] Unexpected error running {command[0]}: {e}"


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    """
    nmap -sV -sC -T4 --open
    -sV  : detect service versions
    -sC  : run default scripts (basic vuln checks)
    -T4  : aggressive timing (faster)
    --open : only show open ports
    """
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_whois(target: str) -> str:
    """
    whois — domain registration, registrar, IP ownership info
    """
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30)


def run_whatweb(target: str) -> str:
    """
    whatweb -a 3 — fingerprint web technologies, CMS, frameworks, headers
    -a 3 : aggression level 3 (active but not destructive)
    """
    print(f"  [*] whatweb -a 3 {target}")
    return run_tool(["whatweb", "-a", "3", target], timeout=60)


def _redirect_stays_on_target(location: str, target: str) -> bool:
    if not location:
        return False
    parsed = urlparse(location)
    if not parsed.netloc:
        return True  # redirect relative, same host
    return (parsed.hostname or "").lower() == target.lower()


def _fetch_headers_no_redirect(url: str) -> tuple:
    command = ["curl", "-sI", "--max-time", "10"]
    if urlparse(url).scheme.lower() == "https":
        command.append("-k")
    result = run_tool(command + [url], timeout=20)
    location = ""
    for line in result.splitlines():
        if line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()
            break
    return result, location


def _fetch_headers_with_safe_redirect(url: str, target: str) -> str:
    result, location = _fetch_headers_no_redirect(url)
    if not location:
        return result
    if not _redirect_stays_on_target(location, target):
        return f"[!] Redirect to different host blocked: {location}"
    return _fetch_headers_no_redirect(urljoin(url, location))[0]


def run_curl_headers(target: str) -> str:
    """
    curl -sI — fetch HTTP headers only
    Reveals: server software, X-Powered-By, cookies, security headers (or lack of them)
    """
    print(f"  [*] curl -sI http://{target}")
    output = _fetch_headers_with_safe_redirect(f"http://{target}", target)

    # also try https
    https_output = _fetch_headers_with_safe_redirect(f"https://{target}", target)

    return f"[HTTP Headers]\n{output}\n\n[HTTPS Headers]\n{https_output}"


def run_dig(target: str) -> str:
    """
    dig — DNS records: A, MX, NS, TXT
    Useful for subdomains, mail servers, SPF/DKIM info
    """
    print(f"  [*] dig {target} ANY")
    a_record  = run_tool(["dig", "+short", "A",   target], timeout=15)
    mx_record = run_tool(["dig", "+short", "MX",  target], timeout=15)
    ns_record = run_tool(["dig", "+short", "NS",  target], timeout=15)
    txt_record= run_tool(["dig", "+short", "TXT", target], timeout=15)

    return (
        f"[A Records]\n{a_record}\n\n"
        f"[MX Records]\n{mx_record}\n\n"
        f"[NS Records]\n{ns_record}\n\n"
        f"[TXT Records]\n{txt_record}"
    )


def run_nikto(target: str) -> str:
    """
    nikto -h — web server vulnerability scanner
    Checks for outdated software, dangerous files, misconfigurations
    WARNING: noisy tool, only run with permission
    """
    print(f"  [*] nikto -h {target}  (this may take a while...)")
    return run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)


# ─────────────────────────────────────────────
# MAIN RECON PIPELINE
# ─────────────────────────────────────────────

TOOLS_MENU = {
    "1": ("nmap",         run_nmap),
    "2": ("whois",        run_whois),
    "3": ("whatweb",      run_whatweb),
    "4": ("curl headers", run_curl_headers),
    "5": ("dig DNS",      run_dig),
    "6": ("nikto",        run_nikto),
}


def run_default_recon(target: str) -> dict:
    """
    Run the standard recon pipeline (everything except nikto).
    Returns a dict of {tool_name: output_string}.
    Nikto is excluded by default — too slow/noisy for auto-run.
    """
    print(f"\n[*] Starting recon on: {target}")
    print("─" * 50)

    results = {}
    results["nmap"]         = run_nmap(target)
    results["whois"]        = run_whois(target)
    results["whatweb"]      = run_whatweb(target)
    results["curl_headers"] = run_curl_headers(target)
    results["dig"]          = run_dig(target)

    print("─" * 50)
    print("[+] Recon complete.\n")
    return results


def run_single_tool(tool_key: str, target: str) -> str:
    """Run one tool by its menu key. Used by AI tool dispatch."""
    if tool_key in TOOLS_MENU:
        name, func = TOOLS_MENU[tool_key]
        return func(target)
    return f"[!] Unknown tool key: {tool_key}"


def format_recon_for_llm(results: dict) -> str:
    """
    Flatten the recon results dict into one clean string
    to paste into the LLM prompt.
    """
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'='*50}\n"
        output += data.strip() + "\n"
    return output


ALLOWED_TOOLS = {"nmap", "whois", "whatweb", "curl", "dig", "nikto"}
_IP_OR_HOST_RE = re.compile(
    r'^(?:\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+)$'
)


def _looks_like_host(arg: str):
    candidate = arg
    if "://" in arg:
        candidate = urlparse(arg).hostname or ""
    if not candidate or candidate.startswith("-"):
        return None
    return candidate if _IP_OR_HOST_RE.match(candidate) else None


def _matches_target(host: str, target: str) -> bool:
    host, target = host.lower(), target.lower()
    return host == target or host.endswith("." + target)


def run_tool_by_command(command_str: str, target: str) -> str:
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."
    
    # allowlist only — reject anything not in the list
    tool = parts[0].lower().split("/")[-1]  # handles /bin/nmap etc
    if tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{parts[0]}' is not permitted. Allowed: {ALLOWED_TOOLS}"

    for arg in parts[1:]:
        host = _looks_like_host(arg)
        if host and not _matches_target(host, target):
            return (
                f"[!] Blocked: argument '{arg}' targets '{host}', which is outside "
                f"the authorized session target '{target}'. Tool not run."
            )
    
    return run_tool(parts)

# ─────────────────────────────────────────────
# INTERACTIVE TOOL SELECTOR (called from CLI)
# ─────────────────────────────────────────────

def interactive_tool_run(target: str) -> str:
    """
    Let user manually pick which tools to run.
    Returns combined output string.
    """
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


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    target = input("Enter test target (IP or domain): ").strip()
    results = run_default_recon(target)
    print(format_recon_for_llm(results))
