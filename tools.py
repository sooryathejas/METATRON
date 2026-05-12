#!/usr/bin/env python3
"""
METATRON - tools.py
Recon tool runners — all output returned as strings to feed into the LLM.
Tools used: nmap, whois, whatweb, curl, dig, nikto, sslscan, testssl.sh
OS: Parrot OS (all these tools are pre-installed or easily available)
"""

import re
import subprocess


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


def run_curl_headers(target: str) -> str:
    """
    curl -sI — fetch HTTP headers only
    Reveals: server software, X-Powered-By, cookies, security headers (or lack of them)
    """
    print(f"  [*] curl -sI http://{target}")
    output = run_tool([
        "curl", "-sI",
        "--max-time", "10",
        "--location",          # follow redirects
        f"http://{target}"
    ], timeout=20)

    # also try https
    https_output = run_tool([
        "curl", "-sI",
        "--max-time", "10",
        "--location",
        "-k",                  # ignore cert errors
        f"https://{target}"
    ], timeout=20)

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


def run_sslscan(target: str) -> str:
    """
    sslscan — quick TLS/SSL scan for certificates, protocol support and ciphers.
    """
    print(f"  [*] sslscan --no-colour {target}")
    output = run_tool(["sslscan", "--no-colour", target], timeout=240)
    metadata = extract_ssl_metadata("sslscan", output)
    return f"{metadata}\n\n[SSLSCAN RAW OUTPUT]\n{output}"


def run_testssl(target: str) -> str:
    """
    testssl.sh — deeper TLS/SSL analysis for protocol, cipher and cert vulnerabilities.
    """
    print(f"  [*] testssl.sh --quiet {target}")
    output = run_tool(["testssl.sh", "--quiet", target], timeout=300)
    metadata = extract_ssl_metadata("testssl.sh", output)
    return f"{metadata}\n\n[TESTSSL.SH RAW OUTPUT]\n{output}"


def extract_ssl_metadata(tool_name: str, output: str) -> str:
    """
    Extract security-relevant SSL/TLS metadata from sslscan or testssl.sh output.
    Returns a short structured summary to improve AI context.
    """
    if not output or output.startswith("[!]"):
        return f"[SSL METADATA] No valid {tool_name} output available."

    subject = re.search(r"subject:\s*(.+)", output, re.IGNORECASE)
    issuer = re.search(r"issuer:\s*(.+)", output, re.IGNORECASE)
    not_before = re.search(r"not before:\s*(.+)", output, re.IGNORECASE)
    not_after = re.search(r"not after\s*:\s*(.+)", output, re.IGNORECASE)

    protocol_lines = []
    cipher_lines = []
    warning_lines = []

    for line in output.splitlines():
        text = line.strip()
        if re.search(r"^(SSLv2|SSLv3|TLSv1(?:\.\d)?)", text, re.IGNORECASE) and re.search(r"offered|not offered|supported|not supported|yes|no|A|B|C|D", text, re.IGNORECASE):
            protocol_lines.append(text)
        if re.search(r"^(TLS|SSL).+ - [A-Z]$", text):
            cipher_lines.append(text)
        if re.search(r"\b(weak|insecure|vulnerable|POODLE|BEAST|FREAK|LOGJAM|RC4|SWEET32|Heartbleed|insecure renegotiation|anonymous DH)\b", text, re.IGNORECASE):
            warning_lines.append(text)

    metadata = ["[SSL METADATA]"]
    metadata.append(f"Tool: {tool_name}")
    if subject:
        metadata.append(f"Subject: {subject.group(1).strip()}")
    if issuer:
        metadata.append(f"Issuer: {issuer.group(1).strip()}")
    if not_before:
        metadata.append(f"Valid from: {not_before.group(1).strip()}")
    if not_after:
        metadata.append(f"Valid until: {not_after.group(1).strip()}")
    if protocol_lines:
        metadata.append("Supported protocol lines:")
        metadata.extend(protocol_lines[:8])
    if cipher_lines:
        metadata.append("Sample ciphers:")
        metadata.extend(cipher_lines[:8])
    if warning_lines:
        metadata.append("Potential SSL issues:")
        metadata.extend(warning_lines[:8])

    if len(metadata) == 1:
        metadata.append("No SSL metadata extracted.")

    return "\n".join(metadata)


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
    "7": ("sslscan",      run_sslscan),
    "8": ("testssl.sh",   run_testssl),
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


ALLOWED_TOOLS = {"nmap", "whois", "whatweb", "curl", "dig", "nikto", "sslscan", "testssl.sh"}

def run_tool_by_command(command_str: str) -> str:
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."
    
    # allowlist only — reject anything not in the list
    tool = parts[0].lower().split("/")[-1]  # handles /bin/nmap etc
    if tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{parts[0]}' is not permitted. Allowed: {ALLOWED_TOOLS}"
    
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
