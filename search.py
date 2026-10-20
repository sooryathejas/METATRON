#!/usr/bin/env python3
"""
METATRON - search.py
Free web search via DuckDuckGo — no API key needed.
Also fetches and extracts plain text from URLs.
Used by LLM tool dispatch when AI writes [SEARCH: query]
"""

import requests
import os
import uuid
from dataclasses import dataclass, field
from bs4 import BeautifulSoup
from ddgs import DDGS   # pip install duckduckgo-search


@dataclass(frozen=True)
class SearchContext:
    """Provider choice and opaque identity owned by one analysis, not a client."""

    provider: str = field(default_factory=lambda: os.environ.get(
        "METATRON_SEARCH_PROVIDER", "duckduckgo"
    ).strip().lower())
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))


# ─────────────────────────────────────────────
# DDG SEARCH
# ─────────────────────────────────────────────

def web_search(query: str, max_results: int = 5) -> str:
    """
    Search DuckDuckGo and return formatted results.
    No API key. No rate limit issues for reasonable usage.
    Returns a string ready to paste into LLM prompt.
    """
    print(f"  [*] Searching: {query}")
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return "[!] No search results found."

        output = f"[WEB SEARCH RESULTS FOR: {query}]\n"
        output += "─" * 50 + "\n"
        for i, r in enumerate(results, 1):
            output += f"\n[{i}] {r['title']}\n"
            output += f"    URL     : {r['href']}\n"
            output += f"    Snippet : {r['body']}\n"

        return output

    except Exception as e:
        return f"[!] Search failed: {e}"


# ─────────────────────────────────────────────
# CVE SPECIFIC SEARCH
# ─────────────────────────────────────────────

def search_cve(cve_id: str) -> str:
    """
    Search for a specific CVE.
    Queries DDG then also hits cve.mitre.org directly.
    """
    print(f"  [*] Looking up {cve_id}...")

    # DDG search first
    ddg_results = web_search(f"{cve_id} vulnerability exploit details", max_results=3)

    # Direct MITRE fetch
    mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    mitre_data = fetch_page(mitre_url, max_chars=2000)

    return f"{ddg_results}\n\n[MITRE CVE LOOKUP: {cve_id}]\n{mitre_data}"


def search_exploit(service: str, version: str) -> str:
    """
    Search for known exploits for a service + version combo.
    e.g. search_exploit("apache", "2.4.49")
    """
    query = f"{service} {version} exploit CVE vulnerability 2023 2024"
    return web_search(query, max_results=5)


def search_fix(vuln_name: str) -> str:
    """
    Search for mitigation/fix for a vulnerability.
    """
    query = f"how to fix {vuln_name} security mitigation patch"
    return web_search(query, max_results=3)


# ─────────────────────────────────────────────
# PAGE FETCHER
# ─────────────────────────────────────────────

def fetch_page(url: str, max_chars: int = 3000) -> str:
    """
    Fetch a URL and return extracted plain text.
    Strips all HTML tags. Truncated to max_chars for LLM context.
    """
    try:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")

        # remove nav/footer/script noise
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()

        text = soup.get_text(separator="\n", strip=True)

        # collapse blank lines
        lines = [l for l in text.splitlines() if l.strip()]
        clean = "\n".join(lines)

        if len(clean) > max_chars:
            clean = clean[:max_chars] + f"\n... [truncated at {max_chars} chars]"

        return clean

    except requests.exceptions.ConnectionError:
        return "[!] Could not connect to URL — check network."
    except requests.exceptions.Timeout:
        return "[!] Page fetch timed out."
    except requests.exceptions.HTTPError as e:
        return f"[!] HTTP error: {e}"
    except Exception as e:
        return f"[!] Fetch failed: {e}"


# ─────────────────────────────────────────────
# TOOL DISPATCH HANDLER
# ─────────────────────────────────────────────

def handle_search_dispatch(query: str, context: SearchContext = None) -> str:
    """
    Called by llm.py when AI writes [SEARCH: something].
    Smartly routes to CVE lookup, exploit search, or general search.
    """
    context = context or SearchContext()
    if context.provider == "none":
        return "[!] Web search is disabled (METATRON_SEARCH_PROVIDER=none)."
    if context.provider == "parallel":
        from parallel_search import dispatch
        return dispatch(query.strip(), context.session_id)
    if context.provider != "duckduckgo":
        return "[!] Unknown METATRON_SEARCH_PROVIDER. Use duckduckgo, parallel or none."

    query = query.strip()

    # CVE pattern — CVE-YYYY-NNNNN
    import re
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    cve_match = cve_pattern.search(query)
    if cve_match:
        return search_cve(cve_match.group())

    # exploit keywords
    if any(word in query.lower() for word in ["exploit", "poc", "payload", "rce", "lfi", "sqli"]):
        return web_search(query + " exploit poc github", max_results=5)

    # fix/patch keywords
    if any(word in query.lower() for word in ["fix", "patch", "mitigate", "harden", "secure"]):
        return search_fix(query)

    # default general search
    return web_search(query, max_results=5)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ search.py test ]\n")
    print("[1] General search")
    print("[2] CVE lookup")
    print("[3] Fetch a URL")
    choice = input("Choice: ").strip()

    if choice == "1":
        q = input("Query: ").strip()
        print(handle_search_dispatch(q))

    elif choice == "2":
        cve = input("CVE ID (e.g. CVE-2021-44228): ").strip()
        print(handle_search_dispatch(cve))

    elif choice == "3":
        url = input("URL: ").strip()
        print(fetch_page(url))
