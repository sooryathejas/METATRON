#!/usr/bin/env python3
"""
Benchmark script for FLM models with METATRON.
Auto-starts/stops the FLM server for each model and saves results.
"""

import time
import sys
import os
import subprocess
import signal
import json
from datetime import datetime
from llm import parse_vulnerabilities, parse_exploits, parse_risk_level


def load_system_prompt() -> str:
    try:
        with open("config/system_prompt.txt", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "You are METATRON, an elite AI penetration testing assistant. Be precise and technical."


TEST_PROMPT = [
    {"role": "system", "content": load_system_prompt()},
    {"role": "user", "content": """TARGET: scanme.nmap.org

RECON DATA:
nmap -sV scanme.nmap.org
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))

Analyze this target. List vulnerabilities with format:
VULN: name | SEVERITY: low/medium/high/critical | PORT: number | SERVICE: name
DESC: description
FIX: fix recommendation

End with:
RISK_LEVEL: LOW/MEDIUM/HIGH/CRITICAL
SUMMARY: brief summary
"""}
]

MODELS = [
    "qwen3.5:4b",
    "qwen3.5:9b",
    "deepseek-r1:8b",
    "qwen3-it:4b",
    "llama3.2:3b",
    "phi4-mini-it:4b",
]

FLM_BASE_URL = "http://localhost:8000/v1"
FLM_API_KEY = "dummy"
FLM_PORT = 8000
WAIT_SECONDS = 8


def is_flm_running() -> bool:
    import urllib.request
    try:
        urllib.request.urlopen(FLM_BASE_URL.replace("/v1", "/health"), timeout=2)
        return True
    except Exception:
        pass
    try:
        req = urllib.request.Request(FLM_BASE_URL + "/models", method="GET")
        urllib.request.urlopen(req, timeout=2)
        return True
    except Exception:
        return False


def start_flm(model: str) -> subprocess.Popen:
    print(f"[*] Starting flm serve {model} --port {FLM_PORT} ...")
    proc = subprocess.Popen(
        ["flm", "serve", model, "--port", str(FLM_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Wait until healthy
    for i in range(30):
        time.sleep(1)
        if is_flm_running():
            print(f"[*] FLM ready in {i+1}s")
            return proc
    print("[!] Warning: FLM did not respond in 30s, continuing anyway...")
    return proc


def stop_flm(proc: subprocess.Popen):
    print("[*] Stopping FLM server...")
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
    except Exception:
        proc.kill()
    time.sleep(2)


def ask_flm_direct(messages: list, model: str, max_tokens: int = 1024, temperature: float = 0.7, top_p: float = 0.9) -> str:
    import urllib.request
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "top_p": top_p,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        FLM_BASE_URL + "/chat/completions",
        data=data,
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {FLM_API_KEY}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        result = json.loads(resp.read().decode("utf-8"))
        content = result["choices"][0]["message"]["content"]
        return content.strip() if content else "[!] Model returned empty response."


def benchmark_model(model: str) -> dict:
    proc = None
    results = {
        "model": model,
        "timestamp": datetime.now().isoformat(),
        "error": None,
        "time_seconds": None,
        "response_length": 0,
        "vulns_parsed": 0,
        "exploits_parsed": 0,
        "risk_level": None,
        "preview": "",
    }

    try:
        if not is_flm_running():
            proc = start_flm(model)
        else:
            print("[*] FLM already running, reusing server...")

        print(f"\n{'='*60}")
        print(f"MODEL: {model}")
        print(f"{'='*60}")

        start = time.time()
        response = ask_flm_direct(TEST_PROMPT, model=model, max_tokens=1024, temperature=0.7)
        elapsed = time.time() - start

        vulns = parse_vulnerabilities(response)
        exploits = parse_exploits(response)
        risk = parse_risk_level(response)

        results["time_seconds"] = round(elapsed, 2)
        results["response_length"] = len(response)
        results["vulns_parsed"] = len(vulns)
        results["exploits_parsed"] = len(exploits)
        results["risk_level"] = risk
        results["preview"] = response.replace('\n', ' ')[:300]

        print(f"Time: {elapsed:.2f}s")
        print(f"Response length: {len(response)} chars")
        print(f"Parsed: {len(vulns)} vulns, {len(exploits)} exploits | Risk: {risk}")
        for v in vulns:
            print(f"  - {v['vuln_name'][:50]} [{v['severity']}] port:{v['port']}")
        print(f"Preview: {results['preview']}...")

    except Exception as e:
        results["error"] = str(e)
        print(f"[!] ERROR: {e}")
    finally:
        if proc:
            stop_flm(proc)

    return results


def save_results(all_results: list, path: str = "benchmark_results.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\n[*] Results saved to {path}")


def print_summary(all_results: list):
    print("\n" + "="*60)
    print("BENCHMARK SUMMARY")
    print("="*60)
    print(f"{'Model':<20} {'Time':>8} {'Chars':>8} {'Vulns':>6} {'Risk':>10} {'Status':>10}")
    print("-"*60)
    for r in all_results:
        status = "OK" if not r["error"] else "FAIL"
        print(f"{r['model']:<20} {r['time_seconds'] or '-':>8} {r['response_length']:>8} {r['vulns_parsed']:>6} {str(r['risk_level'] or '-'):>10} {status:>10}")


if __name__ == "__main__":
    models = [sys.argv[1]] if len(sys.argv) > 1 else MODELS
    all_results = []

    for m in models:
        all_results.append(benchmark_model(m))

    print_summary(all_results)
    save_results(all_results)
