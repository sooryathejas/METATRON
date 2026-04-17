#!/usr/bin/env python3
"""
METATRON - metatron.py
Main CLI entry point. Wires db.py + tools.py + search.py + llm.py together.
Run with: python metatron.py
"""
from export import export_menu
import os
import sys
from db import (
    get_connection,
    create_session,
    save_vulnerability,
    save_fix,
    save_exploit,
    save_summary,
    get_all_history,
    get_session,
    get_vulnerabilities,
    get_fixes,
    get_exploits,
    edit_vulnerability,
    edit_fix,
    edit_exploit,
    edit_summary_risk,
    delete_vulnerability,
    delete_exploit,
    delete_fix,
    delete_full_session,
    print_history,
    print_session
)
from tools import interactive_tool_run, format_recon_for_llm, run_default_recon
from llm import analyse_target
from providers import get_provider, list_providers
import config


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

def banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(f"""
\033[91m
    ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗
    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
    ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
    \033[90mAI Penetration Testing Assistant  |  {config.ACTIVE_PROVIDER}/{config.ACTIVE_MODEL}  |  Parrot OS\033[0m
    \033[90m─────────────────────────────────────────────────────────────────────\033[0m
""")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def divider(label=""):
    if label:
        print(f"\n\033[33m{'─'*20} {label} {'─'*20}\033[0m")
    else:
        print(f"\033[90m{'─'*60}\033[0m")


def prompt(text):
    return input(f"\033[36m{text}\033[0m").strip()


def success(text):
    print(f"\033[92m[+] {text}\033[0m")


def warn(text):
    print(f"\033[93m[!] {text}\033[0m")


def error(text):
    print(f"\033[91m[✗] {text}\033[0m")


def info(text):
    print(f"\033[94m[*] {text}\033[0m")


def confirm(question: str) -> bool:
    ans = prompt(f"{question} [y/N]: ").lower()
    return ans == "y"


# ─────────────────────────────────────────────
# NEW SCAN
# ─────────────────────────────────────────────

def new_scan():
    divider("NEW SCAN")

    # ── provider selection ─────────────────────
    prov_name = config.ACTIVE_PROVIDER
    prov_model = config.ACTIVE_MODEL
    prov_info = config.PROVIDERS.get(prov_name, {})
    info(f"Using: {prov_info.get('name', prov_name)} / {prov_model}")
    switch = prompt("[Enter = continue, s = switch provider]: ").lower()
    if switch == "s":
        result = provider_select_prompt()
        if result:
            prov_name, prov_model = result

    target = prompt("[?] Enter target IP or domain: ")
    if not target:
        warn("No target entered.")
        return

    # check if target was scanned before
    history = get_all_history()
    past = [row for row in history if row[1] == target]
    if past:
        warn(f"Target '{target}' has been scanned before ({len(past)} time(s)).")
        if not confirm("Continue with a new scan?"):
            return

    # create session in history table first
    sl_no = create_session(target)
    success(f"Session created — SL# {sl_no}")

    # run recon tools
    divider("RECON")
    info("Choose recon tools to run:")
    raw_scan = interactive_tool_run(target)

    if not raw_scan.strip():
        warn("No scan data collected. Aborting.")
        delete_full_session(sl_no)
        return

    # send to AI
    divider("AI ANALYSIS")
    result = analyse_target(target, raw_scan,
                            provider_name=prov_name, model=prov_model)

    # ── save everything to DB ──────────────────
    divider("SAVING TO DATABASE")

    # save vulnerabilities and their fixes
    for vuln in result["vulnerabilities"]:
        vuln_id = save_vulnerability(
            sl_no,
            vuln["vuln_name"],
            vuln["severity"],
            vuln["port"],
            vuln["service"],
            vuln["description"]
        )
        if vuln.get("fix"):
            save_fix(sl_no, vuln_id, vuln["fix"], source="ai")
        success(f"Saved vuln: {vuln['vuln_name']} [{vuln['severity']}]")

    # save exploits
    for exp in result["exploits"]:
        save_exploit(
            sl_no,
            exp["exploit_name"],
            exp["tool_used"],
            exp["payload"],
            exp["result"],
            exp["notes"]
        )
        success(f"Saved exploit: {exp['exploit_name']}")

    # save summary
    save_summary(
        sl_no,
        result["raw_scan"],
        result["full_response"],
        result["risk_level"]
    )

    success(f"All data saved. SL# {sl_no} | Risk: {result['risk_level']}")
    divider()

    # show results and offer edit/delete
    data = get_session(sl_no)
    print_session(data)

    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────
# VIEW HISTORY
# ─────────────────────────────────────────────

def view_history():
    divider("SCAN HISTORY")
    rows = get_all_history()

    if not rows:
        warn("No scans in database yet.")
        return

    print_history(rows)

    sl_no_str = prompt("Enter SL# to view details (or press Enter to go back): ")
    if not sl_no_str:
        return

    try:
        sl_no = int(sl_no_str)
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


# ─────────────────────────────────────────────
# EDIT / DELETE MENU
# ─────────────────────────────────────────────

def edit_delete_menu(sl_no: int):
    while True:
        divider(f"EDIT / DELETE — SL# {sl_no}")
        print("  [1] Edit a vulnerability")
        print("  [2] Edit a fix")
        print("  [3] Edit an exploit")
        print("  [4] Edit risk level")
        print("  [5] Delete a vulnerability")
        print("  [6] Delete a fix")
        print("  [7] Delete an exploit")
        print("  [8] Delete FULL session (all tables)")
        print("  [9] Back")
        divider()

        choice = prompt("Choice: ")

        # ── EDIT VULNERABILITY ─────────────────
        if choice == "1":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities recorded for this session.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]} | port {v[4]} | {v[5]}")

            vid = prompt("Enter vulnerability id to edit: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: vuln_name / severity / port / service / description")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_vulnerability(int(vid), field, value)

        # ── EDIT FIX ──────────────────────────
        elif choice == "2":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes recorded for this session.")
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

        # ── EDIT EXPLOIT ──────────────────────
        elif choice == "3":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits recorded for this session.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | tool: {e[3]} | result: {e[5]}")

            eid = prompt("Enter exploit id to edit: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: exploit_name / tool_used / payload / result / notes")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_exploit(int(eid), field, value)

        # ── EDIT RISK LEVEL ───────────────────
        elif choice == "4":
            print("  Options: CRITICAL / HIGH / MEDIUM / LOW")
            risk = prompt("New risk level: ").upper()
            if risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                error("Invalid risk level.")
                continue
            edit_summary_risk(sl_no, risk)

        # ── DELETE VULNERABILITY ──────────────
        elif choice == "5":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities to delete.")
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

        # ── DELETE FIX ────────────────────────
        elif choice == "6":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes to delete.")
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

        # ── DELETE EXPLOIT ────────────────────
        elif choice == "7":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits to delete.")
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

        # ── DELETE FULL SESSION ───────────────
        elif choice == "8":
            if confirm(f"\n\033[91mPermanently delete ENTIRE session SL# {sl_no} from all tables?\033[0m"):
                delete_full_session(sl_no)
                success(f"Session SL# {sl_no} wiped.")
                return   # go back to main menu

        # ── BACK ──────────────────────────────
        elif choice == "9":
            break

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# PROVIDER SELECT PROMPT (inline, for per-scan switching)
# ─────────────────────────────────────────────

def provider_select_prompt():
    """Quick inline provider/model picker. Returns (provider, model) or None."""
    providers = list_providers()
    print()
    for i, p in enumerate(providers, 1):
        key_status = "\033[92m✓\033[0m" if p["has_key"] else "\033[91m✗\033[0m"
        active_tag = " \033[93m← active\033[0m" if p["active"] else ""
        print(f"  [{i}] {p['name']}  {key_status}{active_tag}")

    choice = prompt("Select provider [1-4]: ")
    if not choice.isdigit() or int(choice) < 1 or int(choice) > len(providers):
        warn("Invalid choice. Keeping current provider.")
        return None

    selected = providers[int(choice) - 1]
    if not selected["has_key"]:
        error(f"No API key configured for {selected['name']}.")
        error(f"Add {config.PROVIDERS[selected['key']]['key_var']} to your .env file.")
        return None

    # model selection
    models = selected["models"]
    if len(models) == 1:
        return (selected["key"], models[0])

    print(f"\n  Available models for {selected['name']}:")
    for j, m in enumerate(models, 1):
        print(f"    [{j}] {m}")

    mchoice = prompt(f"Select model [1-{len(models)}]: ")
    if not mchoice.isdigit() or int(mchoice) < 1 or int(mchoice) > len(models):
        warn("Invalid choice. Using first model.")
        return (selected["key"], models[0])

    return (selected["key"], models[int(mchoice) - 1])


# ─────────────────────────────────────────────
# SETTINGS MENU
# ─────────────────────────────────────────────

def settings_menu():
    divider("SETTINGS")

    # show current config
    info(f"Active provider : {config.ACTIVE_PROVIDER}")
    info(f"Active model    : {config.ACTIVE_MODEL}")
    divider()

    # show all providers
    print("\n  \033[1mConfigured Providers:\033[0m\n")
    providers = list_providers()
    for p in providers:
        key_status = "\033[92m✓ key set\033[0m" if p["has_key"] else "\033[91m✗ no key\033[0m"
        active_tag = "  \033[93m← active\033[0m" if p["active"] else ""
        print(f"    {p['name']:<25} {key_status}{active_tag}")
        for m in p["models"]:
            print(f"      └─ {m}")
    print()

    print("  [1] Switch active provider & model")
    print("  [2] Test current provider connection")
    print("  [3] Back")
    divider()

    choice = prompt("Choice: ")

    if choice == "1":
        result = provider_select_prompt()
        if result:
            prov, model = result
            # update runtime config
            config.ACTIVE_PROVIDER = prov
            config.ACTIVE_MODEL    = model
            success(f"Switched to: {config.PROVIDERS[prov]['name']} / {model}")
            info("Note: to make this permanent, update ACTIVE_PROVIDER and ACTIVE_MODEL in .env")

    elif choice == "2":
        info(f"Testing {config.ACTIVE_PROVIDER} / {config.ACTIVE_MODEL}...")
        provider = get_provider()
        if provider.ping():
            success(f"{provider.label()} is reachable!")
        else:
            error(f"{provider.label()} is NOT reachable. Check config / API key / network.")

    elif choice == "3":
        return
    else:
        warn("Invalid choice.")


# ─────────────────────────────────────────────
# DB CONNECTION CHECK
# ─────────────────────────────────────────────

def check_db():
    try:
        conn = get_connection()
        conn.close()
        success("MariaDB connection OK.")
    except Exception as e:
        error(f"Cannot connect to MariaDB: {e}")
        error("Make sure MariaDB is running. Exiting.")
        sys.exit(1)


# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────

def main_menu():
    while True:
        banner()
        print("  \033[92m[1]\033[0m  New Scan")
        print("  \033[92m[2]\033[0m  View History")
        print("  \033[92m[3]\033[0m  Settings")
        print("  \033[92m[4]\033[0m  Exit")
        divider()

        choice = prompt("metatron> ")

        if choice == "1":
            new_scan()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "2":
            view_history()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "3":
            settings_menu()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "4":
            print("\n\033[91m[*] Shutting down Metatron. Stay legal.\033[0m\n")
            sys.exit(0)

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    check_db()
    main_menu()
