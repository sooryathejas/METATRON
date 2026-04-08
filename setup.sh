#!/usr/bin/env bash
# METATRON setup script — automates all install steps from README.md
# Safe to re-run; skips steps already completed.

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────────────────
RED='\e[31m'; GREEN='\e[32m'; YELLOW='\e[33m'; CYAN='\e[36m'; BOLD='\e[1m'; RESET='\e[0m'

ok()   { echo -e "${GREEN}  ✔ $*${RESET}"; }
skip() { echo -e "${YELLOW}  ↷ $* (already done)${RESET}"; }
info() { echo -e "${CYAN}  → $*${RESET}"; }
err()  { echo -e "${RED}  ✘ $*${RESET}" >&2; }
step() { echo -e "\n${BOLD}[STEP $1/6] $2${RESET}"; }

# ── Preflight ────────────────────────────────────────────────────────────────
step 1 "Preflight checks"

if [[ $EUID -eq 0 ]]; then
    err "Do not run this script as root. It will sudo where needed."
    exit 1
fi

if [[ ! -f /etc/debian_version ]]; then
    err "This script requires a Debian-based OS (Parrot OS, Ubuntu, Kali, etc.)."
    exit 1
fi

# Resolve script directory so it works from any cwd
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
ok "Running from: $SCRIPT_DIR"

# ── System packages ──────────────────────────────────────────────────────────
step 2 "System packages (nmap, whois, whatweb, curl, dnsutils, nikto)"

MISSING_PKGS=()
for tool in nmap whois whatweb curl dig nikto; do
    command -v "$tool" &>/dev/null || MISSING_PKGS+=("$tool")
done

# dig lives in dnsutils
if [[ " ${MISSING_PKGS[*]} " =~ " dig " ]]; then
    MISSING_PKGS=("${MISSING_PKGS[@]/dig/dnsutils}")
fi

if [[ ${#MISSING_PKGS[@]} -eq 0 ]]; then
    skip "All system tools already installed"
else
    info "Installing: ${MISSING_PKGS[*]}"
    sudo apt-get update -qq
    sudo apt-get install -y "${MISSING_PKGS[@]}"
    ok "System packages installed"
fi

# ── Python venv + dependencies ───────────────────────────────────────────────
step 3 "Python virtual environment + dependencies"

if ! command -v python3 &>/dev/null; then
    err "python3 not found. Install it first: sudo apt install python3 python3-venv python3-pip"
    exit 1
fi

if [[ -d venv ]]; then
    skip "venv/ already exists"
else
    info "Creating virtual environment..."
    python3 -m venv venv
    ok "venv created"
fi

info "Installing Python dependencies..."
# shellcheck source=/dev/null
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
ok "Python dependencies installed"

# ── Ollama + metatron-qwen model ─────────────────────────────────────────────
step 4 "Ollama + metatron-qwen model"

if ! command -v ollama &>/dev/null; then
    info "Ollama not found — installing..."
    curl -fsSL https://ollama.com/install.sh | sh
    ok "Ollama installed"
else
    skip "Ollama already installed ($(ollama --version 2>/dev/null || echo 'unknown version'))"
fi

# Ensure ollama service is running
if ! pgrep -x ollama &>/dev/null; then
    info "Starting ollama service in background..."
    ollama serve &>/dev/null &
    OLLAMA_PID=$!
    sleep 3  # give it a moment to bind
    ok "ollama serve started (pid $OLLAMA_PID)"
else
    skip "ollama service already running"
fi

BASE_MODEL="huihui_ai/qwen3.5-abliterated:9b"
CUSTOM_MODEL="metatron-qwen"

if ollama list 2>/dev/null | grep -q "qwen3.5-abliterated"; then
    skip "Base model already pulled"
else
    info "Pulling base model $BASE_MODEL (~8.4 GB — this may take a while)..."
    ollama pull "$BASE_MODEL"
    ok "Base model pulled"
fi

if ollama list 2>/dev/null | grep -q "$CUSTOM_MODEL"; then
    skip "metatron-qwen model already built"
else
    info "Building metatron-qwen from Modelfile..."
    ollama create "$CUSTOM_MODEL" -f Modelfile
    ok "metatron-qwen model created"
fi

# ── MariaDB setup ────────────────────────────────────────────────────────────
step 5 "MariaDB — database, user, and tables"

if ! command -v mysql &>/dev/null; then
    info "MariaDB client not found — installing mariadb-server..."
    sudo apt-get install -y mariadb-server
fi

sudo systemctl enable --now mariadb
ok "MariaDB service running"

info "Creating database and user..."
sudo mysql -u root <<'SQL'
CREATE DATABASE IF NOT EXISTS metatron;
CREATE USER IF NOT EXISTS 'metatron'@'localhost' IDENTIFIED BY '123';
GRANT ALL PRIVILEGES ON metatron.* TO 'metatron'@'localhost';
FLUSH PRIVILEGES;
SQL
ok "Database 'metatron' and user ready"

info "Creating tables (if not exist)..."
mysql -u metatron -p123 metatron <<'SQL'
CREATE TABLE IF NOT EXISTS history (
    sl_no     INT AUTO_INCREMENT PRIMARY KEY,
    target    VARCHAR(255) NOT NULL,
    scan_date DATETIME NOT NULL,
    status    VARCHAR(50) DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    sl_no       INT,
    vuln_name   VARCHAR(255),
    severity    VARCHAR(50),
    port        VARCHAR(20),
    service     VARCHAR(100),
    description TEXT,
    FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE IF NOT EXISTS fixes (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    sl_no    INT,
    vuln_id  INT,
    fix_text TEXT,
    source   VARCHAR(50),
    FOREIGN KEY (sl_no) REFERENCES history(sl_no),
    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE IF NOT EXISTS exploits_attempted (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    sl_no        INT,
    exploit_name VARCHAR(255),
    tool_used    VARCHAR(100),
    payload      TEXT,
    result       VARCHAR(100),
    notes        TEXT,
    FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE IF NOT EXISTS summary (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    sl_no        INT,
    raw_scan     LONGTEXT,
    ai_analysis  LONGTEXT,
    risk_level   VARCHAR(50),
    generated_at DATETIME,
    FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);
SQL
ok "All 5 tables ready"

# ── Verification ─────────────────────────────────────────────────────────────
step 6 "Verification"

source venv/bin/activate

if python -c "from db import check_db; exit(0 if check_db() else 1)" 2>/dev/null; then
    ok "Database connection verified"
else
    err "Database connection check failed — review the MariaDB setup above."
    exit 1
fi

TABLES=$(mysql -u metatron -p123 metatron -e "SHOW TABLES;" 2>/dev/null | tail -n +2 | wc -l)
if [[ "$TABLES" -eq 5 ]]; then
    ok "All 5 tables confirmed in database"
else
    err "Expected 5 tables, found $TABLES"
    exit 1
fi

if ollama list 2>/dev/null | grep -q "metatron-qwen"; then
    ok "metatron-qwen model confirmed in ollama"
else
    err "metatron-qwen not found in ollama list — check Step 4 output"
    exit 1
fi

echo -e "\n${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${GREEN}  METATRON setup complete!${RESET}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e ""
echo -e "  To run Metatron, open ${BOLD}two terminals${RESET}:"
echo -e ""
echo -e "  ${CYAN}Terminal 1${RESET} — load the AI model:"
echo -e "    ollama run metatron-qwen"
echo -e ""
echo -e "  ${CYAN}Terminal 2${RESET} — launch Metatron:"
echo -e "    cd $(pwd)"
echo -e "    source venv/bin/activate"
echo -e "    python metatron.py"
echo -e ""
