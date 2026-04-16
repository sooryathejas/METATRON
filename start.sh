#!/usr/bin/env bash
set -e

echo "🔱 METATRON — Environment Launcher"
echo "==================================="

# ── Check Docker ─────────────────────────────
if ! command -v docker &> /dev/null; then
    echo "[!] Docker not found. Please install Docker first."
    exit 1
fi

# ── Start MariaDB ────────────────────────────
echo "[*] Starting MariaDB container..."
docker compose up -d

# ── Start pentest tools container (if not running) ──
if ! docker ps --format "{{.Names}}" | grep -q "^metatron-tools$"; then
    echo "[*] Starting pentest tools container..."
    docker compose -f docker-compose.tools.yml up -d
else
    echo "[+] Pentest tools container already running."
fi

# ── Wait for MariaDB ─────────────────────────
echo "[*] Waiting for MariaDB to be ready..."
for i in {1..30}; do
    if docker exec metatron-mariadb healthcheck.sh --connect --innodb_initialized &> /dev/null; then
        echo "[+] MariaDB is ready."
        break
    fi
    sleep 1
done

# ── Check Python venv ────────────────────────
if [ ! -d "venv" ]; then
    echo "[*] Creating Python virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate

# ── Check dependencies ───────────────────────
echo "[*] Checking Python dependencies..."
pip install -q -r requirements.txt

# ── Check FLM ────────────────────────────────
FLM_PORT=$(grep "^FLM_BASE_URL=" .env 2>/dev/null | grep -oP '(?<=:)[0-9]+' || echo "8000")
if ! ss -tlnp 2>/dev/null | grep -q ":$FLM_PORT "; then
    echo "[!] FLM server not detected on port $FLM_PORT."
    echo "    Start it manually with:"
    echo "    flm serve qwen3.5:4b --port $FLM_PORT --ctx-len 16384 --pmode performance"
    echo ""
    read -p "Press Enter to continue anyway, or Ctrl+C to abort..."
else
    echo "[+] FLM detected on port $FLM_PORT."
fi

# ── Launch METATRON ──────────────────────────
echo ""
echo "[+] Launching METATRON..."
python metatron.py
