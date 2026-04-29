#!/bin/bash
set -e

DB_HOST="${DB_HOST:-mariadb}"
OLLAMA_HOST_URL="${OLLAMA_URL:-http://ollama:11434}"
OLLAMA_TAGS_URL="${OLLAMA_HOST_URL%/api/chat}/api/tags"

echo "[*] Waiting for MariaDB at ${DB_HOST}..."
until mysqladmin ping -h "$DB_HOST" -u "${DB_USER:-metatron}" -p"${DB_PASSWORD:-123}" --silent 2>/dev/null; do
    sleep 2
done
echo "[+] MariaDB is ready."

echo "[*] Waiting for Ollama at ${OLLAMA_TAGS_URL}..."
until curl -sf "$OLLAMA_TAGS_URL" > /dev/null 2>&1; do
    sleep 3
done
echo "[+] Ollama is ready."

exec python3 metatron.py
