# 🔱 METATRON
### AI-Powered Penetration Testing Assistant

<p align="center">
  <img src="screenshots/banner.png" alt="Metatron Banner" width="800"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/OS-Parrot%20Linux%20%7C%20Arch-green?style=for-the-badge&logo=linux"/>
  <img src="https://img.shields.io/badge/AI-FLM%20%7C%20Ollama-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/DB-MariaDB-orange?style=for-the-badge&logo=mariadb"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
</p>

---

## 📌 What is Metatron?

**Metatron** is a CLI-based AI penetration testing assistant that runs entirely on your local machine — no cloud, no API keys, no subscriptions.

You give it a target IP or domain. It runs real recon tools (`nmap`, `whois`, `whatweb`, `curl`, `dig`, `nikto`), feeds all results to a locally running AI model, and the AI analyzes the target, identifies vulnerabilities, suggests exploits, and recommends fixes. Everything gets saved to a MariaDB database with full scan history.

---

## ✨ Features

- 🤖 **Local AI Analysis** — dual backend: FLM (OpenAI-compatible, e.g. AMD NPU) or Ollama, runs 100% offline
- 🔍 **Automated Recon** — `nmap`, `whois`, `whatweb`, `curl` headers, `dig` DNS, `nikto`
- 🐳 **Docker Fallback** — missing tools auto-run inside a Parrot OS container
- 🌐 **Web Search** — DuckDuckGo search + CVE lookup (no API key needed)
- 🗄️ **MariaDB Backend** — full scan history with 5 linked tables
- ✏️ **Edit / Delete** — modify any saved result directly from the CLI
- 🔁 **Agentic Loop** — AI can request more tool runs mid-analysis
- 🚫 **No API Keys** — everything is free and local
- 📤 **Export Reports** — PDF and HTML

Metatron allows you to export scan results into clean, shareable report formats by selecting `2. View History` → select `sl_no` → export.

📄 **PDF** — professional vulnerability reports  
🌐 **HTML** — browser-viewable reports

---

## 🖥️ Screenshots

<p align="center">
  <img src="screenshots/main_menu.png" alt="Main Menu" width="700"/>
  <br><i>Main Menu</i>
</p>

<p align="center">
  <img src="screenshots/scan_running.png" alt="Scan Running" width="700"/>
  <br><i>Recon tools running on target</i>
</p>

<p align="center">
  <img src="screenshots/ai_analysis.png" alt="AI Analysis" width="700"/>
  <br><i>AI analyzing scan results</i>
</p>

<p align="center">
  <img src="screenshots/results.png" alt="Results" width="700"/>
  <br><i>Vulnerabilities saved to database</i>
</p>

<p align="center">
  <img src="screenshots/export_menu.png" alt="Export Menu" width="700"/>
  <br><i>Export scan results as PDF and/or HTML</i>
</p>

---

## 🧱 Tech Stack

| Component  | Technology                          |
|------------|-------------------------------------|
| Language   | Python 3                            |
| AI Model   | `qwen3.5:4b` / `qwen3.5:9b` / `deepseek-r1:8b` (FLM) or `metatron-qwen` (Ollama) |
| LLM Runner | FLM (OpenAI-compatible) or Ollama   |
| Database   | MariaDB (Docker or native)          |
| OS         | Parrot OS, Arch Linux, or any Docker-capable distro |
| Search     | DuckDuckGo (free, no key)           |

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/sooryathejas/METATRON.git
cd METATRON
```

### 2. Create and activate virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install system tools (or use Docker fallback)

**Debian / Parrot OS:**
```bash
sudo apt install nmap whois whatweb curl dnsutils nikto
```

**Arch Linux:**
```bash
sudo pacman -S nmap bind curl whois
# whatweb and nikto via AUR: yay -S whatweb nikto
```

> If some tools are missing, Metatron will automatically fall back to the `metatron-tools` Docker container (Parrot OS with all tools pre-installed). See `docker-compose.tools.yml`.

### 5. Configure environment

```bash
cp .env.example .env
# Edit .env to set your backend, model, and database credentials
```

---

## 🤖 AI Model Setup

### Option A — FLM (recommended for AMD Ryzen AI / NPU)

```bash
# Install FLM: https://github.com/FastFlowLM/FastFlowLM
# Serve a model (example: qwen3.5 4B on port 8000)
flm serve qwen3.5:4b --port 8000 --ctx-len 16384 --pmode performance
```

Make sure `.env` points to FLM:
```bash
METATRON_LLM_BACKEND=flm
FLM_BASE_URL=http://localhost:8000/v1
FLM_MODEL=qwen3.5:4b
```

Recommended models for FLM (tested on AMD Ryzen AI 7 350, 22 GB RAM):

| Model | Time* | Vulns | Risk | Verdict |
|-------|-------|-------|------|---------|
| `qwen3.5:4b` | ~24s | 3 | **HIGH** | ⭐ Best balance — recommended default |
| `qwen3.5:9b` | ~67s | 3 | **HIGH** | Deeper output, 3x slower |
| `deepseek-r1:8b` | ~69s | 3 | MEDIUM | Good reasoning, conservative risk |
| `qwen3-it:4b` | ~18s | 2 | MEDIUM | Fast, less aggressive |
| `llama3.2:3b` | ~10s | 3 | LOW | Very fast, subestimates severity |
| `phi4-mini-it:4b` | ~13s | 2 | LOW | Fast, conservative |

\* Time = response time for a standard pentest prompt via `benchmark_models.py`.

Run the benchmark yourself:
```bash
python benchmark_models.py
```

### Option B — Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull huihui_ai/qwen3.5-abliterated:9b
ollama create metatron-qwen -f Modelfile
```

Make sure `.env` points to Ollama:
```bash
METATRON_LLM_BACKEND=ollama
OLLAMA_URL=http://localhost:11434/api/chat
OLLAMA_MODEL=metatron-qwen
```

---

## 🗄️ Database Setup

### Quick start — Docker MariaDB (recommended)

```bash
docker compose up -d
```

The database and tables are created automatically from `config/initdb/01-schema.sql`.

### Manual setup — Native MariaDB

```bash
sudo systemctl start mariadb
mysql -u root
```

```sql
CREATE DATABASE metatron;
CREATE USER 'metatron'@'localhost' IDENTIFIED BY 'metatron123';
GRANT ALL PRIVILEGES ON metatron.* TO 'metatron'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Then create the 5 tables (see `config/initdb/01-schema.sql`).

---

## 🚀 Usage

### Terminal 1 — Start the LLM server

**FLM:**
```bash
flm serve qwen3.5:4b --port 8000 --ctx-len 16384 --pmode performance
```

**Ollama:**
```bash
ollama run metatron-qwen
```

Leave this terminal running in the background.

### Terminal 2 — Launch Metatron

```bash
cd ~/METATRON
source venv/bin/activate
python metatron.py
```

---

### Walkthrough

**1. Main menu appears:**
```
  [1]  New Scan
  [2]  View History
  [3]  Exit
```

**2. Select [1] New Scan → enter your target:**
```
[?] Enter target IP or domain: 192.168.1.1
```
or
```
[?] Enter target IP or domain: example.com
```

**3. Select recon tools to run:**
```
  [1] nmap
  [2] whois
  [3] whatweb
  [4] curl headers
  [5] dig DNS
  [6] nikto
  [a] Run all (except nikto)
  [n] Run all + nikto (slow)
```

**4. Metatron runs the tools, feeds results to the AI, and prints the analysis.**

**5. Everything is saved to MariaDB automatically.**

**6. After the scan you can edit or delete any result.**

---

## 🛠️ Customizing the AI Behavior

The system prompt that guides the AI is stored in `config/system_prompt.txt`. You can edit this file to:

- Adjust severity calibration for your environment
- Add or remove anti-hallucination rules
- Change the output format constraints
- Include organization-specific compliance language

No code changes are required — the prompt is loaded at runtime.

---

## 📁 Project Structure

```
METATRON/
├── metatron.py       ← main CLI entry point
├── db.py             ← MariaDB connection and all CRUD operations
├── tools.py          ← recon tool runners (nmap, whois, etc.) with Docker fallback
├── llm.py            ← LLM interface and AI tool dispatch loop
├── llm_backends.py   ← unified FLM + Ollama backend
├── search.py         ← DuckDuckGo web search and CVE lookup
├── export.py         ← PDF / HTML report generator
├── config/
│   ├── system_prompt.txt      ← customizable AI system prompt
│   └── initdb/01-schema.sql   ← MariaDB schema
├── .env.example      ← environment configuration template
├── docker-compose.yml         ← MariaDB container
├── docker-compose.tools.yml   ← Parrot OS pentest tools container
├── Modelfile         ← custom model config for Ollama
├── requirements.txt  ← Python dependencies
├── .gitignore        ← excludes venv, pycache, db files
├── LICENSE           ← MIT License
├── README.md         ← this file
└── screenshots/      ← terminal screenshots for documentation
```

---

## 🗃️ Database Schema

All 5 tables are linked by `sl_no` (session number) from the `history` table:

```
history              ← one row per scan session (sl_no is the spine)
    │
    ├── vulnerabilities   ← vulns found, linked by sl_no
    │       │
    │       └── fixes     ← fixes per vuln, linked by vuln_id + sl_no
    │
    ├── exploits_attempted ← exploits tried, linked by sl_no
    │
    └── summary           ← full AI analysis dump, linked by sl_no
```

---

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| `Cannot connect to FLM server` | Verify `flm serve` is running and `FLM_BASE_URL` in `.env` matches the port |
| `Tool not found: nmap` | Either install natively or run `docker compose -f docker-compose.tools.yml up -d` for auto-fallback |
| `MariaDB connection failed` | Run `docker compose up -d` to start the database container |
| Parser misses some vulns | The parser is now typo-tolerant; if issues persist, check `config/system_prompt.txt` formatting |
| PDF export fails | Ensure `reportlab` is installed (`pip install reportlab`) |

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**.

- Only use Metatron on systems you own or have **explicit written permission** to test.
- Unauthorized scanning or exploitation of systems is **illegal**.
- The author is not responsible for any misuse of this tool.

---

## 👤 Author

**Soorya Thejas**
- GitHub: [@sooryathejas](https://github.com/sooryathejas)

## 🤝 Contributors

- **Lucy E. Arias** — FLM/Ollama dual backend, Docker infrastructure, external config, benchmark suite
  - GitHub: [@Matcraft94](https://github.com/Matcraft94)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
