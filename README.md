# METATRON
AI-powered penetration testing assistant using local LLM on linux (Parrot OS)
# 🔱 METATRON
### AI-Powered Penetration Testing Assistant

<p align="center">
  <img src="screenshots/banner.png" alt="Metatron Banner" width="800"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python"/>
  <img src="https://img.shields.io/badge/OS-Parrot%20Linux-green?style=for-the-badge&logo=linux"/>
  <img src="https://img.shields.io/badge/AI-metatron--qwen-red?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/DB-MariaDB-orange?style=for-the-badge&logo=mariadb"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>
</p>

---

## 📌 What is Metatron?

**Metatron** is a CLI-based AI penetration testing assistant that runs entirely on your local machine — no cloud, no API keys, no subscriptions.

You give it a target IP or domain. It runs real recon tools (nmap, whois, whatweb, curl, dig, nikto), feeds all results to a locally running AI model, and the AI analyzes the target, identifies vulnerabilities, suggests exploits, and recommends fixes. Everything gets saved to a MariaDB database with full scan history.

---

## ✨ Features

- 🤖 **Local AI Analysis** — powered by `metatron-qwen` via Ollama, runs 100% offline
- 🔍 **Automated Recon** — nmap, whois, whatweb, curl headers, dig DNS, nikto
- 🌐 **Web Search** — DuckDuckGo search + CVE lookup (no API key needed)
- 🗄️ **MariaDB Backend** — full scan history with 5 linked tables
- ✏️ **Edit / Delete** — modify any saved result directly from the CLI
- 🔁 **Agentic Loop** — AI can request more tool runs mid-analysis
- 🚫 **No API Keys** — everything is free and local
-📤 Export Reports

Metatron allows you to export scan results into clean, shareable report formats by selecting '2.view history'->select slno and export

📄 PDF — professional vulnerability reports
🌐 HTML — browser-viewable reports
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
  <br><i>metatron-qwen analyzing scan results</i>
</p>

<p align="center">
  <img src="screenshots/results.png" alt="Results" width="700"/>
  <br><i>Vulnerabilities saved to database</i>
</p>
<p align="center"> <img src="screenshots/export_menu.png" alt="Export Menu" width="700"/> <br><i>Export scan results as PDF and or HTML</i> </p>
---

## 🧱 Tech Stack

| Component  | Technology                          |
|------------|-------------------------------------|
| Language   | Python 3                            |
| AI Model   | metatron-qwen (fine-tuned Qwen 3.5) |
| Base Model | huihui_ai/qwen3.5-abliterated:9b    |
| LLM Runner | Ollama                              |
| Database   | MariaDB                             |
| OS         | Parrot OS (Debian-based)            |
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

### 4. Install system tools

```bash
sudo apt install nmap whois whatweb curl dnsutils nikto
```

---

## 🤖 AI Model Setup

### Step 1 — Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

### Step 2 — Download the base model

```bash
ollama pull huihui_ai/qwen3.5-abliterated:9b
```

> ⚠️ This model requires at least 8.4 GB of RAM. If your system has less, use the 4b variant:
> ```bash
> ollama pull huihui_ai/qwen3.5-abliterated:4b
> ```
> Then edit `Modelfile` and change the FROM line to the 4b model.

### Step 3 — Build the custom metatron-qwen model

The repo includes a `Modelfile` that fine-tunes the base model with pentest-specific parameters:

```bash
ollama create metatron-qwen -f Modelfile
```

This creates your local `metatron-qwen` model with:
- 16,384 token context window
- Temperature: 0.7
- Top-k: 10
- Top-p: 0.9

### Step 4 — Verify the model exists

```bash
ollama list
```

You should see `metatron-qwen` in the list.

---

## 🗄️ Database Setup

### Step 1 — Make sure MariaDB is running

```bash
sudo systemctl start mariadb
sudo systemctl enable mariadb
```

### Step 2 — Create the database and user

```bash
mysql -u root
```

```sql
CREATE DATABASE metatron;
CREATE USER 'metatron'@'localhost' IDENTIFIED BY '123';
GRANT ALL PRIVILEGES ON metatron.* TO 'metatron'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Step 3 — Create the tables

```bash
mysql -u metatron -p123 metatron
```

```sql
CREATE TABLE history (
  sl_no     INT AUTO_INCREMENT PRIMARY KEY,
  target    VARCHAR(255) NOT NULL,
                      scan_date DATETIME NOT NULL,
                      status    VARCHAR(50) DEFAULT 'active'
);

CREATE TABLE vulnerabilities (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  sl_no       INT,
  vuln_name   TEXT,
  severity    VARCHAR(50),
                              port        VARCHAR(20),
                              service     VARCHAR(100),
                              description TEXT,
                              FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE fixes (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  sl_no    INT,
  vuln_id  INT,
  fix_text TEXT,
  source   VARCHAR(50),
                    FOREIGN KEY (sl_no) REFERENCES history(sl_no),
                    FOREIGN KEY (vuln_id) REFERENCES vulnerabilities(id)
);

CREATE TABLE exploits_attempted (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  sl_no        INT,
  exploit_name TEXT,
  tool_used    TEXT,
  payload      LONGTEXT,
  result       TEXT,
  notes        TEXT,
  FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);

CREATE TABLE summary (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  sl_no        INT,
  raw_scan     LONGTEXT,
  ai_analysis  LONGTEXT,
  risk_level   VARCHAR(50),
                      generated_at DATETIME,
                      FOREIGN KEY (sl_no) REFERENCES history(sl_no)
);
```

---

## 🚀 Usage

Metatron needs **two terminal tabs** to run.

### Terminal 1 — Load the AI model

```bash
ollama run metatron-qwen
```

Wait until you see the `>>>` prompt. This means the model is loaded into memory and ready. You can leave this terminal running in the background.

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

## 📁 Project Structure

```
METATRON/
├── metatron.py       ← main CLI entry point
├── db.py             ← MariaDB connection and all CRUD operations
├── tools.py          ← recon tool runners (nmap, whois, etc.)
├── llm.py            ← Ollama interface and AI tool dispatch loop
├── search.py         ← DuckDuckGo web search and CVE lookup
├── Modelfile         ← custom model config for metatron-qwen
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

## ⚠️ Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**.

- Only use Metatron on systems you own or have **explicit written permission** to test.
- Unauthorized scanning or exploitation of systems is **illegal**.
- The author is not responsible for any misuse of this tool.

---

## 👤 Author

**Soorya Thejas**
- GitHub: [@sooryathejas](https://github.com/sooryathejas)

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Quick Start

```bash
# Clone and setup
git clone https://github.com/sooryathejas/METATRON.git
cd METATRON

# Install dependencies
pip install -r requirements.txt

# Start Ollama (required for AI features)
ollama serve &

# Run METATRON
python metatron.py
```

## Architecture

METATRON is organized into several core modules:

- **metatron.py** - Main CLI entry point, wires all modules together
- **llm.py** - Ollama interface, prompt building, tool dispatch loop
- **db.py** - MariaDB operations (sessions, vulnerabilities, exploits)
- **tools.py** - Recon tool wrappers (nmap, curl, whois, etc.)
- **search.py** - CVE/search database integration

## License

MIT License - see LICENSE file for details.
