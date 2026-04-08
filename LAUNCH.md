cd /home/kali/metatron

# 1. Create a virtual environment
python3 -m venv venv

# 2. Activate it
source venv/bin/activate

# 3. Install the required packages (inside the venv)
pip install requests beautifulsoup4 duckduckgo-search reportlab

# 4. Run METATRON
python metatron.py
