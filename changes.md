I've consolidated all METATRON files into a singular bootstrapped python file: metatron.py.
The app now runs off of a singular file launch, which bootstraps the rest of the folders/files.
Nothing changed just consolidated (using LLM). 

**Test/Verify for errors before deploying (For LLM Mistakes).** 
**Works on my system linux kali debian.**
**Message me on x.com/webxos for anymore info.**
**Hopefully this helps!**

Launch bash command (minus libraries/depends):

cd ~/metatron (The folder the file is in.)

```bash
# 1. Create a virtual environment
python3 -m venv venv

# 2. Activate it
source venv/bin/activate

# 3. Install the required packages (inside the venv)
pip install requests beautifulsoup4 duckduckgo-search reportlab

# 4. Run METATRON
python metatron.py

```
