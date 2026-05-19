# Contributing to METATRON

Thank you for contributing to METATRON!

## Setup

1. **Requirements**
   - Python 3.8+
   - MariaDB/MySQL database
   - Ollama running locally (for AI features)
   - Parrot OS or Kali Linux (recommended)

2. **Database Setup**
   ```sql
   CREATE DATABASE metatron;
   CREATE USER 'metatron'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL ON metatron.* TO 'metatron'@'localhost';
   ```

3. **Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configuration**
   Edit `db.py` to match your database credentials:
   ```python
   def get_connection():
       return mysql.connector.connect(
           host="localhost",
           user="metatron",
           password="your_password",  # Update this
           database="metatron"
       )
   ```

## Running

```bash
python metatron.py
```

## Code Guidelines

- Add docstrings to all functions
- Use type hints where applicable
- Handle exceptions gracefully
- Test on Parrot OS before submitting

## Pull Requests

1. Fork and create a feature branch
2. Test your changes thoroughly
3. Update documentation as needed
4. Submit with clear description

## Issues

Report bugs via GitHub Issues with:
- Python version
- Database type/version
- Steps to reproduce
- Expected vs actual behavior
