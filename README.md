# Password Strength Analyzer and Policy Auditor

CPS 3498 Computer Security — Team 4 Final Project

## Modules

- **Module A** — Core analyzer: entropy scoring (zxcvbn), pattern detection, HIBP breach check
- **Module B** — Batch audit: bulk password analysis with HTML/text report generation
- **Module C** — Flask Web UI (in progress)

## Setup

```bash
python -m venv venv
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows
pip install -r requirements.txt
```

## Usage

Single password analysis:
```bash
python main.py
```

Batch audit:
```bash
python batch_audit.py sample_passwords.txt
python batch_audit.py sample_passwords.txt --output report.html
```

Run tests:
```bash
pytest test_batch.py -v
```
