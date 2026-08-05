# Password Strength Analyzer and Policy Auditor

A privacy-conscious password auditing toolkit developed for the CPS 3498 Computer Security final project. It combines explainable password-strength scoring, custom pattern detection, Have I Been Pwned (HIBP) breach checks, batch reports, and a responsive Flask web interface.

## Highlights

- Scores passwords with `zxcvbn` and explains weaknesses
- Detects keyboard walks, date patterns, and common leetspeak substitutions
- Queries HIBP with its k-anonymity range API; the full password hash is never transmitted
- Audits password lists and generates terminal or HTML reports
- Provides single-password and batch-audit workflows in a responsive web UI
- Masks passwords before returning batch results to the browser
- Includes automated tests for the analysis, reporting, and web layers

## Architecture

```text
Browser / CLI
     |
Flask UI or batch_audit.py
     |
analyzer.py
  |-- zxcvbn strength estimation
  |-- patterns.py custom detectors
  `-- hibp.py breach lookup (k-anonymity)
```

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate       # macOS/Linux
# .venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### Web application

```bash
python app.py
```

Then open <http://127.0.0.1:5000>.

### Command line

Analyze a single password interactively:

```bash
python main.py
```

Audit a password list and optionally create an HTML report:

```bash
python batch_audit.py sample_passwords.txt
python batch_audit.py sample_passwords.txt --output report.html
```

### Tests

```bash
pytest -v
```

## Privacy and Security

- Passwords are processed in memory and are not written to disk by the web app.
- HIBP lookups send only the first five characters of a SHA-1 hash prefix.
- Raw passwords are removed from batch API responses and replaced with masks.
- Uploaded lists are limited to 1 MB.

This is an educational auditing tool, not a production authentication service. Do not upload real organizational password dumps or other sensitive datasets.

## Project Structure

| Path | Purpose |
| --- | --- |
| `analyzer.py` | Combines strength, pattern, and breach analysis |
| `patterns.py` | Custom password-pattern detectors |
| `hibp.py` | HIBP k-anonymity client |
| `batch_audit.py` | Batch auditing and report generation |
| `app.py` | Flask routes and API |
| `templates/index.html` | Responsive web interface |
| `test_batch.py`, `test_app.py` | Automated tests |

## Team Project

Developed as a CPS 3498 Computer Security team project. Hanyi Yang implemented Module C, the Flask web interface and its single-password and batch-audit experiences. The remaining analysis and reporting modules were developed collaboratively by Team 4.

## Future Work

- Add configurable password policies (length, character classes, deny lists)
- Export privacy-preserving aggregate reports from the web UI
- Add rate limiting and production deployment configuration
