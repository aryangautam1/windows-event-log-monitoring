# Windows Security Event Log Monitoring Lab

Practice reviewing Windows authentication and account-management events and produce a concise triage report.

## Quick start

Requirements: Python 3.10+ unless stated otherwise.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux:
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Run:
```bash
python analyze_events.py data/windows_security_events.csv --out reports/triage_report.md
```
The included CSV is synthetic. For real exports, export selected Security log events from Event Viewer to CSV and adapt the column mapping if needed.

## Portfolio evidence
- Keep screenshots of your own successful run in `screenshots/`.
- Record the environment, steps, findings, and limitations in this README.
- Replace or supplement sample data with evidence from your own authorized lab.

## Safety and scope
Use only systems and data you own or are authorized to investigate. Sample data is synthetic.

## Status
This repository includes runnable code/configuration and synthetic demonstration data. Environment-specific integrations may require additional setup described below.
