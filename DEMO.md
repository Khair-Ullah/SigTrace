# Multi-Stage Attack Demo

Simulate a realistic multi-stage attack (`Port Scan → SSH Brute Force → Successful Login`) and feed it straight into the SIEM engine. The dashboard will show generated alerts and a **Critical Incident** right after ingesting.

## Prerequisites

- Python 3.10+ installed
- Dependencies installed: `pip install -r requirements.txt` (or `pip install -e .`)
- Database and schema ready (the demo runs migrations automatically)

## Run the demo

From the repository root (`F:\SIEM`):

```powershell
# Generate and persist into the active database (data/siem.db in a checkout)
python -m siem demo
```

Or to preview without writing to DB:

```powershell
python -m siem demo --dry-run
```

The legacy script entry point still works and is a thin wrapper around the
packaged command:

```powershell
python scripts/run_demo.py --dry-run
```

## View results

1. Start the web dashboard (if not already running):
   ```powershell
   python -m siem run --web
   ```
2. Open [http://localhost:5000](http://localhost:5000)
3. Go to **Alerts** / **Incidents** - you should see a **Critical** Incident generated from the simulated attack
4. Go to **Events** to inspect the individual firewall/SSH events (including Protocol/Direction/Interfaces if shown)

## Expected outcome

- **Events**: ~27 events (20x firewall_deny + 6x failed_login + 1x successful_login)
- **Alerts**: Multiple alerts (e.g. `Network Port Scan Detection`, `Brute Force Attack`, `Successful Login from Suspicious IP`, etc.)
- **Incident**: At least one **critical** incident linking those alerts (multi-stage attack correlation)

## Reset

To clear demo data and recreate a fresh schema:

```powershell
python -m siem db reset
```

The legacy `python scripts/reset_fresh_db.py` entry point is a thin wrapper
around the same packaged command.
