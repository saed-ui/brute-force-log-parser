# Brute-Force Log Parser & Alerter

A small Python tool that works like a basic SIEM. It reads a login log, counts failed logins per IP address, and flags any IP with more than 5 failures as a possible brute-force attack.

## Files
- `generate_log.py` – makes a fake `auth.log` with ~500 normal logins plus a few attacker IPs
- `log_parser.py` – reads the log, prints alerts, and saves them to `security_alerts.csv`

## How to run
```bash
python3 generate_log.py
python3 log_parser.py            # or: python3 log_parser.py path/to/other.log
```

## Example output
```
⚠️ CRITICAL: Potential Brute-Force Attack detected from IP 192.168.1.45 (18 failed attempts)
```

`security_alerts.csv` columns: `ip_address, failed_attempts, first_seen, last_seen, users_targeted`

## What I learned
- Parsing log lines with regular expressions
- Counting events with `defaultdict`
- Writing reports with the `csv` module
- How brute-force attacks show up in auth logs

No extra packages needed (Python 3 standard library only).
