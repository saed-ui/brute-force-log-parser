# brute-force-log-parser

basically a mini SIEM. reads an auth log, counts failed logins per IP, and yells at you if any IP fails more than 5 times.

## run it

```
python3 generate_log.py   # makes a fake auth.log
python3 log_parser.py     # or pass your own log file as an arg
```

output looks like:

```
⚠️ CRITICAL: Potential Brute-Force Attack detected from IP 192.168.1.45 (18 fails)
```

flagged IPs get dumped into `security_alerts.csv` (ip, fail count, first/last seen, which usernames they tried).

no pip installs, just standard python.

## todo maybe
- only count fails inside a time window (like 5 in 1 min) instead of all day
- watch the file live instead of reading it once
