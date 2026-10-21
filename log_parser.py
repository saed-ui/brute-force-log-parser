import csv
import re
import sys
from collections import defaultdict

LIMIT = 5

# 2026-10-21 14:22:01 - User admin - Login Failed - IP 192.168.1.45
pattern = re.compile(r"(\S+ \S+) - User (\S+) - (Login \w+) - IP ([\d.]+)")

logfile = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
fails = defaultdict(list)

with open(logfile) as f:
    for line in f:
        m = pattern.match(line)
        if not m:
            continue
        time, user, status, ip = m.groups()
        if status == "Login Failed":
            fails[ip].append((time, user))

flagged = {ip: hits for ip, hits in fails.items() if len(hits) > LIMIT}

for ip, hits in flagged.items():
    print(f"⚠️ CRITICAL: Potential Brute-Force Attack detected from IP {ip} ({len(hits)} fails)")

# worst ones first
with open("security_alerts.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ip", "fails", "first_seen", "last_seen", "users_tried"])
    for ip, hits in sorted(flagged.items(), key=lambda x: len(x[1]), reverse=True):
        tried = ";".join(sorted(set(u for _, u in hits)))
        w.writerow([ip, len(hits), hits[0][0], hits[-1][0], tried])

print(f"\n{len(flagged)} ip(s) flagged -> security_alerts.csv")
