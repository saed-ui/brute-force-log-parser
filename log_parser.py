"""Reads auth.log, counts failed logins per IP, and flags brute-force attacks."""
import csv
import re
import sys
from collections import defaultdict

THRESHOLD = 5  # more than this many failures = alert
LINE_RE = re.compile(
    r"^(?P<time>\S+ \S+) - User (?P<user>\S+) - (?P<result>Login \w+) - IP (?P<ip>[\d.]+)$"
)


def parse_log(path):
    fails = defaultdict(list)  # ip -> list of (time, user)
    with open(path) as f:
        for line in f:
            m = LINE_RE.match(line.strip())
            if not m:
                continue  # skip lines we can't read
            if m["result"] == "Login Failed":
                fails[m["ip"]].append((m["time"], m["user"]))
    return fails


def find_attackers(fails):
    return {ip: hits for ip, hits in fails.items() if len(hits) > THRESHOLD}


def write_csv(attackers, path="security_alerts.csv"):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip_address", "failed_attempts", "first_seen", "last_seen", "users_targeted"])
        for ip, hits in sorted(attackers.items(), key=lambda x: -len(x[1])):
            users = sorted({u for _, u in hits})
            w.writerow([ip, len(hits), hits[0][0], hits[-1][0], ";".join(users)])


def main():
    log_path = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
    fails = parse_log(log_path)
    attackers = find_attackers(fails)

    for ip, hits in attackers.items():
        print(f"⚠️ CRITICAL: Potential Brute-Force Attack detected from IP {ip} "
              f"({len(hits)} failed attempts)")

    write_csv(attackers)
    print(f"\n{len(attackers)} suspicious IP(s) saved to security_alerts.csv")


if __name__ == "__main__":
    main()
