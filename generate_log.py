"""Makes a fake auth.log file with random login attempts."""
import random
from datetime import datetime, timedelta

USERS = ["admin", "root", "saeed", "guest", "jdoe", "support", "test"]
NORMAL_IPS = [f"192.168.1.{i}" for i in range(10, 40)]
ATTACKER_IPS = ["192.168.1.45", "10.0.0.66", "203.0.113.7"]  # these will brute-force


def make_log(path="auth.log", lines=500):
    start = datetime(2026, 10, 21, 8, 0, 0)
    entries = []

    # Normal traffic: mostly successful, some honest mistakes
    for _ in range(lines):
        t = start + timedelta(seconds=random.randint(0, 36000))
        ip = random.choice(NORMAL_IPS)
        user = random.choice(USERS)
        result = "Login Failed" if random.random() < 0.08 else "Login Success"
        entries.append((t, user, result, ip))

    # Attackers: bursts of failures
    for ip in ATTACKER_IPS:
        burst_start = start + timedelta(seconds=random.randint(0, 30000))
        for i in range(random.randint(8, 25)):
            t = burst_start + timedelta(seconds=i * random.randint(1, 3))
            entries.append((t, random.choice(USERS), "Login Failed", ip))

    entries.sort()
    with open(path, "w") as f:
        for t, user, result, ip in entries:
            f.write(f"{t:%Y-%m-%d %H:%M:%S} - User {user} - {result} - IP {ip}\n")
    print(f"Wrote {len(entries)} lines to {path}")


if __name__ == "__main__":
    make_log()
