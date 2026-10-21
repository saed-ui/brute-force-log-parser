# makes a fake auth.log to test the parser on
import random
from datetime import datetime, timedelta

users = ["admin", "root", "saeed", "guest", "jdoe", "support", "test"]
normal_ips = [f"192.168.1.{i}" for i in range(10, 40)]
bad_ips = ["192.168.1.45", "10.0.0.66", "203.0.113.7"]

start = datetime(2026, 10, 21, 8, 0, 0)
logs = []

# regular traffic, ~8% fail (typos etc)
for _ in range(500):
    t = start + timedelta(seconds=random.randint(0, 36000))
    status = "Login Failed" if random.random() < 0.08 else "Login Success"
    logs.append((t, random.choice(users), status, random.choice(normal_ips)))

# attackers spam a bunch of fails in a short window
for ip in bad_ips:
    t = start + timedelta(seconds=random.randint(0, 30000))
    for _ in range(random.randint(8, 25)):
        t += timedelta(seconds=random.randint(1, 3))
        logs.append((t, random.choice(users), "Login Failed", ip))

logs.sort()

with open("auth.log", "w") as f:
    for t, user, status, ip in logs:
        f.write(f"{t:%Y-%m-%d %H:%M:%S} - User {user} - {status} - IP {ip}\n")

print(f"wrote {len(logs)} lines")
