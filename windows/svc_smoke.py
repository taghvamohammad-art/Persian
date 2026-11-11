"""CI: talk to "pvwin console" the way the app talks to the service."""
import json
import socket
import sys


def ask(req):
    with socket.create_connection(("127.0.0.1", 47811), timeout=10) as c:
        c.sendall(json.dumps(req).encode() + b"\n")
        return json.loads(c.makefile().readline())


r = ask({"cmd": "status"})
print(r)
assert r["ok"] and r["state"] == "off" and r["version"] == int(sys.argv[1]), r
r = ask({"cmd": "connect", "envelope": "{}", "user": "a", "pass": "b"})
print(r)
assert not r["ok"] and "config" in r["error"], r          # unsigned config refused
r = ask({"cmd": "upgrade", "envelope": "{}", "path": "x"})
print(r)
assert not r["ok"], r
print("service smoke ok")
