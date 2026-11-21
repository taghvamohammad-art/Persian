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

# shield: the program is blocked by Windows Firewall while the VPN is not connected
import os
import subprocess

notepad = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")


def rules():
    out = subprocess.run(["netsh", "advfirewall", "firewall", "show", "rule", "name=PersianVPN Shield", "verbose"],
                         capture_output=True, text=True, errors="replace").stdout
    return out


r = ask({"cmd": "shield", "programs": [notepad, "relative.exe", notepad.upper()]})
print(r)
assert r["ok"] and len(r["shield"]) == 1, r
out = rules()
print(out)
assert "notepad.exe" in out.lower() and "block" in out.lower(), out
assert "2000::/3" not in out, out                     # not connected: everything blocked
r = ask({"cmd": "shield", "programs": []})
assert r["ok"] and r["shield"] == [], r
assert "notepad.exe" not in rules().lower()
print("service smoke ok")
