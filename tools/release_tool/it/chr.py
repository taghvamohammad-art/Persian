"""Integration test on a real RouterOS CHR running in QEMU (GitHub Actions).

  python chr.py boot    first login on the serial console, create the tool's user
  python chr.py setup   install packages (user-manager, container), test config
  python chr.py backup  run the real backup code against it and check the result
"""

import os
import re
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

SOCK = os.environ.get("CHR_SERIAL", "/tmp/chr.sock")
SSH_PORT = int(os.environ.get("CHR_SSH_PORT", "2222"))
ADMIN_PW = "Adm1n-test-pw"
TOOL_USER, TOOL_PW = "pvtool", "T00l-test-pw"
PKG_DIR = os.environ.get("CHR_PKGS", "/tmp/pkgs")


def serial_login():
    deadline = time.time() + 240
    s = None
    while s is None:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(SOCK)
        except OSError:
            s = None
            if time.time() > deadline:
                raise SystemExit("no serial socket")
            time.sleep(1)
    s.settimeout(2)
    buf = ""
    steps = [
        (r"Login:\s*$", "admin"),
        (r"Password:\s*$", ""),
        (r"\[Y/n\]:?\s*$", "n"),
        (r"repeat new password>\s*$", ADMIN_PW),
        (r"new password>\s*$", ADMIN_PW),
        (r"\] >\s*$", None),
    ]
    s.sendall(b"\r")
    while time.time() < deadline:
        try:
            data = s.recv(4096).decode("utf-8", "replace")
        except socket.timeout:
            s.sendall(b"\r")   # nudge the console
            continue
        buf += data
        sys.stdout.write(data)
        tail = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", buf)[-200:]
        for pat, answer in steps:
            if re.search(pat, tail):
                if answer is None:
                    return s
                s.sendall(answer.encode() + b"\r")
                buf = ""
                break
    raise SystemExit("serial login timed out")


def console(s, cmd, wait=3):
    s.sendall(cmd.encode() + b"\r")
    end = time.time() + wait
    out = ""
    while time.time() < end:
        try:
            out += s.recv(4096).decode("utf-8", "replace")
        except socket.timeout:
            pass
    sys.stdout.write(out)
    return out


def boot():
    s = serial_login()
    console(s, "/user add name=%s group=full password=%s" % (TOOL_USER, TOOL_PW))
    console(s, "/ip service set ssh disabled=no")
    console(s, "/user print")
    print("\nBOOT OK")


def ssh():
    from routeros import SSHRouter
    deadline = time.time() + 300
    while True:
        try:
            return SSHRouter("127.0.0.1", SSH_PORT, TOOL_USER, TOOL_PW).connect()
        except Exception as e:
            if time.time() > deadline:
                raise
            print("waiting for ssh:", e)
            time.sleep(5)


def setup():
    r = ssh()
    print(r.run("/system resource print"))
    for f in sorted(os.listdir(PKG_DIR)):
        if f.startswith(("user-manager-", "container-")) and f.endswith(".npk"):
            print("upload", f)
            with open(os.path.join(PKG_DIR, f), "rb") as fh:
                r.put(f, fh.read())
    try:
        r.run(":execute {/system reboot}", check=False, timeout=10)
    except Exception as e:
        print("reboot:", e)
    r.close()
    time.sleep(20)
    r = ssh()
    print(r.run("/system package print"))
    cmds = [
        "/user-manager set enabled=yes",
        "/user-manager limitation add name=25G transfer-limit=26843545600",
        "/user-manager profile add name=30d-25G validity=4w2d",
        "/user-manager profile-limitation add profile=30d-25G limitation=25G",
        "/user-manager user add name=25g00001 password=abc123",
        "/user-manager user-profile add user=25g00001 profile=30d-25G",
        "/certificate add name=CA common-name=CA key-usage=key-cert-sign,crl-sign",
        "/certificate sign CA",
        "/certificate add name=server common-name=10.9.8.7",
        "/certificate sign server ca=CA",
        "/interface sstp-server server set enabled=yes certificate=server authentication=mschap2",
        "/ppp aaa set use-radius=yes",
        "/system scheduler add name=demo interval=1d on-event=\":log info demo\"",
    ]
    for c in cmds:
        print(">", c)
        print(r.run(c, timeout=120))
    r.put("umstatus/umstatus.py", b"# test file\n")
    r.put("umbot/data/umbot.sqlite3", b"SQLite format 3\x00 fake")
    print(r.run("/file print"))
    r.close()


def backup():
    import backup as bk
    import tempfile
    local = bk.LocalStore(tempfile.mkdtemp())
    rc = {"id": "r1", "name": "chr", "host": "127.0.0.1", "port": SSH_PORT,
          "user": TOOL_USER, "password": TOOL_PW, "hostkey": ""}
    res = bk.backup_router(rc, "backup-pw", local, None, log=print)
    m, parts = bk.open_backup(res["file"], "backup-pw")
    print("\n== parts")
    for name in sorted(parts):
        print("  %-50s %d" % (name, len(parts[name])))
    print("== warnings", m["warnings"])
    print("== certificates", m["certificates"])
    print("== um_files", m.get("um_files"))
    export = parts["export.rsc"].decode()
    print("== export (head)\n" + "\n".join(export.splitlines()[:60]))
    problems = []
    if m["routeros"] != os.environ.get("ROS_VERSION", m["routeros"]):
        problems.append("version %s" % m["routeros"])
    if "25g00001" not in export:
        problems.append("UM user not in export")
    if not any(p.startswith("um/") for p in parts):
        problems.append("no UM database")
    if "system.backup" not in parts:
        problems.append("no binary backup")
    keyed = [c for c in m["certificates"] if c["private_key"]]
    if len(keyed) < 2 or not all(c["files"] for c in m["certificates"]):
        problems.append("certificates: %s" % m["certificates"])
    for f in ("files/umstatus/umstatus.py", "files/umbot/data/umbot.sqlite3"):
        if f not in parts:
            problems.append("missing " + f)
    if any(p.startswith("files/pvbk-") for p in parts):
        problems.append("temp files copied")
    # the p12 really holds the key and opens with the passphrase
    from cryptography.hazmat.primitives.serialization import pkcs12
    for c in keyed:
        for f in c["files"]:
            key, cert, _ = pkcs12.load_key_and_certificates(parts["certs/" + f], m["cert_passphrase"].encode())
            if key is None or cert is None:
                problems.append("p12 without key: " + f)
    with ssh() as r:
        left = [p for p, _ in r.walk("", lambda p: "/" in p) if p.startswith("pvbk-")]
        if left:
            problems.append("temp files left on router: %s" % left)
    if problems:
        raise SystemExit("PROBLEMS:\n  " + "\n  ".join(problems))
    print("\nBACKUP OK")


if __name__ == "__main__":
    {"boot": boot, "setup": setup, "backup": backup}[sys.argv[1]]()
