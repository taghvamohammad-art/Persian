"""Integration test on real RouterOS CHRs in QEMU (GitHub Actions).

Three routers:  A = the main server (built here like the real one),
B = a fresh router restored from A's backup, C = a secondary server.
Run:  python chr.py boot A|B|C   then   python chr.py all
"""

import os
import re
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

ADMIN_PW = "Adm1n-test-pw"
TOOL_USER, TOOL_PW = "pvtool", "T00l-test-pw"
VM = {"A": {"ssh": 2222, "https": 18443, "sstp": 1443},
      "B": {"ssh": 2223, "https": 28443, "sstp": 2443},
      "C": {"ssh": 2224, "https": 38443, "sstp": 3443}}
UM_USER, UM_PASS = "25g00001", "abc123"
SLIRP_HOST = "10.0.2.2"      # how a guest reaches the host (and is seen by forwarded ports)
GUEST_IP = "10.0.2.15"


def serial_login(name):
    path = "/tmp/chr-%s.sock" % name
    deadline = time.time() + 240
    s = None
    while s is None:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(path)
        except OSError:
            s = None
            if time.time() > deadline:
                raise SystemExit("no serial socket")
            time.sleep(1)
    s.settimeout(2)
    buf = ""
    steps = [(r"Login:\s*$", "admin"), (r"Password:\s*$", ""), (r"\[Y/n\]:?\s*$", "n"),
             (r"repeat new password>\s*$", ADMIN_PW), (r"new password>\s*$", ADMIN_PW), (r"\] >\s*$", None)]
    s.sendall(b"\r")
    while time.time() < deadline:
        try:
            data = s.recv(4096).decode("utf-8", "replace")
        except socket.timeout:
            s.sendall(b"\r")
            continue
        buf += data
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
    while time.time() < end:
        try:
            s.recv(4096)
        except socket.timeout:
            pass


def boot(name):
    s = serial_login(name)
    console(s, "/user add name=%s group=full password=%s" % (TOOL_USER, TOOL_PW))
    console(s, "/ip service set ssh disabled=no")
    print("BOOT %s OK" % name)


def power_cycle(name):
    m = socket.socket(socket.AF_UNIX)
    m.connect("/tmp/mon-%s.sock" % name)
    m.sendall(b"system_reset\n")
    time.sleep(1)
    m.close()
    print("power cycle", name)


def connector(name):
    from routeros import SSHRouter

    def connect():
        return SSHRouter("127.0.0.1", VM[name]["ssh"], TOOL_USER, TOOL_PW, timeout=20).connect()
    return connect


def wait_ssh(name, timeout=300):
    from provision import wait_back
    return wait_back(connector(name), down_first=False, timeout=timeout)


def step(title):
    print("\n========== %s" % title, flush=True)


# ---------------------------------------------------------------- build router A like the real main server

FAKE_BOT = {
    "umbot/__init__.py": b"",
    "umbot/__main__.py": b"""import sys, time
env = {}
for line in open(sys.argv[1]):
    if "=" in line and not line.startswith("#"):
        k, v = line.strip().split("=", 1)
        env[k] = v
import urllib.request, base64
def rest():
    req = urllib.request.Request(env["MT_URL"] + "/rest/system/identity")
    req.add_header("Authorization", "Basic " + base64.b64encode((env["MT_USER"] + ":" + env["MT_PASSWORD"]).encode()).decode())
    return urllib.request.urlopen(req, timeout=5).read().decode()
while True:
    try:
        line = "bot alive, router says " + rest()
    except Exception as e:
        line = "bot alive, rest error %s" % e
    with open(env["LOG_FILE"], "a") as f:
        f.write(time.strftime("%H:%M:%S ") + line + "\\n")
    time.sleep(10)
""",
}


def wait_cert(r, name):
    for _ in range(90):
        fp = r.run(":put [/certificate get [find name=%s] fingerprint]" % name, check=False).strip()
        key = r.run(":put [/certificate get [find name=%s] private-key]" % name, check=False).strip()
        if re.fullmatch(r"[0-9a-f]{64}", fp) and key == "true":
            return
        time.sleep(2)
    raise SystemExit("certificate %s not signed" % name)


def build_main():
    import provision as pv
    import services as sv
    connect = connector("A")
    r = connect()
    step("A: packages")
    r = pv.install_packages(r, connect, ["user-manager", "container"], log=print)
    step("A: device-mode")
    if not sv.device_mode_container(r):
        pv.request_container_mode(r)
        r.close()
        time.sleep(5)
        power_cycle("A")
        r = wait_ssh("A")
    assert sv.device_mode_container(r), "device-mode container still off"
    step("A: VPN + User Manager config")
    cmds = [
        "/user-manager set enabled=yes",
        "/user-manager limitation add name=25G transfer-limit=26843545600",
        "/user-manager profile add name=30d-25G validity=4w2d",
        "/user-manager profile-limitation add profile=30d-25G limitation=25G",
        "/user-manager user add name=%s password=%s shared-users=1" % (UM_USER, UM_PASS),
        "/user-manager user-profile add user=%s profile=30d-25G" % UM_USER,
        "/user-manager router add name=local address=127.0.0.1 shared-secret=localsecret",
        "/radius add address=127.0.0.1 secret=localsecret service=ppp",
        "/ppp aaa set use-radius=yes accounting=yes interim-update=1m",
        "/ip pool add name=vpn ranges=10.10.10.2-10.10.10.200",
        "/ppp profile add name=vpn local-address=10.10.10.1 remote-address=vpn dns-server=1.1.1.1",
        "/certificate add name=CA common-name=CA key-usage=key-cert-sign,crl-sign",
        "/certificate sign CA",
        "/certificate add name=server common-name=%s" % GUEST_IP,
        "/certificate sign server ca=CA",
        "/interface sstp-server server set enabled=yes certificate=server authentication=mschap2 default-profile=vpn",
        "/ip firewall nat add chain=srcnat src-address=10.10.10.0/24 action=masquerade comment=vpn",
        "/certificate add name=umstatus common-name=%s subject-alt-name=IP:%s key-size=2048 days-valid=3650"
        % (GUEST_IP, GUEST_IP),
        "/certificate sign umstatus",
        "/system scheduler add name=demo interval=1d on-event=\":log info demo\"",
        "/ip service set www port=64",
    ]
    for c in cmds:
        print(">", c)
        r.run(c, timeout=180)
        m = re.match(r"/certificate sign (\S+)", c)
        if m:      # signing finishes in the background
            wait_cert(r, m.group(1))
    step("A: umstatus (as in SETUP_FA)")
    sv.ensure_dir(r, "umstatus")
    r.run('/certificate export-certificate umstatus type=pem export-passphrase="certpass1" '
          'file-name=umstatus/umstatus')
    api_pw = "ApiPass-123456"
    sv.ensure_api_user(r, "umstatus", "172.17.0.2", "read,api,rest-api,web,sensitive", api_pw)
    import json
    r.put("umstatus/config.json", json.dumps({
        "router_url": "http://172.17.0.1:64/rest", "router_user": "umstatus", "router_password": api_pw,
        "listen_port": 8443, "cert_file": "/app/umstatus.crt", "key_file": "/app/umstatus.key",
        "key_passphrase": "certpass1"}).encode())
    r.put("umstatus/umstatus.py", sv.umstatus_source())
    sv.ensure_network(r, sv.UMSTATUS)
    sv.ensure_rest(r)
    r.run("/ip firewall nat add chain=dstnat dst-address=%s protocol=tcp dst-port=8443 action=dst-nat "
          "to-addresses=172.17.0.2 to-ports=8443 comment=umstatus" % GUEST_IP)
    sv.ensure_container(r, sv.UMSTATUS)
    step("A: bot")
    sv.install_bot(r, FAKE_BOT, {"BOT_TOKEN": "123456:" + "x" * 35, "ADMIN_IDS": "111"})
    time.sleep(15)
    st, lines = sv.bot_status(r)
    print("bot:", st, lines[-3:])
    assert st == "running" and lines and "router says" in lines[-1], "bot cannot reach REST"
    r.close()
    import provision
    assert provision.health("https://127.0.0.1:%d/health" % VM["A"]["https"]), "umstatus health on A"
    sstp_login("A")


# ---------------------------------------------------------------- SSTP login from the host (real auth)

def sstp_login(name, user=UM_USER, password=UM_PASS):
    step("SSTP login via %s" % name)
    log = tempfile.mktemp()
    p = subprocess.Popen(
        ["sudo", "sstpc", "--cert-warn", "--log-stderr", "--log-level", "3", "--user", user,
         "--password", password, "127.0.0.1:%d" % VM[name]["sstp"], "require-mschap-v2", "noauth",
         "nodefaultroute", "nodetach", "noipdefault", "logfile", log],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ok = False
    for _ in range(30):
        time.sleep(1)
        out = subprocess.run(["ip", "-4", "addr"], capture_output=True, text=True).stdout
        if re.search(r"ppp\d+.*\n\s+inet 10\.10\.10\.", out):
            ok = True
            break
        if p.poll() is not None:
            break
    subprocess.run(["sudo", "pkill", "-f", "sstpc"], check=False)
    try:
        out, _ = p.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        out = b""
    try:
        print(open(log).read()[-1500:])
    except OSError:
        pass
    print(out.decode(errors="replace")[-1500:])
    if not ok:
        raise SystemExit("SSTP login via %s FAILED" % name)
    print("SSTP login via %s OK" % name)
    time.sleep(3)


# ---------------------------------------------------------------- the whole flow

def run_all():
    import backup as bk
    import provision as pv
    build_main()

    step("backup A")
    local = bk.LocalStore(tempfile.mkdtemp())
    rc = {"id": "r1", "name": "A", "host": GUEST_IP, "port": VM["A"]["ssh"], "user": TOOL_USER,
          "password": TOOL_PW, "hostkey": ""}
    res = bk.backup_router(rc, "backup-pw", local, None, log=print,
                           connect=lambda c: connector("A")())
    manifest, parts = bk.open_backup(res["file"], "backup-pw")
    print("parts:", sorted(p for p in parts if not p.startswith("files/um5")))

    step("restore A -> B")
    kw = dict(new_ip=GUEST_IP, old_ip=GUEST_IP, log=print,
              health_url="https://127.0.0.1:%d/health" % VM["B"]["https"], public_key=b"PUBKEY")
    out = pv.restore_main(connector("B"), manifest, parts, **kw)
    if out["status"] == pv.NEED_POWER_CYCLE:
        time.sleep(5)
        power_cycle("B")
        wait_ssh("B").close()
        out = pv.restore_main(connector("B"), manifest, parts, **kw)
    report(out)
    assert out["status"] == pv.DONE
    assert all(c.startswith("✓") for c in out["checks"] if not c.startswith("⚠")), out["checks"]
    sstp_login("B")          # user + password came over with the User Manager database

    step("bot on B")
    import services as sv
    with connector("B")() as r:
        time.sleep(15)
        st, lines = sv.bot_status(r)
        print("bot:", st, lines[-3:])
        assert st == "running" and "router says" in lines[-1]
    with connector("A")() as r:
        assert sv.stop_bot_autostart(r)
        assert sv.container_status(r, sv.UMBOT) == "stopped"

    step("secondary C (RADIUS to A)")
    out = pv.setup_secondary(connector("C"), connector("A"), manifest, parts, sec_ip=GUEST_IP,
                             main_ip=SLIRP_HOST, name="sec1", log=print, sec_ip_seen_by_main=SLIRP_HOST)
    report(out)
    sstp_login("C")          # authenticated by A's User Manager over RADIUS
    print("\nALL OK")


def report(out):
    print("status:", out["status"])
    for c in out.get("checks", []):
        print("  ", c)
    for line, err in out.get("failed", []):
        print("   failed:", line[:160], "->", err[:160])
    for why, line in out.get("skipped", []):
        print("   skipped:", why, "|", line[:120])


if __name__ == "__main__":
    if sys.argv[1] == "boot":
        boot(sys.argv[2])
    else:
        run_all()
