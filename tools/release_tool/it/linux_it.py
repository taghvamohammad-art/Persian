"""Integration test of the Linux VPN server (GitHub Actions runner = the server).

Two RouterOS CHRs act as User Manager 1 and 2. The runner itself is set up
with linux.setup_linux over SSH (root@127.0.0.1), then real clients connect
with each protocol using credentials derived from username + password, the
traffic must show up in User Manager, and when UM1 dies the agent must
carry on with UM2.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "server", "linux"))
import chr as base          # noqa: E402
import pvcreds              # noqa: E402

base.VM.update({"A": {"ssh": 2222}, "B": {"ssh": 2223}})
ROOT_PW = os.environ.get("ROOT_PW", "R00t-test-pw")
USER, PASS = "25g00001", "abc123"
USER2, PASS2 = "25g00002", "xyz789"          # only on UM2 (created after UM1 dies)
REACH = {"A": {"host": "127.0.0.1", "rest_port": 19443, "auth_port": 1812, "acct_port": 1813},
         "B": {"host": "127.0.0.1", "rest_port": 29443, "auth_port": 2812, "acct_port": 2813}}


def step(t):
    print("\n========== " + t, flush=True)


def prepare_um(name):
    import provision as pv
    connect = base.connector(name)
    r = connect()
    r = pv.install_packages(r, connect, ["user-manager"], log=print)
    for c in ["/user-manager set enabled=yes",
              "/user-manager limitation add name=25G transfer-limit=26843545600",
              "/user-manager profile add name=30d-25G validity=4w2d",
              "/user-manager profile-limitation add profile=30d-25G limitation=25G",
              "/user-manager user add name=%s password=%s" % (USER, PASS),
              "/user-manager user-profile add user=%s profile=30d-25G" % USER,
              "/ip service set www-ssl port=9443"]:
        print(">", c)
        r.run(c)
    r.close()


def sh(cmd, check=True, timeout=120):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise SystemExit("FAILED: %s\n%s%s" % (cmd, p.stdout[-2000:], p.stderr[-2000:]))
    return p.stdout


def client_config(entry, user, password):
    proto = {p["type"]: p for p in entry["protocols"]}
    v, x, h, s = proto["vless-reality-vision"], proto["vless-xhttp-reality"], proto["hysteria2"], proto["shadowsocks-2022"]
    uid = pvcreds.vless_uuid(user, password)
    reality = lambda p: {"serverName": p["sni"], "publicKey": p["public_key"], "shortId": p["short_id"],
                         "fingerprint": "chrome"}
    outs = [
        {"tag": "vision", "protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": v["port"],
            "users": [{"id": uid, "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
         "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": reality(v)}},
        {"tag": "xhttp", "protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": x["port"],
            "users": [{"id": uid, "encryption": "none"}]}]},
         "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": x["path"]}, "security": "reality",
                            "realitySettings": reality(x)}},
        {"tag": "hy2", "protocol": "hysteria", "settings": {"version": 2, "address": "127.0.0.1", "port": h["port"]},
         "streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2,
                                                                         "auth": pvcreds.hy2_auth(user, password)},
                            "security": "tls", "tlsSettings": {"serverName": "pv", "alpn": ["h3"],
                                                               "pinnedPeerCertSha256": h["pin_sha256"]}}},
        {"tag": "ss", "protocol": "shadowsocks", "settings": {"servers": [{"address": "127.0.0.1", "port": s["port"],
            "method": s["method"], "password": s["server_key"] + ":" + pvcreds.ss_key(user, password)}]}},
    ]
    ins = [{"tag": "in-" + o["tag"], "port": 1081 + i, "listen": "127.0.0.1", "protocol": "socks",
            "settings": {"udp": True}} for i, o in enumerate(outs)]
    rules = [{"inboundTag": ["in-" + o["tag"]], "outboundTag": o["tag"]} for o in outs]
    return {"log": {"loglevel": "warning"}, "inbounds": ins, "outbounds": outs, "routing": {"rules": rules}}


def run_clients(entry, user, password, expect_ok=True, only=None):
    cfg = client_config(entry, user, password)
    path = tempfile.mktemp(suffix=".json")
    with open(path, "w") as f:
        json.dump(cfg, f)
    p = subprocess.Popen(["/usr/local/bin/xray", "run", "-config", path], stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    time.sleep(2)
    results = {}
    try:
        for i, o in enumerate(cfg["outbounds"]):
            if only and o["tag"] not in only:
                continue
            code = sh("curl -s -o /dev/null -w '%%{http_code}' --max-time 15 -x socks5h://127.0.0.1:%d "
                      "https://www.google.com/generate_204" % (1081 + i), check=False).strip()
            results[o["tag"]] = code
    finally:
        p.terminate()
        out = p.communicate(timeout=10)[0].decode(errors="replace")
    print("client results (%s):" % user, results)
    if any(c != "204" for c in results.values()):
        print(out[-3000:])
    return results


def um_usage(name, user):
    with base.connector(name)() as r:
        sessions = r.run('/user-manager session print detail without-paging where user="%s"' % user)
        print(sessions[-1500:])
        return sessions


def agent_log(n=40):
    return sh("sudo journalctl -u pv-agent -n %d --no-pager" % n, check=False)


def main():
    import linux
    from linux import LinuxHost

    step("User Manager 1 and 2")
    prepare_um("A")
    prepare_um("B")

    step("setup the Linux server (this runner)")

    def connect_linux():
        return LinuxHost("127.0.0.1", 22, "root", ROOT_PW, timeout=30).connect()

    ip = sh("ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i==\"src\") print $(i+1)}'").strip()
    params, entry = linux.setup_linux(
        connect_linux, [(base.connector("A"), "A"), (base.connector("B"), "B")], "it1", ip,
        params={"interval": 10}, log=print, linux_ip_seen_by_router=base.SLIRP_HOST, router_addresses=REACH)
    print(json.dumps(entry, indent=1))
    problems = []
    for _ in range(12):
        time.sleep(5)
        if "users allowed" in agent_log():
            break
    print(agent_log())

    step("clients with the right password")
    res = run_clients(entry, USER, PASS)
    problems += ["%s with right password: %s" % kv for kv in res.items() if kv[1] != "204"]

    step("monitoring sees who is connected with which protocol")
    import monitor
    time.sleep(15)
    with connect_linux() as h:
        st = monitor.linux_status(h)
    print(json.dumps(st, ensure_ascii=False, indent=1)[:2000])
    for tag in ("vless-vision", "vless-xhttp", "hy2", "ss"):
        if st["by_protocol"].get(tag, 0) < 1:
            problems.append("monitor: no %s user online" % tag)
    if st["services"].get("xray") != "active" or st["services"].get("pv-agent") != "active":
        problems.append("monitor: services %s" % st["services"])

    step("clients with a wrong password must fail")
    res = run_clients(entry, USER, "nope", only=["vision", "ss"])
    problems += ["%s let a wrong password in" % k for k, v in res.items() if v == "204"]

    step("accounting reached User Manager 1")
    time.sleep(25)
    print(agent_log(60))
    if "pv-it1" not in um_usage("A", USER) and "nas-identifier" not in um_usage("A", USER):
        problems.append("no session from the Linux server in UM1")

    step("AmneziaWG peer")
    if any(p["type"] == "amneziawg" for p in entry["protocols"]):
        pub = sh("echo %s | awg pubkey" % pvcreds.awg_private(USER, PASS)).strip()
        peers = sh("sudo awg show awg0 allowed-ips", check=False)
        print(peers)
        if pub not in peers or pvcreds.awg_address(USER) not in peers:
            problems.append("awg peer missing")
        else:
            problems += awg_client_test(entry)
    else:
        problems.append("AmneziaWG not installed")

    step("UM1 dies: the agent keeps going with UM2")
    with base.connector("B")() as r:
        r.run("/user-manager user add name=%s password=%s" % (USER2, PASS2))
        r.run("/user-manager user-profile add user=%s profile=30d-25G" % USER2)
    m = __import__("socket").socket(__import__("socket").AF_UNIX)
    m.connect("/tmp/mon-A.sock")
    m.sendall(b"quit\n")
    time.sleep(40)
    print(agent_log(30))
    res = run_clients(entry, USER2, PASS2, only=["vision"])
    if res.get("vision") != "204":
        problems.append("user from UM2 not let in after UM1 died")
    time.sleep(45)
    print(agent_log(30))
    if USER2 not in um_usage("B", USER2):
        problems.append("no accounting on UM2 after failover")

    if problems:
        raise SystemExit("PROBLEMS:\n  " + "\n  ".join(problems))
    print("\nLINUX ALL OK")


def awg_client_test(entry):
    a = next(p for p in entry["protocols"] if p["type"] == "amneziawg")
    conf = """[Interface]
PrivateKey = %s
Jc = %d
Jmin = %d
Jmax = %d
S1 = %d
S2 = %d
H1 = %d
H2 = %d
H3 = %d
H4 = %d

[Peer]
PublicKey = %s
Endpoint = 10.200.0.1:%d
AllowedIPs = 10.64.0.1/32
PersistentKeepalive = 5
""" % (pvcreds.awg_private(USER, PASS), a["jc"], a["jmin"], a["jmax"], a["s1"], a["s2"], a["h1"], a["h2"],
       a["h3"], a["h4"], a["public_key"], a["port"])
    with open("/tmp/awgc.conf", "w") as f:
        f.write(conf)
    cmds = """set -e
ip netns add c1
ip link add vh type veth peer name vc
ip link set vc netns c1
ip addr add 10.200.0.1/24 dev vh; ip link set vh up
ip netns exec c1 ip addr add 10.200.0.2/24 dev vc
ip netns exec c1 ip link set vc up; ip netns exec c1 ip link set lo up
ip netns exec c1 ip link add awgc type amneziawg 2>/dev/null || ip netns exec c1 amneziawg-go awgc
sleep 1
ip netns exec c1 awg setconf awgc /tmp/awgc.conf
ip netns exec c1 ip addr add %s/32 dev awgc
ip netns exec c1 ip link set awgc up
ip netns exec c1 ip route add 10.64.0.1/32 dev awgc
ip netns exec c1 ping -c 3 -W 3 10.64.0.1
""" % pvcreds.awg_address(USER)
    p = subprocess.run(["sudo", "bash", "-c", cmds], capture_output=True, text=True)
    print(p.stdout[-1500:], p.stderr[-1500:])
    return [] if p.returncode == 0 else ["awg client could not reach the server"]


if __name__ == "__main__":
    main()
