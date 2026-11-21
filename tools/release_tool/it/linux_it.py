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
        params={"interval": 10, "domain": "pv-it.example"}, log=print, linux_ip_seen_by_router=base.SLIRP_HOST, router_addresses=REACH)
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

    step("Xray update on a running server (already the latest: nothing changes)")
    try:
        with connect_linux() as h:
            print(linux.update_xray(h, log=print), linux.update_agent(h, log=print))
    except Exception as e:   # noqa: BLE001
        problems.append("update xray/agent: %s" % e)

    step("monitoring sees who is connected with which protocol")
    import monitor
    time.sleep(15)
    with connect_linux() as h:
        st = monitor.linux_status(h)
    print(json.dumps(st, ensure_ascii=False, indent=1)[:2000])
    if st["users_online"] < 1:
        problems.append("monitor: nobody online")
    stat = sh("curl -s --max-time 10 http://127.0.0.1/pvs/%s" % params["status_token"], check=False)
    try:
        tried = json.loads(stat).get("seen_by_protocol", {})
    except ValueError:
        tried = {}
    for tag in ("vless-vision", "vless-xhttp", "hy2", "ss"):     # one user on all: counted once online
        if tried.get(tag, 0) < 1:
            problems.append("status: %s use not seen" % tag)
    try:
        json.loads(stat)["online"]
    except (ValueError, KeyError):
        problems.append("status page for the bot: %r" % stat[:200])
    if sh("curl -s -o /dev/null -w '%%{http_code}' --max-time 10 http://127.0.0.1/pvs/wrong", check=False).strip() == "200" \
            and "online" in sh("curl -s --max-time 10 http://127.0.0.1/pvs/wrong", check=False):
        problems.append("status page answers a wrong token")
    page = sh("curl -s --max-time 10 http://127.0.0.1/", check=False)
    if "دانلود رایگان نرم‌افزار" not in page or "{{" in page:
        problems.append("decoy site not served on port 80: %r" % page[:200])
    if st["services"].get("xray") != "active" or st["services"].get("pv-agent") != "active":
        problems.append("monitor: services %s" % st["services"])

    def probe_json(text):
        # Xray prints warnings around the result line
        for line in text.splitlines():
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except ValueError:
                    pass
        return {}

    step("the app's engine (pvcore) probes every protocol")
    path = tempfile.mktemp(suffix=".json")
    probe_entry = dict(entry, host="127.0.0.1")
    # no Cloudflare here: the CDN path straight to the server's port 80, the
    # DNS tunnel with the server itself as the resolver
    probe_entry["protocols"] = [dict(p_, plain=True, **({"port": 80} if p_["type"] == "vless-xhttp-cdn" else {}))
                                if p_["type"] in ("vless-xhttp-cdn", "vless-dns") else p_
                                for p_ in entry["protocols"]]
    for want in ("vless-xhttp-cdn", "vless-dns"):
        if not any(p_["type"] == want for p_ in entry["protocols"]):
            problems.append("no %s in the server entry" % want)
    with open(path, "w") as f:
        json.dump(probe_entry, f)
    out = sh("/tmp/pvprobe -pool -entry %s -user %s -pass %s -timeout 10000" % (path, USER, PASS), check=False)
    print(out)
    res = probe_json(out)
    pool_line = next((l for l in out.splitlines() if l.startswith("pool:")), "")
    import re as _re
    nums = [int(x) for x in _re.findall(r"(-?\d+) ", pool_line + " ")[:2]]
    if len(nums) < 2 or min(nums) < 0:
        problems.append("pvcore pool (all protocols, fastest picked) failed: %s" % pool_line)
    # the DNS tunnel is skipped when a faster protocol works: probe it alone
    tunnel_path = tempfile.mktemp(suffix=".json")
    with open(tunnel_path, "w") as f:
        json.dump(dict(probe_entry, protocols=[p_ for p_ in probe_entry["protocols"] if p_["type"] == "vless-dns"]), f)
    tout = sh("/tmp/pvprobe -entry %s -user %s -pass %s -timeout 10000" % (tunnel_path, USER, PASS), check=False)
    print(tout)
    res.update({k: v for k, v in probe_json(tout).items() if k == "vless-dns"})
    res.setdefault("errors", {}).update(probe_json(tout).get("errors", {}))
    for p_ in entry["protocols"]:
        if not isinstance(res.get(p_["type"]), int) or res[p_["type"]] < 0:
            problems.append("pvcore probe failed for %s: %s" % (p_["type"], res.get("errors", {}).get(p_["type"])))
    bad = sh("/tmp/pvprobe -entry %s -user %s -pass wrong -timeout 5000" % (path, USER), check=False)
    print(bad)
    if any(isinstance(v, int) and v >= 0 for v in probe_json(bad).values()):
        problems.append("pvcore probe: a wrong password worked")

    step("the app's engine on a real TUN: data, DNS and switching protocols")
    problems += tun_e2e(probe_entry)

    step("clients with a wrong password must fail")
    res = run_clients(entry, USER, "nope", only=["vision", "ss"])
    problems += ["%s let a wrong password in" % k for k, v in res.items() if v == "204"]

    step("accounting reached User Manager 1")
    time.sleep(25)
    print(agent_log(60))
    if "pv-it1" not in um_usage("A", USER) and "nas-identifier" not in um_usage("A", USER):
        problems.append("no session from the Linux server in UM1")
    elif not any(t in um_usage("A", USER) for t in ("vless-vision", "ss", "hy2", "vless-xhttp")):
        problems.append("UM1 sessions carry no protocol (nas-port-id)")

    step("AmneziaWG peer")
    if any(p["type"] == "amneziawg" for p in entry["protocols"]):
        pub = sh("echo %s | awg pubkey" % pvcreds.awg_private(USER, PASS)).strip()
        peers = sh("sudo awg show awg0 allowed-ips", check=False)
        print(peers)
        if pub not in peers or pvcreds.awg_address(USER) not in peers:
            problems.append("awg peer missing")
        else:
            problems += awg_client_test(entry)
            step("backup tunnel: RouterOS WireGuard -> relay -> AmneziaWG")
            problems += backup_tunnel_test(params, connect_linux, ip)
    else:
        # Launchpad (the AmneziaWG PPA) is sometimes unreachable from GitHub's
        # runners; that is their outage, not ours
        ppa_down = sh("timeout 20 curl -sf -o /dev/null https://ppa.launchpadcontent.net/ && echo up",
                      check=False).strip() != "up"
        if ppa_down:
            print("WARNING: AmneziaWG not installed, Launchpad unreachable from this runner")
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


def backup_tunnel_test(params, connect_linux, server_ip):
    """GRE route on UM1 that goes nowhere; the backup takes over through the
    relay (run here on the runner: the CHR reaches it at 10.0.2.2)."""
    import backuptunnel as bt
    relay_dir = os.path.join(HERE, "..", "..", "..", "server", "mikrotik")
    problems = []
    with base.connector("A")() as r:
        for c in ["/routing table add name=to-gre fib",
                  "/interface gre add name=gre-test remote-address=192.0.2.1",
                  "/interface gre set [find where name=gre-test] !keepalive",
                  "/ip address add address=10.99.0.1/30 interface=gre-test",
                  "/ip route add dst-address=0.0.0.0/0 gateway=10.99.0.2 routing-table=to-gre"]:
            print(">", c)
            r.run(c)
        plan = bt.inspect(r)
        print(bt.describe(plan, server_ip), plan.problems)
        if not plan.ok or not plan.changes:
            return ["backup plan: %s %s" % (plan.problems, plan.changes)]
        # the relay's view: the router's public key is known once its interface exists
        pub = bt.ensure_wireguard(r)
        cfg = bt.relay_config("127.0.0.1", params["awg"], pub)
        cfg.update(listen=51899)
        with open("/tmp/relay.json", "w") as f:
            json.dump(cfg, f)
        relay = subprocess.Popen([sys.executable, os.path.join(relay_dir, "awgrelay.py"), "/tmp/relay.json"],
                                 stdout=open("/tmp/relay.log", "w"), stderr=subprocess.STDOUT)
        try:
            bt.setup(r, connect_linux, params, server_ip, log=print, relay_endpoint=(base.SLIRP_HOST, 51899))
            ok = False
            for _ in range(20):
                time.sleep(3)
                out = r.run("/ping 10.64.0.1 count=3 src-address=%s" % bt.TUN_ADDR, check=False)
                print(out.strip().splitlines()[-2:])
                if re.search(r"received=[123]", out):
                    ok = True
                    break
            for _ in range(30):                 # check-gateway needs a few failed pings to drop the GRE route
                st = bt.status(r)
                if st.get("using", {}).get("to-gre") == "AmneziaWG":
                    break
                time.sleep(5)
            print(st)
            print(r.run("/ip route print where routing-table=to-gre", check=False))
            if not ok:
                problems.append("backup tunnel: no ping through AmneziaWG")
            if st.get("using", {}).get("to-gre") != "AmneziaWG":
                problems.append("backup tunnel: to-gre does not use the backup (%s)" % st.get("using"))
            if not r.run(":put [:tostr ([/ip route get [find where gateway=10.99.0.2]]->\"check-gateway\")]").strip():
                problems.append("backup tunnel: no health check on the GRE route")
            # UDP cut, ping still passing: the same tunnel over ICMP (pv-icmp on the server)
            relay.terminate()
            relay.wait()
            if not params["awg"].get("icmp_key") or "active" not in sh("systemctl is-active pv-icmp", check=False):
                problems.append("backup tunnel: pv-icmp not installed on the server")
            cfg.update(icmp_key=params["awg"].get("icmp_key", ""), transport="icmp", mode_file="/tmp/relay-mode.txt")
            with open("/tmp/relay.json", "w") as f:
                json.dump(cfg, f)
            relay = subprocess.Popen(["sudo", sys.executable, os.path.join(relay_dir, "awgrelay.py"), "/tmp/relay.json"],
                                     stdout=open("/tmp/relay.log", "a"), stderr=subprocess.STDOUT)
            ok = False
            for _ in range(20):
                time.sleep(3)
                out = r.run("/ping 10.64.0.1 count=3 src-address=%s" % bt.TUN_ADDR, check=False)
                print("icmp:", out.strip().splitlines()[-2:])
                if re.search(r"received=[123]", out):
                    ok = True
                    break
            if not ok:
                problems.append("backup tunnel: no ping through AmneziaWG over ICMP")
                print(sh("sudo journalctl -u pv-icmp -n 30 --no-pager", check=False))
            if (open("/tmp/relay-mode.txt").read().strip() if os.path.exists("/tmp/relay-mode.txt") else "") != "icmp":
                problems.append("backup tunnel: relay did not report ICMP mode")
            if "64 bytes" not in sh("ping -c 2 -W 2 127.0.0.1", check=False):
                problems.append("backup tunnel: ordinary ping not answered while pv-icmp runs")
            time.sleep(25)                      # a pv-agent round: the router's peer must stay
            if pub not in sh("sudo awg show awg0 peers", check=False):
                problems.append("backup tunnel: pv-agent removed the router's peer")
            bt.remove(r, log=print)
            left = sum(int(r.run(":put [:len [%s find where comment=%s]]" % (m, bt.TAG)).strip() or 0)
                       for m in ("/ip route", "/ip firewall nat", "/ip firewall mangle", "/ip address"))
            if left or r.run(":put [:tostr ([/ip route get [find where gateway=10.99.0.2]]->\"check-gateway\")]").strip():
                problems.append("backup tunnel: remove() left %d items or the health check" % left)
        finally:
            relay.terminate()
            sh("sudo pkill -f awgrelay.py", check=False)
            print(open("/tmp/relay.log").read()[-3000:])
        for c in ["/ip route remove [find where gateway=10.99.0.2]", "/ip address remove [find where interface=gre-test]",
                  "/interface gre remove [find where name=gre-test]", "/routing table remove [find where name=to-gre]"]:
            r.run(c, check=False)
    return problems


DOWNLOADS = ["https://speed.cloudflare.com/__down?bytes=8000000", "https://proof.ovh.net/files/10Mb.dat"]


def tun_e2e(entry):
    """Like the phone: the engine reads a TUN; the "apps" live in a network
    namespace whose only route is that TUN. Checked after the first start,
    after every switch (new TUN first, then the engine moves over, as
    Android's establish() does) and after stop/start."""
    out = []
    path = tempfile.mktemp(suffix=".json")
    with open(path, "w") as f:
        json.dump(entry, f)
    sh("sudo ip netns add pvcli && sudo ip netns exec pvcli ip link set lo up && sudo mkdir -p /etc/netns/pvcli "
       "&& printf 'nameserver 1.1.1.1\\nnameserver 8.8.8.8\\n' | sudo tee /etc/netns/pvcli/resolv.conf")
    url = next((u for u in DOWNLOADS if sh("curl -s -o /dev/null -w '%%{http_code}' --max-time 20 '%s'" % u,
                                          check=False).strip() == "200"), None)
    print("download test:", url)
    eng = subprocess.Popen(["sudo", "/tmp/pvtuntest", "-entry", path, "-user", USER, "-pass", PASS],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def cmd(c):
        eng.stdin.write(c + "\n")
        eng.stdin.flush()
        while True:
            line = eng.stdout.readline()
            if not line:
                return "err engine exited"
            if line.startswith("@@ "):
                line = line[3:].strip()
                print("  engine:", c, "->", line)
                return line
            print("    |", line.rstrip()[:200])

    def use(dev, kind):
        if not cmd("open " + dev).startswith("ok"):
            return False
        addr = pvcreds.awg_address(USER) + "/32" if kind == "amneziawg" else "172.19.0.1/30"
        sh("sudo ip link set %s netns pvcli && sudo ip netns exec pvcli ip addr add %s dev %s && "
           "sudo ip netns exec pvcli ip link set %s mtu %d up && "
           "sudo ip netns exec pvcli ip route replace default dev %s"
           % (dev, addr, dev, dev, 1280 if kind == "amneziawg" else 1500, dev))
        return cmd("start " + kind).startswith("ok")

    def traffic(label, kind="pool"):
        ns = "sudo ip netns exec pvcli "
        dns = sum(1 for _ in range(5) if sh(ns + "dig +short +time=4 +tries=1 @1.1.1.1 example.com",
                                            check=False).strip())
        got = ""
        if url:
            got = sh(ns + "curl -s -o /dev/null -w '%%{size_download}' --max-time 40 '%s'" % url,
                     check=False, timeout=60).strip()
        health = cmd("check").replace("ok ", "")
        counted = cmd("bytes").replace("ok ", "").split()
        if kind != "amneziawg" and url and got.isdigit() and int(got) >= 5000000 and \
                not (len(counted) == 2 and int(counted[1]) >= int(got)):
            out.append("TUN %s: watchdog byte counters wrong: %s" % (label, counted))
        ok = dns >= 4 and (not url or got.isdigit() and int(got) >= 5000000)
        print("  %s: dns %d/5, download %s bytes, check %s" % (label, dns, got or "-", health))
        if not ok:
            out.append("TUN %s: dns %d/5, download %s bytes (engine check %s)" % (label, dns, got or "-", health))

    kinds = [p_["type"] for p_ in entry["protocols"] if p_["type"] != "vless-dns"]
    n = 0
    try:
        if use("pv%d" % n, "pool"):
            traffic("pool")
        else:
            out.append("TUN: pool did not start")
        for kind in kinds + ["pool"]:
            n += 1
            bg = subprocess.Popen("sudo ip netns exec pvcli curl -s -o /dev/null --max-time 20 '%s'" % (url or
                                  DOWNLOADS[0]), shell=True)        # a download running while switching
            time.sleep(1)
            if use("pv%d" % n, kind):
                traffic("switched to " + kind, kind)
            else:
                out.append("TUN: %s did not start" % kind)
            bg.kill()
        cmd("stop")
        n += 1
        if use("pv%d" % n, "pool"):
            traffic("pool after stop/start")
    finally:
        eng.stdin.close()
        eng.wait(timeout=30)
        sh("sudo ip netns del pvcli", check=False)
    return out


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
