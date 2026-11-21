"""Backup tunnel of the main router: SSTP users' traffic goes over the GRE
tunnel to the router abroad as before; when GRE stops answering, it goes
over AmneziaWG to a Linux server instead, and back when GRE returns.

    SSTP user -> main router -[GRE]-> router abroad -> internet      (normal)
    SSTP user -> main router -[WireGuard]-> relay container
                 -[AmneziaWG]-> Linux server -> internet             (backup)
                 (AmneziaWG inside ICMP echo when UDP is cut: pv_icmp.py)

RouterOS only speaks plain WireGuard, which Iran's filtering drops, so a
small relay in a container (server/mikrotik/awgrelay.py) turns it into
AmneziaWG. The existing setup is only added to: a route with a higher
distance in the same routing table as the GRE route, and a health check
(check-gateway=ping) on the GRE route so RouterOS notices it is down.
Everything added carries the comment "pv-backup"; remove() takes it out.
"""

import ipaddress
import json
import os
import re
import sys

import services as sv
from publisher import ReleaseError
from routeros import RouterOSError, q

TAG = "pv-backup"
WG = "wg-pvbackup"
WG_PORT = 13233
MTU = 1380
TUN_ADDR = "10.64.0.2"            # the router inside the Linux server's AmneziaWG network
TUN_GW = "10.64.0.1"
RELAY_PORT = 51820
RELAY = {"comment": "pvawg", "veth": "veth-pvawg", "ip": "172.17.0.4", "dir": "pvawg",
         "cmd": "python3 /app/awgrelay.py /app/relay.json"}
STATE = "pvawg/state.json"         # what was changed on the existing setup, to undo it
MIN_FREE = 80 * 1024 * 1024        # the Python image of the relay container


class Plan:
    def __init__(self):
        self.routes = []           # GRE default routes: dict(id, table, gateway, distance, check, gre)
        self.gres = {}             # name -> dict(remote, keepalive, nets)
        self.problems = []         # why it cannot be set up automatically
        self.warnings = []
        self.changes = []          # what will be changed on the existing setup (text)
        self.tables = []
        self.relay_ip = RELAY["ip"]

    @property
    def ok(self):
        return not self.problems and bool(self.routes)


def _lines(out, kind):
    for line in out.splitlines():
        parts = line.strip().split("|")
        if parts and parts[0] == kind:
            yield parts[1:]


def read_router(r):
    """Raw facts: GRE interfaces, addresses, default routes, PPP profiles."""
    # whole-item "get" arrays: a property that is not set (check-gateway,
    # comment ...) is just missing there, while "get $i prop" would stop the script
    out = r.run(
        ':foreach i in=[/interface gre find] do={:local g [/interface gre get $i]; '
        ':put ("g|" . ($g->"name") . "|" . [:tostr ($g->"remote-address")] . "|" . [:tostr ($g->"keepalive")] . '
        '"|" . [:tostr ($g->"running")])}; '
        ':foreach i in=[/ip address find] do={:local a [/ip address get $i]; '
        ':put ("a|" . ($a->"interface") . "|" . ($a->"address"))}; '
        ':foreach i in=[/ip route find where dst-address=0.0.0.0/0] do={:local x [/ip route get $i]; '
        ':if (($x->"disabled") != true) do={:put ("r|" . $i . "|" . [:tostr ($x->"gateway")] . "|" . '
        '[:tostr ($x->"routing-table")] . "|" . [:tostr ($x->"distance")] . "|" . [:tostr ($x->"check-gateway")] . '
        '"|" . [:tostr ($x->"comment")] . "|" . [:tostr ($x->"active")])}}; '
        ':foreach i in=[/ppp profile find] do={:local p [/ppp profile get $i]; '
        ':put ("p|" . ($p->"name") . "|" . [:tostr ($p->"dns-server")])}')
    gres = {}
    for name, remote, keepalive, running in _lines(out, "g"):
        gres[name] = {"remote": remote, "keepalive": keepalive, "running": running == "true", "nets": []}
    addrs = []
    for iface, addr in _lines(out, "a"):
        addrs.append((iface, addr))
        if iface in gres:
            try:
                gres[iface]["nets"].append(ipaddress.ip_interface(addr).network)
            except ValueError:
                pass
    routes = []
    for parts in _lines(out, "r"):
        if len(parts) < 7:
            continue
        rid, gw, table, dist, check, comment, active = parts[:7]
        routes.append({"id": rid, "gateway": gw, "table": table or "main", "distance": int(dist or 1),
                       "check": check, "comment": comment, "active": active == "true"})
    profiles = [(n, d) for n, d in _lines(out, "p")]
    return gres, addrs, routes, profiles


def gre_of(gateway, gres):
    """The GRE interface a route's gateway goes through, or None."""
    for gw in sv.addr_list(gateway):
        ip, _, iface = gw.partition("%")
        if ip in gres:
            return ip
        if iface in gres:
            return iface
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            continue
        for name, g in gres.items():
            if any(a in n for n in g["nets"]):
                return name
    return None


def free_relay_ip(veths, addrs):
    """The relay's address in the containers' network: its current one if no
    other container has it, else the first free one (another container may
    already use 172.17.0.4)."""
    def ip(a):
        return str(a).split("/")[0].strip()
    taken = {ip(a) for n, a in veths if n != RELAY["veth"]} | {ip(a) for _, a in addrs} | {sv.GW}
    own = next((ip(a) for n, a in veths if n == RELAY["veth"]), None)
    if own and own not in taken:
        return own
    if RELAY["ip"] not in taken:
        return RELAY["ip"]
    for n in range(5, 255):
        cand = "172.17.0.%d" % n
        if cand not in taken:
            return cand
    return None


def make_plan(gres, addrs, routes, profiles, veths=()):
    plan = Plan()
    plan.gres = gres
    if not gres:
        plan.problems.append("روی این روتر تانل GRE پیدا نشد.")
        return plan
    for rt in routes:
        if rt["comment"] == TAG:
            continue
        g = gre_of(rt["gateway"], gres)
        if g:
            rt["gre"] = g
            plan.routes.append(rt)
    if not plan.routes:
        plan.problems.append("مسیر پیش‌فرضی (0.0.0.0/0) که از GRE برود پیدا نشد. مسیرهای پیش‌فرض روتر: %s"
                             % ("، ".join("%s (جدول %s)" % (r["gateway"], r["table"]) for r in routes) or "هیچ"))
        return plan
    if any(rt["table"] == "main" for rt in plan.routes):
        plan.problems.append("مسیر پیش‌فرض جدول main از GRE می‌رود (همه‌ی ترافیک خود روتر). این حالت خودکار "
                             "پشتیبانی نمی‌شود چون تانل پشتیبان هم باید از اینترنت ایران برود.")
    plan.tables = sorted({rt["table"] for rt in plan.routes})
    for rt in plan.routes:
        ip = sv.addr_list(rt["gateway"])[0].partition("%")[0]
        is_ip = bool(re.fullmatch(r"[\d.]+", ip))
        if is_ip and not rt["check"]:
            plan.changes.append("روی مسیر %s (جدول %s) بررسی سلامت check-gateway=ping گذاشته می‌شود."
                                % (rt["gateway"], rt["table"]))
        elif not is_ip and not gres[rt["gre"]]["keepalive"]:
            plan.changes.append("روی تانل %s گزینه‌ی keepalive=10s,3 فعال می‌شود تا قطعی را بفهمد." % rt["gre"])
    nets = [n for g in gres.values() for n in g["nets"]]
    for name, dns in profiles:
        for d in sv.addr_list(dns):
            try:
                if any(ipaddress.ip_address(d) in n for n in nets):
                    plan.warnings.append("DNS پروفایل PPP «%s» (%s) آن طرف GRE است؛ وقتی GRE قطع است کاربران "
                                         "نام‌ها را باز نمی‌کنند. بهتر است DNS عمومی (مثل 1.1.1.1) یا خود روتر باشد."
                                         % (name, d))
            except ValueError:
                pass
    used = [a for i, a in addrs if i != WG and a.split("/")[0] == TUN_ADDR]
    plan.relay_ip = free_relay_ip(veths, addrs)
    if plan.relay_ip is None:
        plan.problems.append("در شبکه‌ی کانتینرها (172.17.0.0/24) آدرس آزادی برای رله نمانده است.")
    elif plan.relay_ip != RELAY["ip"]:
        plan.changes.append("آدرس %s مال کانتینر دیگری است؛ رله آدرس %s را می‌گیرد."
                            % (RELAY["ip"], plan.relay_ip))
    if used:
        plan.problems.append("آدرس %s روی روتر استفاده شده است." % "، ".join(used))
    return plan


def inspect(r):
    out = r.run(':foreach i in=[/interface veth find] do={:local v [/interface veth get $i]; '
                ':put ("v|" . ($v->"name") . "|" . [:tostr ($v->"address")])}', check=False)
    veths = [(n, a) for n, a, *_ in (x + [""] for x in _lines(out, "v"))]
    return make_plan(*read_router(r), veths=veths)


def describe(plan, server):
    lines = ["تانل پشتیبان AmneziaWG به %s:" % server, ""]
    for rt in plan.routes:
        lines.append("• ترافیکی که الان از %s (جدول %s، فاصله %d) می‌رود، اگر GRE قطع شد از AmneziaWG می‌رود."
                     % (rt["gateway"], rt["table"], rt["distance"]))
    lines += ["• یک کانتینر کوچک (رله) و اینترفیس %s ساخته می‌شود؛ همه با توضیح %s." % (WG, TAG)]
    lines += ["• اگر UDP به سرور لینوکس هم بسته شد، رله خودکار بسته‌ها را داخل پینگ (ICMP) می‌فرستد؛ "
              "روی سرور لینوکس سرویس pv-icmp نصب می‌شود."]
    lines += ["• " + c for c in plan.changes]
    if plan.warnings:
        lines += [""] + ["⚠ " + w for w in plan.warnings]
    return "\n".join(lines)


# ---------------------------------------------------------------- router side

def relay_source():
    here = os.path.dirname(os.path.abspath(__file__))
    for d in (here, getattr(sys, "_MEIPASS", None), os.path.join(here, "..", "..", "server", "mikrotik")):
        if d and os.path.isfile(os.path.join(d, "awgrelay.py")):
            with open(os.path.join(d, "awgrelay.py"), "rb") as f:
                return f.read()
    raise ReleaseError("فایل awgrelay.py همراه برنامه پیدا نشد.")


def ensure_wireguard(r, log=print):
    """The router's WireGuard interface; returns its public key."""
    if sv.count(r, "/interface wireguard", "name=%s" % q(WG)) == 0:
        log("ساخت اینترفیس %s…" % WG)
        r.run("/interface wireguard add name=%s listen-port=%d mtu=%d comment=%s" % (WG, WG_PORT, MTU, TAG))
    if sv.count(r, "/ip address", "interface=%s" % q(WG)) == 0:
        r.run("/ip address add address=%s/32 network=%s interface=%s comment=%s" % (TUN_ADDR, TUN_GW, WG, TAG))
    return r.run(":put [/interface wireguard get [find where name=%s] public-key]" % q(WG)).strip()


def ensure_peer(r, server_public, endpoint, port, log=print):
    where = "interface=%s" % q(WG)
    if sv.count(r, "/interface wireguard peers", where) == 0:
        r.run("/interface wireguard peers add interface=%s public-key=%s endpoint-address=%s endpoint-port=%d "
              "allowed-address=0.0.0.0/0 persistent-keepalive=25s comment=%s"
              % (WG, q(server_public), endpoint, port, TAG))
    else:
        r.run("/interface wireguard peers set [find where %s] public-key=%s endpoint-address=%s endpoint-port=%d "
              "allowed-address=0.0.0.0/0 persistent-keepalive=25s" % (where, q(server_public), endpoint, port))


def relay_config(server_ip, awg, router_public):
    cfg = {k: awg[k] for k in ("port", "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4")}
    cfg.update(server=server_ip, server_public=awg["public"], router_public=router_public, listen=RELAY_PORT)
    if awg.get("icmp_key"):
        cfg.update(icmp_key=awg["icmp_key"], transport="auto")
    return cfg


def free_space(r):
    try:
        return int(r.run(":put [/system resource get free-hdd-space]").strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None


def relay_svc(ip):
    return dict(RELAY, ip=ip)


def install_relay(r, cfg, log=print, ip=RELAY["ip"]):
    svc = relay_svc(ip)
    exists = sv.count(r, "/container", "comment=%s" % q(RELAY["comment"])) > 0
    if not exists:
        free = free_space(r)
        if free is not None and free < MIN_FREE:
            raise RouterOSError("فضای خالی روتر %d مگابایت است؛ برای کانتینر رله حدود ۸۰ مگابایت لازم است."
                                % (free // 2 ** 20))
    if sv.count(r, "/interface veth", "name=%s" % q(RELAY["veth"])):
        r.run("/interface veth set [find where name=%s] address=%s/24 gateway=%s" % (q(RELAY["veth"]), ip, sv.GW))
    sv.ensure_network(r, svc, log)
    sv.ensure_dir(r, RELAY["dir"])
    r.put(RELAY["dir"] + "/awgrelay.py", relay_source())
    r.put(RELAY["dir"] + "/relay.json", json.dumps(cfg, indent=1).encode())
    log("کانتینر رله (%s)…" % ip)
    sv.ensure_container(r, svc, log)
    if exists:
        sv.restart(r, svc, log)


def _place(r, menu):
    return " place-before=0" if sv.count(r, menu) else ""


def _add_once(r, menu, where, cmd):
    if sv.count(r, menu, where) == 0:
        r.run("%s add %s%s" % (menu, cmd, _place(r, menu)))


def configure_routes(r, plan, relay_ip=RELAY["ip"], log=print):
    """Backup route next to each GRE route, health checks, NAT and MSS."""
    state = {"check": [], "keepalive": []}
    old = sv.file_text(r, STATE)
    if old:
        try:
            state.update(json.loads(old))
        except ValueError:
            pass
    if relay_ip:
        # the relay's own packets must leave through the Iranian internet,
        # whatever marks the existing setup puts on the router's traffic
        _add_once(r, "/routing rule", "comment=%s" % q(TAG),
                  "src-address=%s/32 action=lookup-only-in-table table=main comment=%s" % (relay_ip, TAG))
        r.run("/routing rule set [find where comment=%s] src-address=%s/32" % (q(TAG), relay_ip))
    for table in plan.tables:
        dist = max(rt["distance"] for rt in plan.routes if rt["table"] == table) + 1
        where = "comment=%s and routing-table=%s" % (q(TAG), q(table))
        if sv.count(r, "/ip route", where) == 0:
            log("مسیر پشتیبان در جدول %s (فاصله %d)…" % (table, dist))
            r.run("/ip route add dst-address=0.0.0.0/0 gateway=%s routing-table=%s distance=%d comment=%s"
                  % (WG, q(table), dist, TAG))
        else:
            r.run("/ip route set [find where %s] gateway=%s distance=%d" % (where, WG, dist))
    for rt in plan.routes:
        gw = sv.addr_list(rt["gateway"])[0].partition("%")[0]
        if re.fullmatch(r"[\d.]+", gw):
            if not rt["check"]:
                log("بررسی سلامت روی مسیر %s…" % rt["gateway"])
                r.run("/ip route set %s check-gateway=ping" % rt["id"])
                state["check"].append([rt["table"], rt["gateway"]])
        elif not plan.gres[rt["gre"]]["keepalive"]:
            log("keepalive روی %s…" % rt["gre"])
            r.run("/interface gre set [find where name=%s] keepalive=10s,3" % q(rt["gre"]))
            state["keepalive"].append(rt["gre"])
    _add_once(r, "/ip firewall nat", "comment=%s" % q(TAG),
              "chain=srcnat out-interface=%s action=masquerade comment=%s" % (WG, TAG))
    _add_once(r, "/ip firewall mangle", "comment=%s and chain=forward" % q(TAG),
              "chain=forward out-interface=%s protocol=tcp tcp-flags=syn action=change-mss "
              "new-mss=clamp-to-pmtu passthrough=yes comment=%s" % (WG, TAG))
    if sv.count(r, "/ip firewall filter", "chain=forward"):
        _add_once(r, "/ip firewall filter", "comment=%s and out-interface=%s" % (q(TAG), WG),
                  "chain=forward out-interface=%s action=accept comment=%s" % (WG, TAG))
        _add_once(r, "/ip firewall filter", "comment=%s and in-interface=%s" % (q(TAG), WG),
                  "chain=forward in-interface=%s connection-state=established,related action=accept comment=%s"
                  % (WG, TAG))
    if relay_ip:
        sv.ensure_input_accept(r, relay_ip, "udp", str(WG_PORT), TAG)
        r.run("/ip firewall filter set [find where comment=%s and chain=input] src-address=%s" % (q(TAG), relay_ip),
              check=False)
    state["check"] = [list(x) for x in {tuple(x) for x in state["check"]}]
    state["keepalive"] = sorted(set(state["keepalive"]))
    sv.ensure_dir(r, RELAY["dir"])
    r.put(STATE, json.dumps(state).encode())


def _ssh_errors():
    try:
        import paramiko
        return (paramiko.SSHException,)
    except ImportError:
        return ()


def setup(r, linux_connect, p, server_ip, log=print, relay_endpoint=None):
    """Everything, on the router r and the Linux server; p are the server's
    params (updated with the router's peer, to be saved by the caller).
    relay_endpoint: (host, port) of a relay that runs elsewhere (tests)."""
    import linux
    plan = inspect(r)
    if not plan.ok:
        raise RouterOSError("\n".join(plan.problems) or "مسیر GRE پیدا نشد.")
    awg = p.get("awg") or {}
    if not awg.get("priv"):
        raise ReleaseError("این سرور لینوکس AmneziaWG ندارد.")
    pub = ensure_wireguard(r, log)
    # the ICMP carrier first (touches nothing users use), the peer last (it
    # restarts pv-agent); if the SSH connection drops (e.g. the phone's own VPN
    # goes through this server), connect again: both steps can be repeated
    for attempt in range(3):
        try:
            h = linux_connect()
            try:
                p = linux.ensure_icmp(h, p, log)
                p = linux.add_static_peer(h, p, pub, TUN_ADDR, log)
            finally:
                try:
                    h.close()
                except Exception:   # noqa: BLE001
                    pass
            break
        except (OSError, EOFError) + _ssh_errors() as e:
            if attempt == 2:
                raise
            log("ارتباط با سرور لینوکس قطع شد (%s)؛ دوباره…" % e)
            import time
            time.sleep(5)
    awg = p["awg"]
    if relay_endpoint:
        ensure_peer(r, awg["public"], relay_endpoint[0], relay_endpoint[1], log)
    else:
        install_relay(r, relay_config(server_ip, awg, pub), log, ip=plan.relay_ip)
        ensure_peer(r, awg["public"], plan.relay_ip, RELAY_PORT, log)
    configure_routes(r, plan, relay_ip=None if relay_endpoint else plan.relay_ip, log=log)
    log("✓ تانل پشتیبان آماده است")
    return p


# ---------------------------------------------------------------- status and removal

def status(r):
    """dict: installed, handshake (RouterOS text or ""), rx, tx, using (per table: "GRE"/"AmneziaWG"/"-"),
    relay (container state)."""
    out = {"installed": sv.count(r, "/interface wireguard", "name=%s" % q(WG)) > 0}
    if not out["installed"]:
        return out
    res = r.run(':local i [/interface wireguard peers find where interface=%s]; :if ([:len $i] > 0) do={'
                ':local p [/interface wireguard peers get ($i->0)]; '
                ':put ("h|" . [:tostr ($p->"last-handshake")] . "|" . [:tostr ($p->"rx")] . "|" . [:tostr ($p->"tx")])}; '
                ':foreach i in=[/ip route find where dst-address=0.0.0.0/0 and active] do={:local x [/ip route get $i]; '
                ':put ("r|" . [:tostr ($x->"routing-table")] . "|" . [:tostr ($x->"gateway")] . "|" . '
                '[:tostr ($x->"comment")])}' % q(WG))
    for hs, rx, tx in _lines(res, "h"):
        import monitor
        out.update(handshake=hs, rx=monitor._size(rx or 0), tx=monitor._size(tx or 0))
    using = {}
    for table, gw, comment in _lines(res, "r"):
        using[table or "main"] = "AmneziaWG" if comment == TAG or gw == WG else gw
    out["using"] = using
    out["relay"] = sv.container_status(r, RELAY) if sv.has_package(r, "container") else "none"
    out["carrier"] = (sv.file_text(r, RELAY["dir"] + "/mode.txt") or "").strip().upper() or "UDP"
    # why nothing reaches the relay, if that is the case (each part alone:
    # a missing menu must not hide the others)
    parts = [
        ':put ("ping|" . [/ping %(ip)s count=2 interval=300ms])',
        ':foreach i in=[/interface veth find] do={:local v [/interface veth get $i]; '
        ':put ("veth|" . ($v->"name") . "|" . [:tostr ($v->"address")])}',
        ':local i [/interface wireguard peers find where interface=%(wg)s]; :if ([:len $i] > 0) do={'
        ':local p [/interface wireguard peers get ($i->0)]; :put ("peer|" . [:tostr ($p->"endpoint-address")] . '
        '"|" . [:tostr ($p->"endpoint-port")] . "|" . [:tostr ($p->"current-endpoint-address")] . "|" . '
        '[:tostr ($p->"current-endpoint-port")])}',
        ':foreach i in=[/ip route find where dst-address~"^172.17.0." and active] do={'
        ':local x [/ip route get $i]; :put ("route|" . ($x->"dst-address") . "|" . [:tostr ($x->"gateway")] '
        '. "|" . [:tostr ($x->"routing-table")])}',
        ':put ("rules|" . [:len [/routing rule find]] . "|" . [:len [/ip firewall mangle find where chain=output]] '
        '. "|" . [:len [/ip firewall filter find where chain=output]])']
    ip = r.run(':put [/interface veth get [find where name=%s] address]' % q(RELAY["veth"]), check=False)
    ip = ip.strip().split("/")[0] if re.match(r"\s*[\d.]+/", ip) else RELAY["ip"]
    diag = "\n".join(r.run(c % {"ip": ip, "wg": q(WG)}, check=False) for c in parts)
    out["diag"] = [l.strip() for l in diag.splitlines()
                   if l.strip().split("|")[0] in ("ping", "veth", "peer", "route", "rules")]
    logs = r.run(':foreach i in=[/log find where message~"awgrelay"] do={:put [/log get $i message]}', check=False)
    out["log"] = [l.strip() for l in logs.splitlines() if l.strip()][-4:]
    return out


def remove(r, log=print):
    state = {"check": [], "keepalive": []}
    try:
        state.update(json.loads(sv.file_text(r, STATE) or "{}"))
    except ValueError:
        pass
    for table, gw in state["check"]:
        r.run("/ip route unset [find where routing-table=%s and gateway=%s and dst-address=0.0.0.0/0] "
              "check-gateway" % (q(table), q(gw)), check=False)
    for gre in state["keepalive"]:
        r.run("/interface gre set [find where name=%s] !keepalive" % q(gre), check=False)
    for menu in ("/ip route", "/ip firewall nat", "/ip firewall mangle", "/ip firewall filter", "/routing rule",
                 "/ip address"):
        r.run("%s remove [find where comment=%s]" % (menu, q(TAG)), check=False)
    if sv.has_package(r, "container"):
        if sv.count(r, "/container", "comment=%s" % q(RELAY["comment"])):
            sv.stop(r, RELAY, log)
            r.run("/container remove [find where comment=%s]" % q(RELAY["comment"]))
        r.run("/container mounts remove [find where list=%s]" % q(RELAY["dir"]), check=False)
    r.run("/interface wireguard peers remove [find where interface=%s]" % q(WG), check=False)
    r.run("/interface wireguard remove [find where name=%s]" % q(WG), check=False)
    r.run("/interface bridge port remove [find where interface=%s]" % q(RELAY["veth"]), check=False)
    r.run("/interface veth remove [find where name=%s]" % q(RELAY["veth"]), check=False)
    r.remove(STATE)
    log("✓ تانل پشتیبان برداشته شد")
