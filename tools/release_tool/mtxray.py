"""Xray server in a container on a MikroTik (e.g. the CHR abroad).

The app sees it as one more server (type "linux" in its config) with the
Xray protocols: VLESS Reality / XHTTP, Hysteria2 (Salamander) and
Shadowsocks-2022. Inside the container server/mikrotik/xraybox.py fetches
Xray, makes the keys and runs pv-agent, which keeps the users in step with
User Manager exactly as on a Linux server.

On the router: the containers' bridge and a veth (services.py), dst-nat of
the protocol ports and of the status port to the container, and an accept
rule in forward when the router has a firewall. Everything added carries the
comment "pv-xray"; remove() takes it out.
"""

import json
import os
import secrets
import sys
import time

import linux
import services as sv
from publisher import ReleaseError
from routeros import RouterOSError, q

TAG = "pv-xray"
BOX = {"comment": "pvxray", "veth": "veth-pvxray", "ip": "172.17.0.6", "dir": "pvxray",
       "cmd": "python3 /app/xraybox.py"}
STATUS_PORT = 8081            # inside the container (xraybox.py)
KEYS = BOX["dir"] + "/state/keys.json"


def box_source(name):
    here = os.path.dirname(os.path.abspath(__file__))
    for d in (here, getattr(sys, "_MEIPASS", None), os.path.join(here, "..", "..", "server", "mikrotik"),
              os.path.join(here, "..", "..", "server", "linux")):
        if d and os.path.isfile(os.path.join(d, name)):
            with open(os.path.join(d, name), "rb") as f:
                return f.read()
    raise ReleaseError("فایل %s همراه برنامه پیدا نشد." % name)


# ---------------------------------------------------------------- ports

def used_ports(r):
    """{("tcp"|"udp", port)} the router itself or its dst-nat already uses."""
    out = r.run(
        ':foreach i in=[/ip service find where disabled=no] do={:put ("tcp|" . [/ip service get $i port])}; '
        ':foreach i in=[/ip firewall nat find where chain=dstnat] do={:local n [/ip firewall nat get $i]; '
        ':put ([:tostr ($n->"protocol")] . "|" . [:tostr ($n->"dst-port")] . "|" . [:tostr ($n->"comment")])}; '
        ':do {:if ([/interface sstp-server server get enabled]) do={'
        ':put ("tcp|" . [/interface sstp-server server get port])}} on-error={}; '
        ':do {:foreach i in=[/interface wireguard find] do={'
        ':put ("udp|" . [/interface wireguard get $i listen-port])}} on-error={}; '
        ':do {:foreach i in=[/interface ovpn-server server find] do={'
        ':put ("tcp|" . [/interface ovpn-server server get $i port])}} on-error={}', check=False)
    used = set()
    for line in out.splitlines():
        parts = line.strip().split("|")
        if len(parts) < 2 or (len(parts) > 2 and parts[2] == TAG):
            continue                       # our own rules are made again
        protos = ("tcp", "udp") if parts[0] in ("", "nil") else (parts[0],)
        for chunk in parts[1].split(","):
            lo, _, hi = chunk.partition("-")
            try:
                lo, hi = int(lo), int(hi or lo)
            except ValueError:
                continue
            for port in range(lo, min(hi, lo + 2000) + 1):
                for pr in protos:
                    used.add((pr, port))
    return used


def pick_ports(p, used):
    """The usual ports where free on this router, else random high ones.
    Ports chosen before (p is saved) stay: the apps already know them, and
    the router's own dst-nat to the container lists them as "used"."""
    def free(proto, port, taken):
        return (proto, port) not in used and (proto, port) not in taken

    taken = set()
    for key, proto, default in (("vision_port", "tcp", 443), ("xhttp_port", "tcp", 8443),
                                ("hy2_port", "udp", 443), ("ss_port", "tcp", None),
                                ("status_port", "tcp", None)):
        protos = (proto, "udp") if key == "ss_port" else (proto,)
        port = p.get(key)
        if not (port and p.get("box_ports_chosen") and all((x, port) not in taken for x in protos)):
            port = port or default
            while not port or not all(free(x, port, taken) for x in protos):
                port = 20000 + secrets.randbelow(40000)
        p[key] = port
        for x in protos:
            taken.add((x, port))
    p["box_ports_chosen"] = True
    return p


# ---------------------------------------------------------------- files

def template(p):
    """Xray config for the container: the private key and certificate files
    are filled in there (xraybox.py), the log goes where pv-agent reads it."""
    t = linux.xray_template(dict(p, reality_private="__REALITY_PRIVATE__", domain=None))
    t["log"]["access"] = "/app/state/access.log"
    for ib in t["inbounds"]:
        for c in ib.get("streamSettings", {}).get("tlsSettings", {}).get("certificates", []):
            c["certificateFile"], c["keyFile"] = "__HY2_CERT__", "__HY2_KEY__"
    return t


def agent_config(p, name, public_ip, routers_cfg, radius_servers, allow):
    return {
        "routers": routers_cfg,
        "radius": {"servers": radius_servers, "nas_ip": public_ip, "nas_identifier": "pv-" + name},
        "xray": {"template": "/app/state/template.json", "config": "/app/state/config.json",
                 "bin": "/app/bin/xray", "assets": "/app/bin", "supervise": True,
                 "inbounds": {"vless-vision": "vless-vision", "vless-xhttp": "vless",
                              "hy2": "hysteria", "ss": "shadowsocks"}},
        "access_log": "/app/state/access.log",
        "status_file": "/app/state/status.json",
        "state": "/app/state/agent-state.json",
        "box_status": {"token": p["status_token"], "allow": sorted(allow)},
        "interval": p.get("interval", 60),
    }


# ---------------------------------------------------------------- router side

def box_ip(r):
    out = r.run(':foreach i in=[/interface veth find] do={:put ([/interface veth get $i name] . "|" . '
                '[:tostr [/interface veth get $i address]])}', check=False)
    veths = [tuple(l.strip().split("|", 1)) for l in out.splitlines() if "|" in l]
    taken = {a.split("/")[0] for n, a in veths if n != BOX["veth"]} | {sv.GW}
    own = next((a.split("/")[0] for n, a in veths if n == BOX["veth"]), None)
    if own and own not in taken:
        return own
    for n in [6] + list(range(7, 255)):
        cand = "172.17.0.%d" % n
        if cand not in taken:
            return cand
    raise RouterOSError("آدرس آزادی در شبکه‌ی کانتینرها نمانده است.")


def forward_rules(r, p, ip):
    """dst-nat of the protocol ports (and the status page) to the container."""
    wan = sv.wan_interface(r)
    if not wan:
        raise RouterOSError("کارت شبکه‌ی اینترنت روتر پیدا نشد.")
    r.run("/ip firewall nat remove [find where comment=%s]" % q(TAG), check=False)
    first = " place-before=0" if sv.count(r, "/ip firewall nat") else ""
    rules = [("tcp", p["vision_port"], p["vision_port"]), ("tcp", p["xhttp_port"], p["xhttp_port"]),
             ("udp", p["hy2_port"], p["hy2_port"]), ("tcp", p["ss_port"], p["ss_port"]),
             ("udp", p["ss_port"], p["ss_port"]), ("tcp", p["status_port"], STATUS_PORT)]
    for proto, port, to in rules:
        r.run("/ip firewall nat add chain=dstnat in-interface=%s protocol=%s dst-port=%d action=dst-nat "
              "to-addresses=%s to-ports=%d comment=%s%s"
              % (q(wan), proto, port, ip, to, q(TAG), first))
    r.run("/ip firewall filter remove [find where comment=%s]" % q(TAG), check=False)
    if sv.count(r, "/ip firewall filter", "chain=forward"):
        r.run("/ip firewall filter add chain=forward dst-address=%s connection-nat-state=dstnat action=accept "
              "comment=%s%s" % (ip, q(TAG), sv.place_first(r, "forward")))


def wait_keys(r, log, timeout=600):
    """The container's first start downloads Xray and makes the keys."""
    end = time.time() + timeout
    while time.time() < end:
        text = sv.file_text(r, KEYS)
        if text:
            try:
                keys = json.loads(text)
                if keys.get("reality_public") and keys.get("hy2_pin"):
                    return keys
            except ValueError:
                pass
        if sv.container_status(r, BOX) not in ("running", "starting"):
            raise RouterOSError("کانتینر Xray متوقف شد:\n%s" % box_log(r))
        time.sleep(5)
    raise RouterOSError("کانتینر Xray بعد از %d دقیقه آماده نشد:\n%s" % (timeout // 60, box_log(r)))


def box_log(r):
    text = sv.file_text(r, BOX["dir"] + "/state/box.log") or ""
    logs = r.run('/log print where topics~"container"', check=False).strip().splitlines()[-10:]
    return (text[-1200:] + "\n" + "\n".join(logs)).strip()


def setup_box(connect_box, um_routers, name, public_ip, params=None, log=print, router_addresses=None,
              seen_ip=None):
    """Install/refresh. connect_box: the MikroTik that runs the container;
    um_routers: [(connect(), host)] main first. Returns (params, app entry)."""
    p = linux.new_params(params)
    for k in ("domain", "domain_info", "cf_token"):
        p.pop(k, None)                     # no CDN here (no web server for the domain)
    import provision as pv
    r = connect_box()
    try:
        if not sv.has_package(r, "container"):
            log("نصب پکیج container (روتر یک بار ریبوت می‌شود؛ GRE و SSTP چند ثانیه قطع می‌شوند)…")
            r = pv.install_packages(r, connect_box, ["container"], log)
        if not sv.device_mode_container(r):
            pv.request_container_mode(r, log)
            raise RouterOSError(
                "حالت کانتینر درخواست شد. حالا ظرف ۵ دقیقه سرور را از پنل شرکت سرور مجازی یک بار کامل "
                "خاموش و روشن کنید (Power off / Power on یا Reset؛ ریبوت از داخل روتر قبول نمی‌شود).\n"
                "بعد از بالا آمدن روتر، دوباره «شروع» را بزنید.")
        pick_ports(p, used_ports(r))
    finally:
        r.close()
    log("پورت‌ها: Reality %(vision_port)d، XHTTP %(xhttp_port)d، Hysteria2 %(hy2_port)d/udp، "
        "Shadowsocks %(ss_port)d، وضعیت %(status_port)d" % p)

    routers_cfg, radius_servers, allow = linux.register_um(um_routers, name, seen_ip or public_ip, p, log,
                                                          router_addresses, what="سرور Xray")
    p["status_allow"] = sorted(allow)

    r = connect_box()
    try:
        BOX["ip"] = box_ip(r)
        sv.ensure_network(r, BOX, log)
        log("فرستادن فایل‌ها به روتر…")
        sv.ensure_dir(r, BOX["dir"])
        r.put(BOX["dir"] + "/xraybox.py", box_source("xraybox.py"))
        r.put(BOX["dir"] + "/pv_agent.py", box_source("pv_agent.py"))
        r.put(BOX["dir"] + "/pvcreds.py", box_source("pvcreds.py"))
        r.put(BOX["dir"] + "/template.in.json", json.dumps(template(p), indent=1).encode())
        r.put(BOX["dir"] + "/agent.json",
              json.dumps(agent_config(p, name, public_ip, routers_cfg, radius_servers, allow), indent=1).encode())
        forward_rules(r, p, BOX["ip"])
        existed = sv.count(r, "/container", "comment=%s" % q(BOX["comment"])) > 0
        sv.ensure_container(r, BOX, log)
        if existed:
            log("راه‌اندازی دوباره‌ی کانتینر با فایل‌های جدید…")
            sv.restart(r, BOX, log)
        log("کانتینر Xray را دانلود و کلیدها را می‌سازد (بار اول چند دقیقه)…")
        keys = wait_keys(r, log)
        p["reality_public"], p["hy2_pin"] = keys["reality_public"], keys["hy2_pin"]
        p["reality_private"] = "(in the container)"
        log("✓ کانتینر Xray اجرا شد.\n%s" % (box_log(r).splitlines() or [""])[-1])
    finally:
        r.close()
    return p, linux.server_entry(name, public_ip, p, awg=False)


def status(r):
    out = {"container": sv.container_status(r, BOX) if sv.has_package(r, "container") else "none",
           "rules": sv.count(r, "/ip firewall nat", "comment=%s" % q(TAG))}
    out["log"] = box_log(r)
    return out


def remove(r, log=print):
    if sv.has_package(r, "container") and sv.count(r, "/container", "comment=%s" % q(BOX["comment"])):
        sv.stop(r, BOX, log)
        r.run("/container remove [find where comment=%s]" % q(BOX["comment"]))
    for menu in ("/ip firewall nat", "/ip firewall filter"):
        r.run("%s remove [find where comment=%s]" % (menu, q(TAG)), check=False)
    log("✓ سرور Xray از روی روتر برداشته شد (فایل‌های %s ماندند)." % BOX["dir"])
