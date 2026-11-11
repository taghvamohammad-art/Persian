"""Live state of all servers for the monitoring tab: health and who is
connected with which protocol.

MikroTik routers: /ppp active (SSTP, L2TP, ...) and system resources.
Linux servers: pv-agent's status file (users seen per Xray inbound in the
last few minutes, AmneziaWG handshakes) and system load.
"""

import json
import re
from concurrent.futures import ThreadPoolExecutor

import services as sv

PROTOCOL_NAMES = {
    "sstp": "SSTP", "l2tp": "L2TP", "ovpn": "OpenVPN", "pptp": "PPTP", "pppoe": "PPPoE",
    "vless-vision": "Reality", "vless-xhttp": "XHTTP", "hy2": "Hysteria2", "ss": "Shadowsocks",
    "amneziawg": "AmneziaWG", "vless-cdn": "CDN", "vless-dns": "DNS tunnel",
}


def proto_name(p):
    return PROTOCOL_NAMES.get(p, p)


def _size(v):
    """RouterOS sizes: "690.3MiB" or a plain number of bytes."""
    m = re.fullmatch(r"([\d.]+)\s*([KMGT]?)i?B?", str(v).strip())
    if not m:
        return 0
    return int(float(m.group(1)) * 1024 ** "_KMGT".index(m.group(2) or "_"))


def router_status(r):
    res = r.run(':put ([/system resource get cpu-load] . "|" . [/system resource get free-memory] . "|" . '
                '[/system resource get total-memory] . "|" . [/system resource get uptime] . "|" . '
                '[/system resource get version])').strip().split("|")
    cpu, free, total, uptime, version = (res + [""] * 5)[:5]
    online = []
    for line in r.lines(':foreach a in=[/ppp active find] do={:put ([/ppp active get $a name] . "|" . '
                        '[/ppp active get $a service] . "|" . [/ppp active get $a address] . "|" . '
                        '[/ppp active get $a uptime])}'):
        name, service, address, up = (line.split("|") + [""] * 4)[:4]
        online.append({"user": name, "protocol": service, "address": address, "since": up})
    by = {}
    for o in online:
        by[o["protocol"]] = by.get(o["protocol"], 0) + 1
    services = {}
    for svc in (sv.UMSTATUS, sv.UMBOT):
        try:
            state = sv.container_status(r, svc)
        except Exception:
            state = "none"
        if state != "none":
            services[svc["comment"]] = state
    total_b, free_b = _size(total), _size(free)
    return {"ok": True, "cpu": int(cpu or 0), "mem": round(100 * (total_b - free_b) / total_b) if total_b else None,
            "uptime": uptime, "version": "RouterOS " + version.split()[0] if version else "",
            "online": online, "by_protocol": by, "users_online": len({o["user"] for o in online}),
            "services": services}


def linux_status(h):
    raw = h.run("cat /var/lib/pv-agent/status.json 2>/dev/null || echo {}")
    st = json.loads(raw or "{}")
    sysinfo = h.run("cat /proc/loadavg; nproc; free -b | awk '/Mem:/{print $2, $7}'; cut -d. -f1 /proc/uptime; "
                    "for s in xray pv-agent awg-quick@awg0 nginx; do echo $s $(systemctl is-active $s 2>/dev/null); done",
                    check=False).split("\n")
    load = float(sysinfo[0].split()[0]) if sysinfo and sysinfo[0] else 0.0
    cpus = int(sysinfo[1]) if len(sysinfo) > 1 and sysinfo[1].strip().isdigit() else 1
    total, avail = (int(x) for x in sysinfo[2].split()) if len(sysinfo) > 2 and sysinfo[2].strip() else (0, 0)
    up = int(sysinfo[3]) if len(sysinfo) > 3 and sysinfo[3].strip().isdigit() else 0
    services = {}
    for line in sysinfo[4:]:
        parts = line.split()
        if len(parts) != 2:
            continue
        name = "amneziawg" if parts[0] == "awg-quick@awg0" else parts[0]
        if name in ("amneziawg", "nginx") and parts[1] == "inactive":
            continue           # not installed on this server
        services[name] = parts[1]
    online = [{"user": o["user"], "protocol": o["protocol"], "address": "",
               "since": "%d ثانیه پیش" % max(0, int(st.get("time", 0)) - o["last"])} for o in st.get("online", [])]
    return {"ok": True, "cpu": min(100, round(100 * load / cpus)), "mem": round(100 * (total - avail) / total) if total else None,
            "uptime": "%dd%dh%dm" % (up // 86400, up % 86400 // 3600, up % 3600 // 60),
            "version": "pv-agent (%s)" % (st.get("um_source") or "?"), "online": online,
            "by_protocol": st.get("by_protocol", {}), "users_online": st.get("users_online", 0),
            "allowed": st.get("allowed"), "services": services, "agent_time": st.get("time")}


def poll(routers, connector_for, workers=6):
    """{router id: status}; a server that cannot be reached gets ok=False."""
    def one(r):
        try:
            with connector_for(r)() as c:
                return r["id"], (linux_status(c) if r.get("role") == "linux" else router_status(c))
        except Exception as e:
            return r["id"], {"ok": False, "error": str(e).splitlines()[0][:200] if str(e) else type(e).__name__}
    if not routers:
        return {}
    with ThreadPoolExecutor(max_workers=min(workers, len(routers))) as pool:
        return dict(pool.map(one, routers))
