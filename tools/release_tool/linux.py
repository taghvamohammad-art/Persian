"""Setting up a Linux (Ubuntu 24.04) VPN server from the release tool.

Over SSH as root: Xray-core (VLESS Reality Vision, VLESS XHTTP Reality,
Hysteria2, Shadowsocks-2022), AmneziaWG, and pv-agent, which keeps the
users in step with User Manager and reports their traffic to it over
RADIUS. On each User Manager router the Linux server is registered as a
RADIUS client and gets a read-only REST account restricted to its address.

The result is a server entry for the app's signed config (protocol
parameters, ports, keys, certificate pins), stored in the tool's settings.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import time

import services as sv
from publisher import ReleaseError
from routeros import RouterOSError, SSHRouter, q

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = "/opt/pv-agent"
XRAY_CONF_DIR = "/usr/local/etc/xray"
REALITY_TARGETS = ["www.microsoft.com", "www.apple.com", "www.speedtest.net", "dl.google.com"]


class LinuxError(ReleaseError):
    pass


class LinuxHost(SSHRouter):
    """SSH to a Linux server: commands fail on a non-zero exit status."""

    def run(self, cmd, timeout=900, check=True):
        return SSHRouter.run(self, cmd, timeout, check)

    def _run(self, cmd, timeout=900, check=True):
        ch = self._t.open_session(timeout=self.timeout)
        try:
            ch.settimeout(timeout)
            ch.set_combine_stderr(True)
            ch.exec_command(cmd)
            chunks = []
            while True:
                try:
                    data = ch.recv(65536)
                except socket.timeout:
                    raise LinuxError("سرور در زمان مقرر جواب نداد:\n%s" % cmd[:200])
                if not data:
                    break
                chunks.append(data)
            status = ch.recv_exit_status()
        finally:
            ch.close()
        out = b"".join(chunks).decode("utf-8", "replace")
        if check and status != 0:
            raise LinuxError("دستور روی سرور لینوکس ناموفق بود (%d):\n%s\n\n%s" % (status, cmd[:300], out[-800:]))
        return out

    def write(self, path, text, mode=None):
        self.put(path, text.encode() if isinstance(text, str) else text)
        if mode:
            self.run("chmod %s %s" % (mode, path))


def source(name):
    """A file shipped with the tool (bundled in the .exe) or from the repo."""
    import sys
    for d in (getattr(sys, "_MEIPASS", None), HERE, os.path.join(HERE, "..", "..", "server", "linux")):
        if d and os.path.isfile(os.path.join(d, name)):
            with open(os.path.join(d, name), "rb") as f:
                return f.read()
    raise ReleaseError("فایل %s همراه برنامه پیدا نشد." % name)


# ---------------------------------------------------------------- server side

def check_os(h):
    info = h.run(". /etc/os-release; echo $ID $VERSION_ID; uname -m").split()
    if len(info) < 3 or info[0] != "ubuntu" or info[2] not in ("x86_64", "aarch64"):
        raise LinuxError("فقط Ubuntu (x86_64 یا arm64) پشتیبانی می‌شود؛ این سرور: %s" % " ".join(info))
    return info


def install_base(h, log):
    log("نصب بسته‌های پایه (چند دقیقه)…")
    h.run("export DEBIAN_FRONTEND=noninteractive; apt-get update -q && "
          "apt-get install -y -q curl unzip python3 openssl iptables ca-certificates "
          "software-properties-common", timeout=1800)
    h.write("/etc/sysctl.d/90-pv.conf",
            "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\nnet.ipv4.ip_forward=1\n"
            "net.core.rmem_max=16777216\nnet.core.wmem_max=16777216\n")
    h.run("sysctl --system >/dev/null")


def install_xray(h, log):
    log("نصب Xray-core (آخرین نسخه)…")
    arch = "64" if "x86_64" in h.run("uname -m") else "arm64-v8a"
    script = r"""set -e
cd /tmp
tag=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | python3 -c 'import json,sys;print(json.load(sys.stdin)["tag_name"])')
curl -fsSLo xray.zip https://github.com/XTLS/Xray-core/releases/download/$tag/Xray-linux-%(arch)s.zip
curl -fsSLo xray.zip.dgst https://github.com/XTLS/Xray-core/releases/download/$tag/Xray-linux-%(arch)s.zip.dgst
want=$(grep -i 'SHA2-256' xray.zip.dgst | head -1 | awk -F'= ' '{print $2}')
have=$(sha256sum xray.zip | awk '{print $1}')
[ "$want" = "$have" ] || { echo "checksum mismatch"; exit 3; }
rm -rf xr && mkdir xr && unzip -q xray.zip -d xr
install -m 755 xr/xray /usr/local/bin/xray
mkdir -p /usr/local/share/xray %(conf)s
cp xr/geoip.dat xr/geosite.dat /usr/local/share/xray/ 2>/dev/null || true
echo $tag
""" % {"arch": arch, "conf": XRAY_CONF_DIR}
    tag = h.run(script, timeout=600).strip().splitlines()[-1]
    h.write("/etc/systemd/system/xray.service", """[Unit]
Description=Xray (Persian VPN)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/xray run -config %s/config.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
Environment=XRAY_LOCATION_ASSET=/usr/local/share/xray

[Install]
WantedBy=multi-user.target
""" % XRAY_CONF_DIR)
    h.run("systemctl daemon-reload")
    return tag


def x25519(h):
    """(private, public) Reality keys; xray changed its output format over time."""
    out = h.run("/usr/local/bin/xray x25519")
    priv = re.search(r"Private\s*key:\s*(\S+)|PrivateKey:\s*(\S+)", out)
    pub = re.search(r"Public\s*key:\s*(\S+)|Password(?:\s*\(PublicKey\))?:\s*(\S+)", out)
    if not priv or not pub:
        raise LinuxError("خروجی xray x25519 شناخته نشد:\n" + out)
    return (priv.group(1) or priv.group(2)), (pub.group(1) or pub.group(2))


def make_cert(h):
    """Self-signed certificate for Hysteria2; clients pin its SHA-256."""
    h.run("cd %s && [ -f hy2.crt ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 "
          "-nodes -days 3650 -subj /CN=%s -keyout hy2.key -out hy2.crt 2>/dev/null; chmod 600 hy2.key"
          % (XRAY_CONF_DIR, secrets.token_hex(6)))
    der = h.run("openssl x509 -in %s/hy2.crt -outform DER | base64 -w0" % XRAY_CONF_DIR).strip()
    return hashlib.sha256(base64.b64decode(der)).hexdigest()


def xray_template(p):
    """Full Xray config with empty user lists (pv-agent fills them)."""
    reality = {"show": False, "target": "%s:443" % p["sni"], "serverNames": [p["sni"]],
               "privateKey": p["reality_private"], "shortIds": [p["short_id"]]}
    return {
        "log": {"loglevel": "warning", "access": "/var/log/xray/access.log"},
        "api": {"tag": "api", "listen": "127.0.0.1:10085",
                "services": ["HandlerService", "StatsService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": [
            {"tag": "vless-vision", "port": p["vision_port"], "protocol": "vless",
             "settings": {"clients": [], "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": reality},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
            {"tag": "vless-xhttp", "port": p["xhttp_port"], "protocol": "vless",
             "settings": {"clients": [], "decryption": "none"},
             "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": p["xhttp_path"], "mode": "auto"},
                                "security": "reality", "realitySettings": reality},
             "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
            {"tag": "hy2", "port": p["hy2_port"], "protocol": "hysteria",
             "settings": {"version": 2, "users": []},
             "streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2},
                                "security": "tls",
                                "tlsSettings": {"alpn": ["h3"], "certificates": [
                                    {"certificateFile": XRAY_CONF_DIR + "/hy2.crt",
                                     "keyFile": XRAY_CONF_DIR + "/hy2.key"}]}}},
            {"tag": "ss", "port": p["ss_port"], "protocol": "shadowsocks",
             "settings": {"method": "2022-blake3-aes-128-gcm", "password": p["ss_server_key"],
                          "clients": [], "network": "tcp,udp"}},
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
        "routing": {"rules": [
            {"ip": ["geoip:private"], "outboundTag": "block"},
            {"protocol": ["bittorrent"], "outboundTag": "block"},
        ]},
    }


AMNEZIAWG_GO = r"""set -e
cd /tmp
ver=$(curl -fsSL 'https://go.dev/VERSION?m=text' | head -1)
arch=$(dpkg --print-architecture)
curl -fsSL -o go.tgz https://go.dev/dl/$ver.linux-$arch.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go.tgz
rm -rf amneziawg-go && git clone -q --depth 1 https://github.com/amnezia-vpn/amneziawg-go
# no C toolchain needed (some servers lack the libc headers)
cd amneziawg-go && CGO_ENABLED=0 PATH=/usr/local/go/bin:$PATH make >/dev/null
install -m 755 amneziawg-go /usr/bin/amneziawg-go
mkdir -p /etc/systemd/system/awg-quick@.service.d
printf '[Service]\nEnvironment=WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go\nEnvironment=AWG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go\n' > /etc/systemd/system/awg-quick@.service.d/userspace.conf
systemctl daemon-reload
"""


def install_awg(h, p, log):
    """AmneziaWG: the kernel module from the Amnezia PPA, or (when the kernel
    module cannot be built, e.g. no headers for this kernel) the userspace
    amneziawg-go. Returns False if neither works; the other protocols still do."""
    log("نصب AmneziaWG…")
    try:
        h.run("export DEBIAN_FRONTEND=noninteractive; add-apt-repository -y ppa:amnezia/ppa && "
              "apt-get update -q && apt-get install -y -q --no-install-recommends amneziawg-tools git", timeout=1800)
    except LinuxError as e:
        log("⚠ AmneziaWG نصب نشد:\n%s" % "\n".join(str(e).splitlines()[-15:]))
        return False
    kernel = h.run("export DEBIAN_FRONTEND=noninteractive; (apt-get install -y -q linux-headers-$(uname -r) "
                   "amneziawg-dkms >/dev/null 2>&1 && modprobe amneziawg && echo KERNEL_OK) || true",
                   timeout=1800)
    if "KERNEL_OK" in kernel:
        log("  ماژول کرنل AmneziaWG نصب شد")
    else:
        log("  ماژول کرنل ساخته نشد؛ نسخه‌ی userspace (amneziawg-go) ساخته می‌شود…")
        h.run("export DEBIAN_FRONTEND=noninteractive; apt-get purge -y -q amneziawg-dkms amneziawg >/dev/null 2>&1 || true")
        try:
            h.run(AMNEZIAWG_GO, timeout=1800)
        except LinuxError as e:
            log("⚠ AmneziaWG نصب نشد:\n%s" % "\n".join(str(e).splitlines()[-15:]))
            return False
    wan = h.run("ip route show default | awk '{print $5; exit}'").strip() or "eth0"
    conf = """[Interface]
PrivateKey = %(priv)s
Address = 10.64.0.1/10
ListenPort = %(port)d
Jc = %(jc)d
Jmin = %(jmin)d
Jmax = %(jmax)d
S1 = %(s1)d
S2 = %(s2)d
H1 = %(h1)d
H2 = %(h2)d
H3 = %(h3)d
H4 = %(h4)d
PostUp = iptables -t nat -A POSTROUTING -s 10.64.0.0/10 -o %(wan)s -j MASQUERADE; iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.64.0.0/10 -o %(wan)s -j MASQUERADE; iptables -D FORWARD -i %%i -j ACCEPT; iptables -D FORWARD -o %%i -j ACCEPT
""" % dict(p["awg"], wan=wan)
    h.run("mkdir -p /etc/amnezia/amneziawg")
    h.write("/etc/amnezia/amneziawg/awg0.conf", conf, "600")
    h.run("systemctl enable awg-quick@awg0 >/dev/null 2>&1; systemctl restart awg-quick@awg0")
    p["awg"]["public"] = h.run("echo %s | awg pubkey" % p["awg"]["priv"]).strip()
    return True


def awg_params():
    hs = set()
    while len(hs) < 4:
        hs.add(5 + secrets.randbelow(2 ** 31 - 10))
    h1, h2, h3, h4 = sorted(hs)
    priv = bytearray(secrets.token_bytes(32))
    priv[0] &= 248
    priv[31] = (priv[31] & 127) | 64
    jmin = 40 + secrets.randbelow(20)
    return {"priv": base64.b64encode(bytes(priv)).decode(), "port": 20000 + secrets.randbelow(40000),
            "jc": 3 + secrets.randbelow(6), "jmin": jmin, "jmax": jmin + 20 + secrets.randbelow(40),
            "s1": 15 + secrets.randbelow(60), "s2": 15 + secrets.randbelow(60),
            "h1": h1, "h2": h2, "h3": h3, "h4": h4}


def new_params(old=None):
    """Ports, keys and secrets of a server; kept across re-installs."""
    p = dict(old or {})
    p.setdefault("sni", secrets.choice(REALITY_TARGETS))
    p.setdefault("short_id", secrets.token_hex(4))
    p.setdefault("vision_port", 443)
    p.setdefault("xhttp_port", 8443)
    p.setdefault("xhttp_path", "/" + secrets.token_urlsafe(8))
    p.setdefault("hy2_port", 443)
    p.setdefault("ss_port", 20000 + secrets.randbelow(40000))
    p.setdefault("ss_server_key", base64.b64encode(secrets.token_bytes(16)).decode())
    p.setdefault("awg", awg_params())
    p.setdefault("radius_secret", secrets.token_urlsafe(24))
    p.setdefault("agent_password", secrets.token_urlsafe(24))
    return p


# ---------------------------------------------------------------- router side

REST_CERT = "pv-rest"


def router_rest_port(r, log):
    """www-ssl for the agents (port, certificate fingerprint). SSTP keeps 443."""
    port = int((sv.get(r, "/ip service", "name=www-ssl", "port") or "443").strip())
    if port == 443:
        port = 9443
    cert = (sv.get(r, "/ip service", "name=www-ssl", "certificate") or "").strip()
    if cert in ("", "none", "*0"):
        if sv.count(r, "/certificate", "name=%s" % q(REST_CERT)) == 0:
            log("ساخت گواهی REST روی روتر…")
            r.run("/certificate add name=%s common-name=%s key-size=2048 days-valid=3650"
                  % (REST_CERT, REST_CERT))
            r.run("/certificate sign %s" % REST_CERT, timeout=120)
            for _ in range(60):
                fp = sv.get(r, "/certificate", "name=%s" % q(REST_CERT), "fingerprint") or ""
                if re.fullmatch(r"[0-9a-f]{64}", fp.strip()):
                    break
                time.sleep(2)
        cert = REST_CERT
    r.run("/ip service set www-ssl certificate=%s port=%d disabled=no" % (q(cert), port))
    fp = (sv.get(r, "/certificate", "name=%s" % q(cert), "fingerprint") or "").strip()
    return port, fp


def register_on_router(r, linux_ip, name, p, log):
    """Let the Linux server read users over REST and send RADIUS to User Manager."""
    tag = "pv-linux-%s" % re.sub(r"[^A-Za-z0-9_-]", "-", name)
    port, fp = router_rest_port(r, log)
    addrs = sv.addr_list(sv.get(r, "/ip service", "name=www-ssl", "address"))
    mine = sv.with_prefix(linux_ip)
    if addrs and mine not in addrs and linux_ip not in addrs:
        r.run("/ip service set www-ssl address=%s" % ",".join(addrs + [mine]))
    if sv.count(r, "/user group", "name=pvagent") == 0:
        r.run("/user group add name=pvagent policy=read,api,rest-api,web,sensitive")
    if sv.count(r, "/user", "name=pvagent"):
        addrs = sv.addr_list(sv.get(r, "/user", "name=pvagent", "address"))
        if sv.with_prefix(linux_ip) not in addrs:
            addrs.append(sv.with_prefix(linux_ip))
        r.run("/user set [find where name=pvagent] group=pvagent password=%s address=%s"
              % (q(p["agent_password"]), ",".join(addrs)))
    else:
        r.run("/user add name=pvagent group=pvagent password=%s address=%s/32" % (q(p["agent_password"]), linux_ip))
    if sv.count(r, "/user-manager router", "address=%s" % linux_ip):
        r.run("/user-manager router remove [find where address=%s]" % linux_ip)
    r.run("/user-manager router add name=%s address=%s shared-secret=%s" % (q(tag), linux_ip, q(p["radius_secret"])))
    sv.ensure_input_accept(r, linux_ip, "udp", "1812,1813", tag + "-radius")
    sv.ensure_input_accept(r, linux_ip, "tcp", str(port), tag + "-rest")
    return port, fp


def public_address(r, host):
    """Address the Linux server uses for this router: the one the tool uses,
    unless that is a private one (reached over a tunnel or LAN)."""
    import ipaddress
    try:
        if not ipaddress.ip_address(host).is_private:
            return host
    except ValueError:
        return host                    # a domain name
    import provision as pv
    found = pv.first_public_ip(r.run("/ip address print without-paging"))
    if not found:
        raise LinuxError("آدرس %s خصوصی است و روی این روتر آدرس عمومی پیدا نشد؛ "
                         "سرور لینوکس از اینترنت به آن نمی‌رسد." % host)
    return found


# ---------------------------------------------------------------- whole server

def setup_linux(connect_linux, um_routers, name, public_ip, params=None, log=print,
                linux_ip_seen_by_router=None, router_addresses=None, install_awg_too=True):
    """Install/refresh everything. um_routers: [(connect(), host)] main first.

    Returns (params, server entry for the app config)."""
    p = new_params(params)
    seen = linux_ip_seen_by_router or public_ip
    routers_cfg, radius_servers = [], []
    for i, (connect, host) in enumerate(um_routers):
        log("ثبت سرور لینوکس روی یوزر منیجر %d (%s)…" % (i + 1, host))
        r = connect()
        try:
            if not sv.has_package(r, "user-manager"):
                import provision as pv
                log("  پکیج user-manager روی این روتر نیست؛ نصب می‌شود (روتر یک بار ری‌استارت می‌شود)…")
                r = pv.install_packages(r, connect, ["user-manager"], log)
            if r.run(":put [/user-manager get enabled]").strip() not in ("true", "yes"):
                r.run("/user-manager set enabled=yes")
            port, fp = register_on_router(r, seen, name, p, log)
            public = public_address(r, host)
        finally:
            r.close()
        reach = (router_addresses or {}).get(host, {"host": public})
        routers_cfg.append({"name": "um%d" % (i + 1), "url": "https://%s:%d" % (reach.get("host", host),
                                                                                reach.get("rest_port", port)),
                            "user": "pvagent", "password": p["agent_password"], "pin": fp})
        radius_servers.append({"host": reach.get("host", host), "secret": p["radius_secret"],
                               "auth_port": reach.get("auth_port", 1812), "acct_port": reach.get("acct_port", 1813)})

    h = connect_linux()
    try:
        info = check_os(h)
        log("سرور: %s" % " ".join(info))
        install_base(h, log)
        p["xray_version"] = install_xray(h, log)
        if not p.get("reality_private"):
            p["reality_private"], p["reality_public"] = x25519(h)
        h.run("mkdir -p %s /var/log/xray" % XRAY_CONF_DIR)
        p["hy2_pin"] = make_cert(h)
        h.write(XRAY_CONF_DIR + "/template.json", json.dumps(xray_template(p), indent=1))
        h.write(XRAY_CONF_DIR + "/config.json", json.dumps(xray_template(p), indent=1))
        h.run("/usr/local/bin/xray run -test -config %s/config.json" % XRAY_CONF_DIR)
        h.run("systemctl enable xray >/dev/null 2>&1; systemctl restart xray")
        awg = install_awg(h, p, log) if install_awg_too else False

        log("نصب pv-agent…")
        h.run("mkdir -p %s /etc/pv-agent /var/lib/pv-agent" % AGENT_DIR)
        h.write(AGENT_DIR + "/pv_agent.py", source("pv_agent.py"))
        h.write(AGENT_DIR + "/pvcreds.py", source("pvcreds.py"))
        agent_cfg = {
            "routers": routers_cfg,
            "radius": {"servers": radius_servers, "nas_ip": public_ip, "nas_identifier": "pv-" + name},
            "xray": {"template": XRAY_CONF_DIR + "/template.json", "config": XRAY_CONF_DIR + "/config.json",
                     "inbounds": {"vless-vision": "vless-vision", "vless-xhttp": "vless",
                                  "hy2": "hysteria", "ss": "shadowsocks"}},
            "interval": p.get("interval", 60),
        }
        if awg:
            agent_cfg["awg"] = {"iface": "awg0"}
        h.write("/etc/pv-agent/config.json", json.dumps(agent_cfg, indent=1), "600")
        h.write("/etc/systemd/system/pv-agent.service", """[Unit]
Description=Persian VPN agent (User Manager sync and accounting)
After=network-online.target xray.service

[Service]
ExecStart=/usr/bin/python3 %s/pv_agent.py /etc/pv-agent/config.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
""" % AGENT_DIR)
        h.run("systemctl daemon-reload && systemctl enable pv-agent >/dev/null 2>&1 && systemctl restart pv-agent")
        status = {s: h.run("systemctl is-active %s" % s, check=False).strip()
                  for s in ("xray", "pv-agent") + (("awg-quick@awg0",) if awg else ())}
        log("وضعیت سرویس‌ها: %s" % ", ".join("%s=%s" % kv for kv in status.items()))
        bad = [s for s, v in status.items() if v != "active"]
        if bad:
            logs = h.run("journalctl -u %s -n 30 --no-pager" % bad[0], check=False)
            raise LinuxError("سرویس %s اجرا نشد:\n%s" % (bad[0], logs[-1500:]))
    finally:
        h.close()
    return p, server_entry(name, public_ip, p, awg)


def server_entry(name, host, p, awg=True):
    """What the apps need to connect (no secrets of other users: the per-user
    parts come from each user's own username and password)."""
    entry = {"name": name, "host": host, "type": "linux", "protocols": [
        {"type": "vless-reality-vision", "port": p["vision_port"], "sni": p["sni"],
         "public_key": p["reality_public"], "short_id": p["short_id"]},
        {"type": "vless-xhttp-reality", "port": p["xhttp_port"], "sni": p["sni"], "path": p["xhttp_path"],
         "public_key": p["reality_public"], "short_id": p["short_id"]},
        {"type": "hysteria2", "port": p["hy2_port"], "pin_sha256": p["hy2_pin"]},
        {"type": "shadowsocks-2022", "port": p["ss_port"], "method": "2022-blake3-aes-128-gcm",
         "server_key": p["ss_server_key"]},
    ]}
    if awg and p["awg"].get("public"):
        a = p["awg"]
        entry["protocols"].append({"type": "amneziawg", "port": a["port"], "public_key": a["public"],
                                   "jc": a["jc"], "jmin": a["jmin"], "jmax": a["jmax"], "s1": a["s1"],
                                   "s2": a["s2"], "h1": a["h1"], "h2": a["h2"], "h3": a["h3"], "h4": a["h4"]})
    return entry
