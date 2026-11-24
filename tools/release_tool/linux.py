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
    # HERE first: the code folder of "get new features" when that is in use
    for d in (HERE, getattr(sys, "_MEIPASS", None), os.path.join(HERE, "..", "..", "server", "linux")):
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
    pkgs = "curl unzip python3 openssl iptables ca-certificates software-properties-common"
    have = h.run("dpkg-query -W -f='${db:Status-Status}\\n' %s 2>/dev/null | grep -c '^installed$' || true"
                 % pkgs, check=False).strip()
    if have == str(len(pkgs.split())):
        log("بسته‌های پایه از قبل نصب‌اند.")       # no apt: a broken Ubuntu mirror does not stop a re-run
    else:
        log("نصب بسته‌های پایه (چند دقیقه)…")
        h.run("export DEBIAN_FRONTEND=noninteractive; apt-get update -q && "
              "apt-get install -y -q %s" % pkgs, timeout=1800)
    h.write("/etc/sysctl.d/90-pv.conf",
            "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\nnet.ipv4.ip_forward=1\n"
            "net.core.rmem_max=16777216\nnet.core.wmem_max=16777216\n")
    h.run("sysctl --system >/dev/null")


XRAY_FETCH = r"""set -e
cd /tmp
# the API has a small hourly limit per IP; the release page redirect has none
tag=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["tag_name"])' 2>/dev/null || true)
[ -n "$tag" ] || tag=$(curl -fsS -o /dev/null -w '%%{redirect_url}' https://github.com/XTLS/Xray-core/releases/latest | sed 's#.*/tag/##')
[ -n "$tag" ] || { echo "Xray version not found"; exit 1; }
curl -fsSLo xray.zip https://github.com/XTLS/Xray-core/releases/download/$tag/Xray-linux-%(arch)s.zip
curl -fsSLo xray.zip.dgst https://github.com/XTLS/Xray-core/releases/download/$tag/Xray-linux-%(arch)s.zip.dgst
want=$(grep -i 'SHA2-256' xray.zip.dgst | head -1 | awk -F'= ' '{print $2}')
have=$(sha256sum xray.zip | awk '{print $1}')
[ "$want" = "$have" ] || { echo "checksum mismatch"; exit 3; }
rm -rf xr && mkdir xr && unzip -q xray.zip -d xr
"""


def install_xray(h, log):
    log("نصب Xray-core (آخرین نسخه)…")
    arch = "64" if "x86_64" in h.run("uname -m") else "arm64-v8a"
    script = (XRAY_FETCH + r"""install -m 755 xr/xray /usr/local/bin/xray
mkdir -p /usr/local/share/xray %(conf)s
cp xr/geoip.dat xr/geosite.dat /usr/local/share/xray/ 2>/dev/null || true
echo $tag
""") % {"arch": arch, "conf": XRAY_CONF_DIR}
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


def x25519(h, private=None):
    """(private, public) Reality keys (new ones, or the public key of `private`);
    xray changed its output format over time."""
    out = h.run("/usr/local/bin/xray x25519" + (" -i %s" % shell_quote(private) if private else ""))
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


def hy2_mask(p):
    """Salamander on Hysteria2, both ends (the app gets the password as "obfs")."""
    if not p.get("hy2_obfs"):
        return {}
    return {"finalmask": {"udp": [{"type": "salamander", "settings": {"password": p["hy2_obfs"]}}]}}


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
             "streamSettings": dict({"network": "hysteria", "hysteriaSettings": {"version": 2},
                                     "security": "tls",
                                     "tlsSettings": {"alpn": ["h3"], "certificates": [
                                         {"certificateFile": XRAY_CONF_DIR + "/hy2.crt",
                                          "keyFile": XRAY_CONF_DIR + "/hy2.key"}]}},
                                    **hy2_mask(p))},
            {"tag": "ss", "port": p["ss_port"], "protocol": "shadowsocks",
             "settings": {"method": "2022-blake3-aes-128-gcm", "password": p["ss_server_key"],
                          "clients": [], "network": "tcp,udp"}},
        ] + domain_inbounds(p),
        "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
        "routing": {"rules": [
            {"ip": ["geoip:private"], "outboundTag": "block"},
            {"protocol": ["bittorrent"], "outboundTag": "block"},
        ]},
    }


def dns_name(p):
    """Delegated zone of the DNS tunnel: d.<domain> (NS -> ns.<domain>)."""
    return "d." + p["domain"]


def domain_inbounds(p):
    """With a domain: XHTTP behind Cloudflare (nginx on port 80 hands the
    secret path to Xray) and the DNS tunnel on UDP 53. Both carry VLESS
    Encryption, since Cloudflare-to-server is plain HTTP and DNS queries
    cross public resolvers."""
    if not p.get("domain") or not p.get("vless_dec"):
        return []
    sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    return [
        {"tag": "vless-cdn", "listen": "127.0.0.1", "port": p["cdn_local_port"], "protocol": "vless",
         "settings": {"clients": [], "decryption": p["vless_dec"]},
         "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": p["cdn_path"], "mode": "auto"}},
         "sniffing": sniff},
        {"tag": "vless-dns", "port": 53, "protocol": "vless",
         "settings": {"clients": [], "decryption": p["vless_dec"]},
         "streamSettings": {"network": "mkcp", "kcpSettings": {"mtu": 900, "tti": 200},
                            "finalmask": {"udp": [{"type": "xdns", "settings": {"domains": [
                                {"names": [dns_name(p)], "edns0": 1232}]}}]}},
         "sniffing": sniff},
    ]


def vless_encryption(h):
    """(decryption, encryption) pair of VLESS Encryption (X25519 authentication)."""
    out = h.run("/usr/local/bin/xray vlessenc")
    dec = re.findall(r'"decryption":\s*"([^"]+)"', out)
    enc = re.findall(r'"encryption":\s*"([^"]+)"', out)
    if not dec or not enc:
        raise LinuxError("خروجی xray vlessenc شناخته نشد:\n" + out)
    return dec[0], enc[0]


def install_web(h, p, log):
    """nginx on port 80: the decoy shop for everyone; with a domain the secret
    path to Xray (Cloudflare, SSL mode Flexible, reaches the server here);
    the status page for the bot, only for the routers' addresses."""
    log("نصب وب‌سرور و سایت ظاهری…")
    h.run("export DEBIAN_FRONTEND=noninteractive; command -v nginx >/dev/null || "
          "apt-get install -y -q --no-install-recommends nginx", timeout=900)
    h.run("mkdir -p /var/www/pv /var/lib/pv-agent && chmod 755 /var/lib/pv-agent")
    name = p["domain"].split(".")[0].capitalize() if p.get("domain") else "Soft"
    html = source("site/index.html").decode("utf-8")
    for k, v in (("{{NAME}}", name), ("{{INITIAL}}", name[0]), ("{{DOMAIN}}", p.get("domain") or "example.com")):
        html = html.replace(k, v)
    h.write("/var/www/pv/index.html", html)
    h.write("/var/www/pv/favicon.svg",
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><defs><linearGradient id="g" x1="0" y1="0" '
            'x2="1" y2="1"><stop offset="0" stop-color="#2563eb"/><stop offset="1" stop-color="#7c3aed"/>'
            '</linearGradient></defs><rect width="64" height="64" rx="16" fill="url(#g)"/><text x="32" y="44" '
            'font-family="Arial" font-size="34" font-weight="700" fill="#fff" text-anchor="middle">%s</text></svg>'
            % name[0])
    h.write("/var/www/pv/robots.txt", "User-agent: *\nAllow: /\n")
    cdn = """
    location %(path)s {
        proxy_pass http://127.0.0.1:%(port)d;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        client_max_body_size 0;
    }
""" % {"path": p["cdn_path"], "port": p["cdn_local_port"]} if p.get("domain") else ""
    # online users for the Telegram bot on the routers (and nobody else)
    allow = "".join("        allow %s;\n" % a for a in ["127.0.0.1"] + list(p.get("status_allow") or []))
    h.write("/etc/nginx/sites-available/pv", """server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/pv;
    index index.html;
    server_tokens off;
    access_log off;
%(cdn)s
    location = /pvs/%(token)s {
%(allow)s        deny all;
        default_type application/json;
        add_header Cache-Control no-store;
        alias /var/lib/pv-agent/status.json;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
""" % {"cdn": cdn, "token": p["status_token"], "allow": allow})
    h.run("rm -f /etc/nginx/sites-enabled/default; ln -sf /etc/nginx/sites-available/pv /etc/nginx/sites-enabled/pv; "
          "nginx -t 2>&1 && systemctl enable nginx >/dev/null 2>&1; systemctl restart nginx")


def free_port_53(h):
    """systemd-resolved's stub listener holds port 53; the DNS tunnel needs it."""
    h.run(r"""if systemctl is-active -q systemd-resolved; then
  mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/pv.conf
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  systemctl restart systemd-resolved
fi""")


CLOUDFLARE_PY = r"""
import json, os, sys, urllib.request
TOKEN, DOMAIN, IP = os.environ["CF_TOKEN"], sys.argv[1], sys.argv[2]
def api(method, path, body=None):
    req = urllib.request.Request("https://api.cloudflare.com/client/v4" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return json.load(e)
out = {"warnings": []}
z = api("GET", "/zones?name=" + DOMAIN)
if not z.get("success") or not z.get("result"):
    print(json.dumps({"error": "zone", "detail": z.get("errors")})); sys.exit(0)
zone = z["result"][0]
out["status"] = zone.get("status")
zid = zone["id"]
want = [("A", DOMAIN, IP, True), ("A", "www." + DOMAIN, IP, True), ("A", "ns." + DOMAIN, IP, False),
        ("NS", "d." + DOMAIN, "ns." + DOMAIN, False)]
for typ, name, content, proxied in want:
    have = api("GET", "/zones/%s/dns_records?name=%s" % (zid, name)).get("result") or []
    body = {"type": typ, "name": name, "content": content, "ttl": 1 if proxied else 300}
    if typ == "A":
        body["proxied"] = proxied
    same = [r for r in have if r["type"] == typ]
    for r in have:
        if r["type"] in ("A", "AAAA", "CNAME", "NS") and r not in same[:1]:
            api("DELETE", "/zones/%s/dns_records/%s" % (zid, r["id"]))
    res = api("PUT", "/zones/%s/dns_records/%s" % (zid, same[0]["id"]), body) if same else         api("POST", "/zones/%s/dns_records" % zid, body)
    if not res.get("success"):
        print(json.dumps({"error": "record", "name": name, "detail": res.get("errors")})); sys.exit(0)
api("PATCH", "/zones/%s/settings/ssl_automatic_mode" % zid, {"value": "custom"})
r = api("PATCH", "/zones/%s/settings/ssl" % zid, {"value": "flexible"})
if not r.get("success"):
    out["warnings"].append("ssl")
r = api("PATCH", "/zones/%s/settings/ech" % zid, {"value": "on"})
print(json.dumps(out))
"""


def cloudflare_setup(h, p, ip, log):
    """DNS records and SSL mode of the domain, through Cloudflare's API.
    Runs on the server (outside Iran), so the tool's own internet does not matter."""
    if not p.get("cf_token"):
        log("⚠ توکن Cloudflare وارد نشده؛ این رکوردها را خودتان در Cloudflare بسازید:\n"
            "    A  %(d)s → %(ip)s (Proxied، ابر نارنجی)\n    A  www.%(d)s → %(ip)s (Proxied)\n"
            "    A  ns.%(d)s → %(ip)s (DNS only، ابر خاکستری)\n    NS d.%(d)s → ns.%(d)s\n"
            "    و در SSL/TLS حالت را روی Flexible بگذارید." % {"d": p["domain"], "ip": ip})
        return
    log("تنظیم دامنه در Cloudflare…")
    h.write("/tmp/pv-cf.py", CLOUDFLARE_PY)
    out = h.run("CF_TOKEN=%s python3 /tmp/pv-cf.py %s %s; rm -f /tmp/pv-cf.py"
                % (shell_quote(p["cf_token"]), shell_quote(p["domain"]), shell_quote(ip)), check=False)
    try:
        res = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise LinuxError("جواب Cloudflare شناخته نشد:\n" + out[-800:])
    if res.get("error") == "zone":
        raise LinuxError("دامنه‌ی %s در حساب Cloudflare پیدا نشد یا توکن اجازه ندارد.\n%s"
                         % (p["domain"], res.get("detail")))
    if res.get("error"):
        raise LinuxError("Cloudflare رکورد %s را نساخت (توکن باید اجازه‌ی DNS Edit داشته باشد):\n%s"
                         % (res.get("name"), res.get("detail")))
    if "ssl" in res.get("warnings", []):
        log("⚠ حالت SSL عوض نشد (توکن اجازه‌ی Zone Settings ندارد). در Cloudflare، بخش SSL/TLS، "
            "حالت را دستی روی Flexible بگذارید؛ وگرنه مسیر CDN کار نمی‌کند.")
    if res.get("status") != "active":
        log("⚠ دامنه در Cloudflare هنوز فعال نشده (%s). رکوردها ساخته شد؛ بعد از فعال شدن، مسیر CDN و "
            "تونل DNS خودشان کار می‌کنند." % res.get("status"))
    else:
        log("  رکوردهای دامنه و حالت SSL تنظیم شد.")


def domain_lookup(h, domain):
    """ECH config and Cloudflare addresses of the domain (empty until it is active)."""
    script = r"""
import json, sys, urllib.request
def q(t):
    req = urllib.request.Request("https://cloudflare-dns.com/dns-query?name=%s&type=%s" % (sys.argv[1], t),
                                 headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return [a["data"] for a in json.load(r).get("Answer", []) if a.get("type") in (1, 65)]
out = {"ips": [], "ech": ""}
try:
    out["ips"] = q("A")
    for rec in q("HTTPS"):
        for part in rec.split():
            if part.startswith("ech="):
                out["ech"] = part[4:].strip('"')
except Exception:
    pass
print(json.dumps(out))
"""
    h.write("/tmp/pv-dns.py", script)
    out = h.run("python3 /tmp/pv-dns.py %s; rm -f /tmp/pv-dns.py" % shell_quote(domain), check=False)
    try:
        return json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"ips": [], "ech": ""}


def shell_quote(s):
    return "'" + str(s).replace("'", "'\\''") + "'"


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
    present = h.run("command -v awg >/dev/null && command -v awg-quick >/dev/null && "
                    "(lsmod | grep -q '^amneziawg' || command -v amneziawg-go >/dev/null) && echo YES || true",
                    check=False).strip()
    if present == "YES":
        log("  AmneziaWG از قبل نصب است.")
        return configure_awg(h, p, log)
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
    return configure_awg(h, p, log)


def configure_awg(h, p, log):
    h.run("mkdir -p /etc/amnezia/amneziawg")
    h.write("/etc/amnezia/amneziawg/awg0.conf", awg_conf(h, p), "600")
    h.run("systemctl enable awg-quick@awg0 >/dev/null 2>&1; systemctl restart awg-quick@awg0")
    p["awg"]["public"] = h.run("echo %s | awg pubkey" % p["awg"]["priv"]).strip()
    return True


def ensure_awg_hop(h, p, log=print):
    """The hop ports on a running server, without restarting AmneziaWG (its
    users stay connected): the rule now, and in awg0.conf for later starts."""
    if not p.get("awg", {}).get("public") or not p["awg"].get("hop"):
        return False
    if not h.run("test -f /etc/amnezia/amneziawg/awg0.conf && echo Y || true").strip():
        return False
    h.write("/etc/amnezia/amneziawg/awg0.conf", awg_conf(h, p), "600")
    h.run("%s 2>/dev/null || %s" % (awg_hop_rule(p, "-C"), awg_hop_rule(p, "-A")))
    log("✓ پورت‌های جایگزین AmneziaWG: %d تا %d" % tuple(p["awg"]["hop"]))
    return True


def awg_conf(h, p):
    wan = h.run("ip route show default | awk '{print $5; exit}'").strip() or "eth0"
    hop_up = "; " + awg_hop_rule(p, "-A") if p["awg"].get("hop") else ""
    hop_down = "; " + awg_hop_rule(p, "-D") if p["awg"].get("hop") else ""
    return """[Interface]
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
PostUp = iptables -t nat -A POSTROUTING -s 10.64.0.0/10 -o %(wan)s -j MASQUERADE; iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -j ACCEPT%(hop_up)s
PostDown = iptables -t nat -D POSTROUTING -s 10.64.0.0/10 -o %(wan)s -j MASQUERADE; iptables -D FORWARD -i %%i -j ACCEPT; iptables -D FORWARD -o %%i -j ACCEPT%(hop_down)s
""" % dict(p["awg"], wan=wan, hop_up=hop_up, hop_down=hop_down)


def update_agent(h, log=print):
    """Only the pv-agent code (users, settings and Xray stay as they are)."""
    if not h.run("test -f /etc/pv-agent/config.json && echo Y || true").strip():
        raise LinuxError("pv-agent روی این سرور نصب نیست؛ اول سرور را از تب «سرور جدید» نصب کنید.")
    log("نوشتن کد جدید pv-agent…")
    h.write(AGENT_DIR + "/pv_agent.py", source("pv_agent.py"))
    h.write(AGENT_DIR + "/pvcreds.py", source("pvcreds.py"))
    h.run("systemctl restart pv-agent")
    if h.run("test -f /etc/systemd/system/pv-icmp.service && echo Y || true").strip():
        h.write(AGENT_DIR + "/pv_icmp.py", source("pv_icmp.py"))
        h.run("systemctl restart pv-icmp")
    for _ in range(10):
        state = h.run("systemctl is-active pv-agent || true").strip()
        if state == "active":
            break
        time.sleep(1)
    if state != "active":
        raise LinuxError("pv-agent بعد از به‌روزرسانی اجرا نشد (%s):\n%s" % (
            state, h.run("journalctl -u pv-agent -n 15 --no-pager || true")))
    log("pv-agent به‌روز شد ✓")


def user_check(h, p, username, client_ip="", seconds=25, log=print):
    """Why one user cannot connect, seen from the server (lines of text):
    their AmneziaWG peer (present, last handshake, the address it came from,
    bytes), whether pv-agent lets them in, and - while they press connect on
    the phone - whether their packets reach the server at all (tcpdump on the
    AmneziaWG and Hysteria2 ports, from the phone's own IP when given: the
    test screen shows it in ①). Packets that never arrive mean the network
    drops them; packets that arrive without a handshake mean a mismatch."""
    import ipaddress
    out = []
    user = username.strip().lower()
    # as pvcreds.awg_address (that file is not a module in the packaged tool)
    net = ipaddress.ip_network("10.64.0.0/10")
    h_ = int.from_bytes(hashlib.sha256(b"pv-awg-ip\n" + user.encode()).digest()[:4], "big")
    addr = str(net.network_address + 2 + h_ % (net.num_addresses - 3))
    awg = p.get("awg") or {}
    port = int(awg.get("port") or 0)
    out.append("کاربر %s — آدرس AmneziaWG او: %s" % (user, addr))
    dump = h.run("awg show awg0 dump 2>/dev/null || true")
    lines = [l.split("\t") for l in dump.splitlines()[1:]]
    peer = next((l for l in lines if len(l) >= 8 and addr + "/32" in l[3].split(",")), None)
    if peer is None:
        out.append("✗ روی سرور peer این کاربر نیست (pv-agent او را اضافه نکرده: یوزر منیجر ردش کرده یا "
                   "در لیست کاربران نیست)")
    else:
        hs = int(peer[4] or 0)
        out.append("✓ peer هست — آخرین handshake: %s، از %s، دریافت %s، ارسال %s" % (
            "%d ثانیه پیش" % (time.time() - hs) if hs else "هرگز",
            peer[2] if peer[2] != "(none)" else "—", peer[5], peer[6]))
    out.append("  کل peerهای AmneziaWG: %d، با handshake در ۳ دقیقه‌ی اخیر: %d" % (
        len(lines), sum(1 for l in lines if len(l) >= 5 and l[4].isdigit() and int(l[4])
                        and time.time() - int(l[4]) < 180)))
    st = h.run("cat /var/lib/pv-agent/state.json 2>/dev/null || echo {}")
    try:
        state = json.loads(st or "{}")
    except ValueError:
        state = {}
    if user in (state.get("blocked") or {}):
        out.append("✗ pv-agent این کاربر را موقتاً کنار گذاشته (یوزر منیجر اتصالش را رد کرد)")
    seen = [k.split("|", 1)[1] for k in (state.get("seen") or {}) if k.split("|", 1)[0] == user]
    out.append("  دیده‌شده در ۳ دقیقه‌ی اخیر روی: %s" % ("، ".join(seen) or "هیچ پروتکلی"))
    ports = [x for x in (port, int(p.get("hy2_port") or 0)) if x]
    if ports and seconds:
        if not h.run("command -v tcpdump || true").strip():
            log("نصب tcpdump…")
            h.run("DEBIAN_FRONTEND=noninteractive apt-get install -y -q tcpdump >/dev/null 2>&1 || true",
                  timeout=300, check=False)
        hop = (p.get("awg") or {}).get("hop")
        flt = "udp and (%s)" % " or ".join(["port %d" % x for x in ports] +
                                          (["portrange %d-%d" % tuple(hop)] if hop else []))
        if client_ip.strip():
            flt += " and host %s" % client_ip.strip()
        log("گوش دادن %d ثانیه: حالا روی گوشی VPN را قطع و وصل کنید…" % seconds)
        cap = h.run("timeout %d tcpdump -n -l -i any -c 400 '%s' 2>/dev/null || true" % (seconds, flt),
                    timeout=seconds + 30, check=False)
        pk = [l for l in cap.splitlines() if " IP " in l or " IP6 " in l]
        by = {}
        for l in pk:
            src = l.split(" IP ")[-1].split(" > ")[0] if " IP " in l else "?"
            by[src.rsplit(".", 1)[0]] = by.get(src.rsplit(".", 1)[0], 0) + 1
        if not pk:
            out.append("✗ در %d ثانیه هیچ بسته‌ی UDP %sبه پورت‌های %s نرسید: شبکه‌ی گوشی آن را می‌اندازد"
                       % (seconds, ("از %s " % client_ip.strip()) if client_ip.strip() else "",
                          "، ".join(map(str, ports))))
        else:
            out.append("✓ %d بسته‌ی UDP رسید/رفت (پورت‌های %s): %s" % (
                len(pk), "، ".join(map(str, ports)),
                "، ".join("%s ×%d" % kv for kv in sorted(by.items(), key=lambda x: -x[1])[:6])))
            out += ["    " + l[:160] for l in pk[:8]]
    return out


def refresh_xray_config(h, p, log=print):
    """A running server gets this tool's current Xray settings (new options,
    e.g. Salamander on Hysteria2), keeping its keys, ports and users. The new
    template must pass Xray's own test before it replaces the old one;
    pv-agent then restarts Xray with the users (a few seconds' cut for the
    Xray protocols). Returns the updated params (to save and publish)."""
    p = new_params(p)
    adopt_server_secrets(h, p, log)
    if not p.get("hy2_pin") or not p.get("reality_public"):
        raise LinuxError("تنظیمات این سرور در ابزار کامل نیست؛ یک بار از «سرور جدید» نصبش کنید.")
    try:
        ensure_awg_hop(h, p, log)
    except LinuxError as e:
        log("⚠ پورت‌های جایگزین AmneziaWG اضافه نشد: %s" % str(e)[-300:])
        p["awg"].pop("hop", None)
    log("تنظیمات جدید Xray…")
    new = XRAY_CONF_DIR + "/template.new.json"   # Xray reads the format from the extension
    h.write(new, json.dumps(xray_template(p), indent=1))
    test = h.run("/usr/local/bin/xray run -test -config %s 2>&1" % new, check=False)
    if "Configuration OK" not in test:
        h.run("rm -f %s" % new, check=False)
        raise LinuxError("Xray تنظیمات جدید را قبول نکرد؛ چیزی عوض نشد:\n%s" % test[-600:])
    h.run("mv %s %s/template.json && systemctl restart pv-agent" % (new, XRAY_CONF_DIR))
    for _ in range(20):
        time.sleep(2)
        if all(h.run("systemctl is-active %s || true" % svc).strip() == "active" for svc in ("xray", "pv-agent")):
            log("✓ Xray با تنظیمات جدید اجرا شد")
            return p
    raise LinuxError("Xray بعد از تنظیمات جدید اجرا نشد:\n%s"
                     % h.run("journalctl -u xray -n 20 --no-pager || true")[-1200:])


def refreshed_entry(old_entry, p):
    """The app-config entry of a server after refresh_xray_config."""
    awg = any(x.get("type") == "amneziawg" for x in old_entry.get("protocols", []))
    return server_entry(old_entry["name"], old_entry["host"], p, awg)


def update_xray(h, log=print):
    """Xray's latest release on a running server: the new binary must accept
    the current config before it replaces the old one, and the old one comes
    back if the service does not start. Users of the Xray protocols are cut
    for the few seconds of the restart; the app reconnects by itself.
    Returns (old version, new version)."""
    if not h.run("test -x /usr/local/bin/xray && echo Y || true").strip():
        raise LinuxError("Xray روی این سرور نصب نیست.")
    arch = "64" if "x86_64" in h.run("uname -m") else "arm64-v8a"
    old = h.run("/usr/local/bin/xray version 2>/dev/null | head -1 | awk '{print $2}'").strip()
    log("نسخه‌ی فعلی Xray: %s — دریافت آخرین نسخه…" % (old or "?"))
    script = (XRAY_FETCH + r"""
echo "NEW $tag"
[ "v%(old)s" = "$tag" ] && { echo SAME; exit 0; }
XRAY_LOCATION_ASSET=/tmp/xr /tmp/xr/xray run -test -config %(conf)s/config.json >/tmp/xray-test.log 2>&1 \
  || { echo "REJECTED"; tail -5 /tmp/xray-test.log; exit 4; }
cp -p /usr/local/bin/xray /usr/local/bin/xray.old
install -m 755 xr/xray /usr/local/bin/xray
for f in geoip.dat geosite.dat; do [ -f xr/$f ] && cp xr/$f /usr/local/share/xray/; done
systemctl restart xray
sleep 3
if ! systemctl is-active --quiet xray; then
  install -m 755 /usr/local/bin/xray.old /usr/local/bin/xray
  systemctl restart xray
  echo "ROLLED BACK"; exit 5
fi
echo DONE
""") % {"arch": arch, "conf": XRAY_CONF_DIR, "old": old}
    out = h.run(script, timeout=600, check=False)
    new = next((l.split()[1] for l in out.splitlines() if l.startswith("NEW ") and len(l.split()) > 1), "")
    if "SAME" in out.splitlines():
        log("Xray به‌روز است (%s)" % new)
        return old, old
    if "REJECTED" in out:
        raise LinuxError("Xray %s تنظیمات فعلی سرور را قبول نکرد؛ نسخه‌ی قبلی (%s) دست نخورد:\n%s"
                         % (new, old, out[-600:]))
    if "ROLLED BACK" in out:
        raise LinuxError("Xray %s اجرا نشد؛ نسخه‌ی قبلی (%s) برگردانده شد." % (new, old))
    if "DONE" not in out.splitlines():
        raise LinuxError("به‌روزرسانی Xray ناموفق بود:\n%s" % out[-600:])
    log("Xray از %s به %s رسید ✓" % (old, new.lstrip("v")))
    return old, new.lstrip("v")


def ensure_icmp(h, p, log=print):
    """pv-icmp: the ICMP carrier of the router's backup tunnel (for routes
    where Iran cuts UDP but ping passes). The key is kept in the params so a
    re-install keeps it. The kernel's own ping replies are off while it runs;
    it answers ordinary pings itself."""
    awg = p["awg"]
    if not awg.get("icmp_key"):
        awg["icmp_key"] = secrets.token_hex(16)
    log("ICMP پشتیبان روی سرور لینوکس…")
    h.run("mkdir -p %s /etc/pv-agent" % AGENT_DIR)
    h.write(AGENT_DIR + "/pv_icmp.py", source("pv_icmp.py"))
    h.write("/etc/pv-agent/icmp.json", json.dumps({"key": awg["icmp_key"], "awg_port": int(awg["port"])}), "600")
    h.write("/etc/systemd/system/pv-icmp.service", """[Unit]
Description=Persian VPN backup tunnel over ICMP
After=network-online.target

[Service]
ExecStartPre=/usr/sbin/sysctl -q -w net.ipv4.icmp_echo_ignore_all=1
ExecStart=/usr/bin/python3 %s/pv_icmp.py /etc/pv-agent/icmp.json
ExecStopPost=/usr/sbin/sysctl -q -w net.ipv4.icmp_echo_ignore_all=0
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
""" % AGENT_DIR)
    h.run("systemctl daemon-reload && systemctl enable pv-icmp >/dev/null 2>&1; systemctl restart pv-icmp")
    return p


def icmp_status(h):
    return h.run("systemctl is-active pv-icmp 2>/dev/null || true").strip() or "none"


def remove_icmp(h):
    h.run("systemctl disable --now pv-icmp >/dev/null 2>&1; rm -f /etc/systemd/system/pv-icmp.service; "
          "systemctl daemon-reload; sysctl -q -w net.ipv4.icmp_echo_ignore_all=0 || true", check=False)


def add_static_peer(h, p, public, address, log=print):
    """A non-user AmneziaWG peer (the main router's backup tunnel) that
    pv-agent keeps; saved in the params too, so a re-install keeps it."""
    if not h.run("test -f /etc/amnezia/amneziawg/awg0.conf && echo Y || true").strip():
        raise LinuxError("AmneziaWG روی این سرور نصب نیست؛ اول سرور را از تب «سرور جدید» نصب کنید.")
    static = p["awg"].setdefault("static", {})
    for k in [k for k, v in static.items() if v == address and k != public]:
        del static[k]                       # an earlier key of the same router
    static[public] = address
    cfg = json.loads(h.run("cat /etc/pv-agent/config.json"))
    cfg.setdefault("awg", {"iface": "awg0"})["static"] = dict(static)
    log("ثبت روتر روی AmneziaWG سرور لینوکس…")
    h.write(AGENT_DIR + "/pv_agent.py", source("pv_agent.py"))
    h.write(AGENT_DIR + "/pvcreds.py", source("pvcreds.py"))
    h.write("/etc/pv-agent/config.json", json.dumps(cfg, indent=1), "600")
    h.run("awg set awg0 peer %s allowed-ips %s/32" % (shell_quote(public), address))
    h.run("systemctl restart pv-agent")
    if not p["awg"].get("public"):
        p["awg"]["public"] = h.run("echo %s | awg pubkey" % p["awg"]["priv"]).strip()
    return p


def static_peer_status(h, public):
    """(seconds since the last handshake or None, received, sent) of one peer."""
    hs = h.run("awg show awg0 latest-handshakes", check=False)
    tr = h.run("awg show awg0 transfer", check=False)
    age, rx, tx = None, 0, 0
    for line in hs.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == public and parts[1].isdigit() and int(parts[1]):
            age = max(0, int(time.time()) - int(parts[1]))
    for line in tr.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == public:
            rx, tx = int(parts[1]), int(parts[2])
    return age, rx, tx


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


AWG_KEYS = {"PrivateKey": "priv", "ListenPort": "port", "Jc": "jc", "Jmin": "jmin", "Jmax": "jmax",
            "S1": "s1", "S2": "s2", "H1": "h1", "H2": "h2", "H3": "h3", "H4": "h4"}


def server_secrets(h):
    """The keys a running server already uses (its users' apps depend on
    them): {} on a new server."""
    out = {}
    t = h.run("grep -oE 'location = /pvs/[^ ]+' /etc/nginx/sites-available/pv 2>/dev/null || true", check=False)
    m = re.search(r"/pvs/([^\s{;]+)", t)
    if m:
        out["status_token"] = m.group(1)
    tpl = h.run("cat %s/template.json 2>/dev/null || true" % XRAY_CONF_DIR, check=False)
    try:
        for ib in json.loads(tpl).get("inbounds", []):
            rs = (ib.get("streamSettings") or {}).get("realitySettings")
            if rs and rs.get("privateKey"):
                out["reality_private"] = rs["privateKey"]
                if rs.get("shortIds"):
                    out["short_id"] = rs["shortIds"][0]
                break
    except ValueError:
        pass
    conf = h.run("cat /etc/amnezia/amneziawg/awg0.conf 2>/dev/null || true", check=False)
    awg = {}
    for line in conf.split("[Peer]")[0].splitlines():
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if k in AWG_KEYS and v:
            awg[AWG_KEYS[k]] = v if k == "PrivateKey" else int(v)
    if awg.get("priv"):
        out["awg"] = awg
    return out


def adopt_server_secrets(h, p, log=print):
    """When the tool's copy of a server's keys differs from what the server
    really uses (settings from another device, an old copy ...), the
    server's keys win: writing the tool's would cut every user's app and
    the bot's online list. Returns the names of what was taken."""
    srv = server_secrets(h)
    taken = []
    for k in ("status_token", "short_id"):
        if srv.get(k) and p.get(k) != srv[k]:
            p[k] = srv[k]
            taken.append(k)
    if srv.get("reality_private") and p.get("reality_private") != srv["reality_private"]:
        p["reality_private"] = srv["reality_private"]
        p["reality_public"] = x25519(h, srv["reality_private"])[1]
        taken.append("reality")
    if srv.get("awg"):
        a = p.setdefault("awg", {})
        diff = {k: v for k, v in srv["awg"].items() if a.get(k) != v}
        if diff:
            a.update(diff)
            pub = h.run("command -v awg >/dev/null && echo %s | awg pubkey || true" % shell_quote(a["priv"]),
                        check=False).strip()
            if pub:
                a["public"] = pub
            taken.append("amneziawg")
    if taken:
        log("⚠ کلیدهای ابزار با خود سرور یکی نبود (%s)؛ کلیدهای فعلی سرور نگه داشته شد تا اتصال کاربران و "
            "لیست آنلاین بات قطع نشود." % "، ".join(taken))
    return taken


def new_params(old=None):
    """Ports, keys and secrets of a server; kept across re-installs."""
    p = dict(old or {})
    p.setdefault("sni", secrets.choice(REALITY_TARGETS))
    p.setdefault("short_id", secrets.token_hex(4))
    p.setdefault("vision_port", 443)
    p.setdefault("xhttp_port", 8443)
    p.setdefault("xhttp_path", "/" + secrets.token_urlsafe(8))
    p.setdefault("hy2_port", 443)
    # Salamander: Hysteria2's QUIC made to look like random UDP (Iran drops QUIC)
    p.setdefault("hy2_obfs", secrets.token_urlsafe(16))
    p.setdefault("ss_port", 20000 + secrets.randbelow(40000))
    p.setdefault("ss_server_key", base64.b64encode(secrets.token_bytes(16)).decode())
    p.setdefault("awg", awg_params())
    p.setdefault("cdn_path", "/" + secrets.token_urlsafe(10))
    p.setdefault("status_token", secrets.token_urlsafe(18))
    p.setdefault("cdn_local_port", 10086)
    p.setdefault("radius_secret", secrets.token_urlsafe(24))
    p.setdefault("agent_password", secrets.token_urlsafe(24))
    p["awg"].setdefault("hop", awg_hop_range(p))
    return p


AWG_HOP_N = 32


def awg_hop_range(p):
    """[first, last] of AWG_HOP_N UDP ports redirected to AmneziaWG's port:
    when a network cuts one AmneziaWG flow (the rekey after 2 minutes gets
    no answer) the app moves to another port. Clear of the server's other ports."""
    used = {int(p.get(k) or 0) for k in ("vision_port", "xhttp_port", "hy2_port", "ss_port", "cdn_local_port")}
    used |= {int((p.get("awg") or {}).get("port") or 0), 53, 80, 443, 1812, 1813}
    while True:
        first = 20000 + secrets.randbelow(40000 - AWG_HOP_N)
        if not any(first <= u < first + AWG_HOP_N for u in used):
            return [first, first + AWG_HOP_N - 1]


def awg_hop_rule(p, op):
    """iptables rule (op -A, -D or -C) sending the hop ports to AmneziaWG."""
    a = p["awg"]
    hop = a.get("hop")
    if not hop:
        return ""
    return ("iptables -t nat %s PREROUTING -p udp -m addrtype --dst-type LOCAL --dport %d:%d "
            "-j REDIRECT --to-ports %d" % (op, hop[0], hop[1], a["port"]))


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

def register_um(um_routers, name, seen, p, log=print, router_addresses=None, what="سرور لینوکس"):
    """The server as a RADIUS client and REST reader on each User Manager
    router. Returns pv-agent's routers and radius lists and the routers'
    addresses (who may read the status page)."""
    routers_cfg, radius_servers = [], []
    allow = set()            # who may read the status page (the bot runs on the routers)
    for i, (connect, host) in enumerate(um_routers):
        log("ثبت %s روی یوزر منیجر %d (%s)…" % (what, i + 1, host))
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
            allow.update(a for a in (public, host) if re.fullmatch(r"[\d.]+", a or ""))
        finally:
            r.close()
        reach = (router_addresses or {}).get(host, {"host": public})
        routers_cfg.append({"name": "um%d" % (i + 1), "url": "https://%s:%d" % (reach.get("host", host),
                                                                                reach.get("rest_port", port)),
                            "user": "pvagent", "password": p["agent_password"], "pin": fp})
        radius_servers.append({"host": reach.get("host", host), "secret": p["radius_secret"],
                               "auth_port": reach.get("auth_port", 1812), "acct_port": reach.get("acct_port", 1813)})

    return routers_cfg, radius_servers, allow


def setup_linux(connect_linux, um_routers, name, public_ip, params=None, log=print,
                linux_ip_seen_by_router=None, router_addresses=None, install_awg_too=True):
    """Install/refresh everything. um_routers: [(connect(), host)] main first.

    Returns (params, server entry for the app config)."""
    p = new_params(params)
    seen = linux_ip_seen_by_router or public_ip
    routers_cfg, radius_servers, allow = register_um(um_routers, name, seen, p, log, router_addresses)

    h = connect_linux()
    try:
        info = check_os(h)
        log("سرور: %s" % " ".join(info))
        adopt_server_secrets(h, p, log)
        install_base(h, log)
        p["xray_version"] = install_xray(h, log)
        if not p.get("reality_private"):
            p["reality_private"], p["reality_public"] = x25519(h)
        h.run("mkdir -p %s /var/log/xray" % XRAY_CONF_DIR)
        p["hy2_pin"] = make_cert(h)
        p["status_allow"] = sorted(allow)
        if p.get("domain"):
            if not p.get("vless_dec"):
                p["vless_dec"], p["vless_enc"] = vless_encryption(h)
            free_port_53(h)
        install_web(h, p, log)
        if p.get("domain"):
            cloudflare_setup(h, p, public_ip, log)
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
                     "inbounds": dict({"vless-vision": "vless-vision", "vless-xhttp": "vless",
                                       "hy2": "hysteria", "ss": "shadowsocks"},
                                      **({"vless-cdn": "vless", "vless-dns": "vless"} if p.get("domain") else {}))},
            "interval": p.get("interval", 60),
        }
        if awg:
            agent_cfg["awg"] = {"iface": "awg0", "static": dict(p["awg"].get("static") or {})}
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
        if p.get("domain"):
            p["domain_info"] = domain_lookup(h, p["domain"])
        names = ("xray", "pv-agent", "nginx") + (("awg-quick@awg0",) if awg else ())
        # pv-agent restarts Xray with the users as it starts: give it a moment
        for _ in range(15):
            status = {s: h.run("systemctl is-active %s" % s, check=False).strip() for s in names}
            if all(v == "active" for v in status.values()):
                break
            time.sleep(2)
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
        dict({"type": "hysteria2", "port": p["hy2_port"], "pin_sha256": p["hy2_pin"]},
             **({"obfs": p["hy2_obfs"]} if p.get("hy2_obfs") else {})),
        {"type": "shadowsocks-2022", "port": p["ss_port"], "method": "2022-blake3-aes-128-gcm",
         "server_key": p["ss_server_key"]},
    ]}
    if p.get("domain") and p.get("vless_enc"):
        info = p.get("domain_info") or {}
        entry["protocols"] += [
            {"type": "vless-xhttp-cdn", "host": p["domain"], "port": 443, "path": p["cdn_path"],
             "encryption": p["vless_enc"], "ips": info.get("ips", [])[:4], "ech_config": info.get("ech", ""),
             "ech_dns": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query",
                         "udp://8.8.8.8", "udp://1.1.1.1"]},
            {"type": "vless-dns", "domain": dns_name(p), "encryption": p["vless_enc"],
             "resolvers": ["udp://8.8.8.8:53", "udp://1.1.1.1:53", "udp://9.9.9.9:53"]},
        ]
    if awg and p["awg"].get("public"):
        a = p["awg"]
        entry["protocols"].append({"type": "amneziawg", "port": a["port"], "public_key": a["public"],
                                   "jc": a["jc"], "jmin": a["jmin"], "jmax": a["jmax"], "s1": a["s1"],
                                   "s2": a["s2"], "h1": a["h1"], "h2": a["h2"], "h3": a["h3"], "h4": a["h4"]})
        if a.get("hop"):
            entry["protocols"][-1]["hop"] = list(a["hop"])
    return entry


def status_url(router):
    """The bot's view of a Linux server's online users (settings router entry)."""
    import settings as st
    box = bool(router.get("xray_box"))          # Xray in a container on a MikroTik (mtxray.py)
    blob = router.get("xray_params") if box else router.get("params")
    p = st.decrypt_blob(blob) if blob else {}
    tok = (p or {}).get("status_token")
    if not tok:
        return None
    port = (p or {}).get("status_port") if box else None
    return "http://%s%s/pvs/%s" % (router["host"], ":%d" % port if port else "", tok)


def bot_linux_status(routers):
    """LINUX_STATUS for the bot's settings."""
    out = []
    for r in routers:
        if r.get("role") == "linux" or r.get("xray_box"):
            u = status_url(r)
            if u:
                out.append("%s|%s" % (r.get("name") or r["host"], u))
    return ";".join(out)
