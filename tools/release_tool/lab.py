"""«پروتکل‌های آزمایشی»: a second Xray on a Linux server with every protocol
and transport worth trying from Iran, beside the production ones, for the
Android test app (ir.persianvpn.tester).

It runs as its own service (xray-lab, its own config and ports), with one
fixed test account (not User Manager): installing, changing or removing it
never touches the production Xray, pv-agent or the users.

Each protocol is a pair: the server inbound and the matching client
outbound. Every inbound is checked with `xray run -test` on its own, so an
Xray version without some transport simply leaves that one out. The export
for the test app lists the outbounds with the server's production entry
(the app also tests those, each way, with a real account).
"""

import json
import secrets
import uuid

import linux

LAB_DIR = "/usr/local/etc/xray-lab"
LAB_PORTS = 24


def lab_params(p):
    """Test account and ports, kept in the server's params."""
    p.setdefault("lab_uuid", str(uuid.uuid4()))
    p.setdefault("lab_pass", secrets.token_urlsafe(18))
    p.setdefault("lab_ss_key", __import__("base64").b64encode(secrets.token_bytes(16)).decode())
    p.setdefault("lab_ss_old", secrets.token_urlsafe(12))
    p.setdefault("lab_path", "/" + secrets.token_hex(6))
    return p


def _reality_server(p):
    return {"show": False, "target": linux.reality_target(p), "serverNames": [linux.reality_sni(p)],
            "privateKey": p["reality_private"], "shortIds": [p["short_id"]]}


def _reality_client(p):
    return {"serverName": linux.reality_sni(p), "publicKey": p["reality_public"], "shortId": p["short_id"],
            "fingerprint": "chrome"}


def _tls_server(alpn):
    return {"alpn": alpn, "certificates": [{"certificateFile": linux.XRAY_CONF_DIR + "/hy2.crt",
                                            "keyFile": linux.XRAY_CONF_DIR + "/hy2.key"}]}


def _tls_client(p, alpn):
    return {"serverName": "pv", "alpn": alpn, "fingerprint": "chrome", "pinnedPeerCertSha256": p["hy2_pin"]}


def lab_defs(p, host):
    """[(id, label, inbound, outbound)] in the order the app shows them."""
    base = p["lab_port0"]
    uid, path = p["lab_uuid"], p["lab_path"]
    out = []

    def vless(i, key, label, stream, flow=None, udp=False):
        port = base + i
        user = {"id": uid}
        if flow:
            user["flow"] = flow
        inbound = {"tag": key, "port": port, "protocol": "vless",
                   "settings": {"clients": [user], "decryption": "none"}, "streamSettings": stream[0]}
        cu = {"id": uid, "encryption": "none"}
        if flow:
            cu["flow"] = flow
        outbound = {"tag": "proxy", "protocol": "vless",
                    "settings": {"vnext": [{"address": host, "port": port, "users": [cu]}]},
                    "streamSettings": stream[1]}
        out.append((key, label, inbound, outbound))

    rs, rc = _reality_server(p), _reality_client(p)
    vless(0, "lab-vless-vision-reality", "VLESS Vision + Reality (TCP)",
          ({"network": "raw", "security": "reality", "realitySettings": rs},
           {"network": "raw", "security": "reality", "realitySettings": rc}), flow="xtls-rprx-vision")
    for i, mode in ((1, "packet-up"), (2, "stream-up"), (3, "stream-one")):
        vless(i, "lab-xhttp-reality-" + mode, "VLESS XHTTP %s + Reality" % mode,
              ({"network": "xhttp", "xhttpSettings": {"path": path, "mode": "auto"},
                "security": "reality", "realitySettings": rs},
               {"network": "xhttp", "xhttpSettings": {"path": path, "mode": mode},
                "security": "reality", "realitySettings": rc}))
    vless(4, "lab-grpc-reality", "VLESS gRPC + Reality",
          ({"network": "grpc", "grpcSettings": {"serviceName": path.strip("/")},
            "security": "reality", "realitySettings": rs},
           {"network": "grpc", "grpcSettings": {"serviceName": path.strip("/")},
            "security": "reality", "realitySettings": rc}))
    # Trojan over Reality
    port = base + 5
    out.append(("lab-trojan-reality", "Trojan + Reality (TCP)",
                {"tag": "lab-trojan-reality", "port": port, "protocol": "trojan",
                 "settings": {"clients": [{"password": p["lab_pass"]}]},
                 "streamSettings": {"network": "raw", "security": "reality", "realitySettings": rs}},
                {"tag": "proxy", "protocol": "trojan",
                 "settings": {"servers": [{"address": host, "port": port, "password": p["lab_pass"]}]},
                 "streamSettings": {"network": "raw", "security": "reality", "realitySettings": rc}}))
    ts, th2 = _tls_server(["h2", "http/1.1"]), _tls_client(p, ["h2", "http/1.1"])
    th1 = _tls_client(p, ["http/1.1"])
    vless(6, "lab-vless-tls", "VLESS + TLS (TCP)",
          ({"network": "raw", "security": "tls", "tlsSettings": _tls_server(["http/1.1"])},
           {"network": "raw", "security": "tls", "tlsSettings": th1}))
    vless(7, "lab-ws-tls", "VLESS WebSocket + TLS",
          ({"network": "ws", "wsSettings": {"path": path}, "security": "tls",
            "tlsSettings": _tls_server(["http/1.1"])},
           {"network": "ws", "wsSettings": {"path": path}, "security": "tls", "tlsSettings": th1}))
    vless(8, "lab-httpupgrade-tls", "VLESS HTTPUpgrade + TLS",
          ({"network": "httpupgrade", "httpupgradeSettings": {"path": path}, "security": "tls",
            "tlsSettings": _tls_server(["http/1.1"])},
           {"network": "httpupgrade", "httpupgradeSettings": {"path": path}, "security": "tls",
            "tlsSettings": th1}))
    vless(9, "lab-xhttp-tls", "VLESS XHTTP + TLS (h2)",
          ({"network": "xhttp", "xhttpSettings": {"path": path, "mode": "auto"}, "security": "tls",
            "tlsSettings": ts},
           {"network": "xhttp", "xhttpSettings": {"path": path, "mode": "auto"}, "security": "tls",
            "tlsSettings": th2}))
    vless(10, "lab-xhttp-h3", "VLESS XHTTP + QUIC (h3)",
          ({"network": "xhttp", "xhttpSettings": {"path": path, "mode": "auto"}, "security": "tls",
            "tlsSettings": _tls_server(["h3"])},
           {"network": "xhttp", "xhttpSettings": {"path": path, "mode": "auto"}, "security": "tls",
            "tlsSettings": _tls_client(p, ["h3"])}))
    # no encryption on the wire (baselines: what plain traffic gets)
    for i, key, label, net, setting in (
            (11, "lab-vmess-ws", "VMess WebSocket (بدون TLS)", "ws", {"wsSettings": {"path": path}}),
            (12, "lab-vmess-tcp", "VMess TCP (بدون TLS)", "raw", {})):
        port = base + i
        out.append((key, label,
                    {"tag": key, "port": port, "protocol": "vmess", "settings": {"clients": [{"id": uid}]},
                     "streamSettings": dict({"network": net}, **setting)},
                    {"tag": "proxy", "protocol": "vmess",
                     "settings": {"vnext": [{"address": host, "port": port,
                                             "users": [{"id": uid, "security": "auto"}]}]},
                     "streamSettings": dict({"network": net}, **setting)}))
    # (VLESS without TLS: the Xray client refuses it for a public address)
    # Shadowsocks
    for i, key, label, method, pw in ((15, "lab-ss2022", "Shadowsocks-2022 (یک کاربر)",
                                       "2022-blake3-aes-128-gcm", p["lab_ss_key"]),
                                      (16, "lab-ss-aead", "Shadowsocks قدیمی (aes-128-gcm)",
                                       "aes-128-gcm", p["lab_ss_old"])):
        port = base + i
        out.append((key, label,
                    {"tag": key, "port": port, "protocol": "shadowsocks",
                     "settings": {"method": method, "password": pw, "network": "tcp,udp"}},
                    {"tag": "proxy", "protocol": "shadowsocks",
                     "settings": {"servers": [{"address": host, "port": port, "method": method, "password": pw}]}}))
    # Hysteria2, plain and with Salamander
    for i, key, label, mask in ((17, "lab-hy2-plain", "Hysteria2 (بدون مبهم‌سازی)", None),
                                (18, "lab-hy2-salamander", "Hysteria2 + Salamander", p.get("hy2_obfs"))):
        port = base + i
        s_stream = {"network": "hysteria", "hysteriaSettings": {"version": 2}, "security": "tls",
                    "tlsSettings": _tls_server(["h3"])}
        c_stream = {"network": "hysteria", "hysteriaSettings": {"version": 2, "auth": p["lab_pass"]},
                    "security": "tls", "tlsSettings": _tls_client(p, ["h3"])}
        if i == 18 and not mask:
            continue
        if mask:
            fm = {"udp": [{"type": "salamander", "settings": {"password": mask}}]}
            s_stream["finalmask"] = fm
            c_stream["finalmask"] = fm
        out.append((key, label,
                    {"tag": key, "port": port, "protocol": "hysteria",
                     "settings": {"version": 2, "users": [{"auth": p["lab_pass"]}]}, "streamSettings": s_stream},
                    {"tag": "proxy", "protocol": "hysteria",
                     "settings": {"version": 2, "address": host, "port": port}, "streamSettings": c_stream}))
    # mKCP (UDP), as VMess (encrypted itself)
    port = base + 19
    kcp = {"network": "mkcp", "kcpSettings": {"seed": p["lab_pass"]}}
    out.append(("lab-mkcp", "VMess mKCP (UDP)",
                {"tag": "lab-mkcp", "port": port, "protocol": "vmess", "settings": {"clients": [{"id": uid}]},
                 "streamSettings": kcp},
                {"tag": "proxy", "protocol": "vmess",
                 "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": uid, "security": "auto"}]}]},
                 "streamSettings": kcp}))
    # WireGuard (plain, as the app's AmneziaWG without its disguise)
    if p.get("lab_wg_server_priv") and p.get("lab_wg_client_pub"):
        port = base + 20
        out.append(("lab-wireguard", "WireGuard ساده (بدون مبهم‌سازی AmneziaWG)",
                    {"tag": "lab-wireguard", "port": port, "protocol": "wireguard",
                     "settings": {"secretKey": p["lab_wg_server_priv"], "mtu": 1280,
                                  "peers": [{"publicKey": p["lab_wg_client_pub"],
                                             "allowedIPs": ["10.250.0.2/32"]}]}},
                    {"tag": "proxy", "protocol": "wireguard",
                     "settings": {"secretKey": p["lab_wg_client_priv"], "address": ["10.250.0.2/32"],
                                  "mtu": 1280, "peers": [{"publicKey": p["lab_wg_server_pub"],
                                                          "endpoint": "%s:%d" % (host, port),
                                                          "allowedIPs": ["0.0.0.0/0"]}]}}))
    return out


def lab_config(inbounds):
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds,
            "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
            "routing": {"rules": [{"ip": ["geoip:private"], "outboundTag": "block"}]}}


def _free_base(h, p):
    if p.get("lab_port0"):
        return p["lab_port0"]
    used = set()
    for line in h.run("ss -lntuH 2>/dev/null | awk '{print $5}' || true").split():
        try:
            used.add(int(line.rsplit(":", 1)[1]))
        except (ValueError, IndexError):
            pass
    used |= {int(p.get(k) or 0) for k in ("vision_port", "xhttp_port", "hy2_port", "ss_port", "cdn_local_port")}
    hop = (p.get("awg") or {}).get("hop") or [0, -1]
    while True:
        b = 20000 + secrets.randbelow(38000)
        ports = range(b, b + LAB_PORTS)
        if not any(x in used or hop[0] <= x <= hop[1] for x in ports):
            return b


def _wg_keys(h, p):
    if p.get("lab_wg_server_priv"):
        return
    import base64

    def std(k):       # xray prints URL-safe base64 without padding; WireGuard keys are standard base64
        raw = base64.urlsafe_b64decode(k + "=" * (-len(k) % 4))
        return base64.b64encode(raw).decode()
    for side in ("server", "client"):
        priv, pub = linux.x25519(h)
        p["lab_wg_%s_priv" % side], p["lab_wg_%s_pub" % side] = std(priv), std(pub)


def setup_lab(h, p, host, log=print):
    """Install or refresh xray-lab on a production Linux server (Xray, keys
    and certificate already there). Returns (params, export entry)."""
    lab_params(p)
    p["lab_port0"] = _free_base(h, p)
    try:
        _wg_keys(h, p)
    except Exception as e:   # noqa: BLE001 - WireGuard is just one of them
        log("⚠ کلید WireGuard ساخته نشد: %s" % str(e)[:200])
    defs = lab_defs(p, host)
    h.run("mkdir -p %s" % LAB_DIR)
    good, bad = [], []
    for key, label, inbound, outbound in defs:
        path = "%s/test-%s.json" % (LAB_DIR, key)
        h.write(path, json.dumps(lab_config([inbound])))
        res = h.run("/usr/local/bin/xray run -test -config %s 2>&1 || true" % path)
        h.run("rm -f %s" % path)
        if "Configuration OK" in res:
            good.append((key, label, inbound, outbound))
        else:
            bad.append((label, res.strip().splitlines()[-1][:160] if res.strip() else "?"))
    for label, why in bad:
        log("⚠ این نسخه‌ی Xray «%s» را ندارد: %s" % (label, why))
    if not good:
        raise linux.LinuxError("هیچ پروتکل آزمایشی‌ای از xray run -test رد نشد.")
    h.write(LAB_DIR + "/config.json", json.dumps(lab_config([d[2] for d in good]), indent=1))
    h.write("/etc/systemd/system/xray-lab.service", """[Unit]
Description=Xray lab (test protocols for the test app)
After=network-online.target

[Service]
ExecStart=/usr/local/bin/xray run -config %s/config.json
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
""" % LAB_DIR)
    h.run("systemctl daemon-reload; systemctl enable xray-lab >/dev/null 2>&1; systemctl restart xray-lab")
    state = h.run("sleep 2; systemctl is-active xray-lab || true").strip()
    if state != "active":
        raise linux.LinuxError("xray-lab اجرا نشد:\n" + h.run("journalctl -u xray-lab -n 20 --no-pager || true"))
    log("✓ %d پروتکل آزمایشی روی پورت‌های %d تا %d اجرا شد." % (len(good), p["lab_port0"],
                                                                 p["lab_port0"] + LAB_PORTS - 1))
    return p, [{"id": d[0], "label": d[1], "outbound": d[3]} for d in good]


def remove_lab(h, log=print):
    h.run("systemctl disable --now xray-lab >/dev/null 2>&1 || true; rm -f /etc/systemd/system/xray-lab.service; "
          "systemctl daemon-reload; rm -rf %s" % LAB_DIR)
    log("✓ پروتکل‌های آزمایشی برداشته شدند (Xray اصلی دست نخورد).")


def export(servers):
    """The text the test app imports: [{name, server (production entry), lab}]."""
    return json.dumps({"pv_test": 1, "servers": servers}, ensure_ascii=False)
