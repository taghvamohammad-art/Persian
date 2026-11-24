"""Xray server in a container on a MikroTik (the router abroad).

The same protocols as a Linux server (VLESS Reality / XHTTP, Hysteria2 with
Salamander, Shadowsocks-2022) and the same pv-agent keeping the users in
step with User Manager, without systemd or a package manager:

  1. Xray-core is downloaded from GitHub once (/app/bin),
  2. the Reality keys and Hysteria2's certificate are made once
     (/app/state/keys.json; the release tool reads the public parts),
  3. /app/template.in.json (from the release tool) gets the private key,
  4. pv-agent runs, and runs Xray itself ("supervise"),
  5. a small HTTP server gives the bot the online list (/pvs/<token>),
     only to the addresses in agent.json "status_allow".

Standard library only:  python3 /app/xraybox.py
"""

import base64
import hashlib
import http.server
import io
import json
import os
import platform
import re
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile

APP = os.environ.get("PV_APP", "/app")
BIN = os.path.join(APP, "bin")
STATE = os.path.join(APP, "state")
XRAY = os.path.join(BIN, "xray")
KEYS = os.path.join(STATE, "keys.json")
STATUS_PORT = 8081
RELEASE = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-%s.zip"


def say(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)
    try:
        with open(os.path.join(STATE, "box.log"), "a") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + msg + "\n")
    except OSError:
        pass


def arch():
    m = platform.machine().lower()
    return {"x86_64": "64", "amd64": "64", "aarch64": "arm64-v8a", "arm64": "arm64-v8a",
            "armv7l": "arm32-v7a"}.get(m, "64")


def ensure_xray():
    if os.path.isfile(XRAY) and os.access(XRAY, os.X_OK):
        return
    url = RELEASE % arch()
    say("downloading %s" % url)
    data = None
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url, timeout=120) as r:
                data = r.read()
            break
        except OSError as e:
            say("download failed (%s), again in 20s" % e)
            time.sleep(20)
    if data is None:
        raise SystemExit("Xray could not be downloaded")
    os.makedirs(BIN, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in ("xray", "geoip.dat", "geosite.dat"):
            try:
                with open(os.path.join(BIN, name + ".new"), "wb") as f:
                    f.write(z.read(name))
                os.replace(os.path.join(BIN, name + ".new"), os.path.join(BIN, name))
            except KeyError:
                pass
    os.chmod(XRAY, 0o755)


def run(*args):
    p = subprocess.run([XRAY] + list(args), capture_output=True, text=True, timeout=60)
    return p.stdout + p.stderr


def parse_x25519(out):
    priv = re.search(r"Private\s*key:\s*(\S+)|PrivateKey:\s*(\S+)", out)
    pub = re.search(r"Public\s*key:\s*(\S+)|Password(?:\s*\(PublicKey\))?:\s*(\S+)", out)
    if not priv or not pub:
        raise ValueError("unknown xray x25519 output: " + out[:300])
    return (priv.group(1) or priv.group(2)), (pub.group(1) or pub.group(2))


def pem_sha256(path):
    """SHA-256 of the certificate's DER (what the apps pin)."""
    with open(path) as f:
        text = f.read()
    m = re.search(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", text, re.S)
    return hashlib.sha256(base64.b64decode("".join(m.group(1).split()))).hexdigest()


def ensure_keys():
    try:
        with open(KEYS) as f:
            keys = json.load(f)
        if keys.get("reality_public") and keys.get("hy2_pin"):
            return keys
    except (OSError, ValueError):
        pass
    os.makedirs(STATE, exist_ok=True)
    priv, pub = parse_x25519(run("x25519"))
    prefix = os.path.join(STATE, "hy2")
    name = base64.b32encode(os.urandom(5)).decode().lower()
    run("tls", "cert", "-domain=%s" % name, "-file=%s" % prefix)
    if not os.path.isfile(prefix + "_cert.pem"):
        # older/newer flag sets: the JSON it prints by default
        out = run("tls", "cert", "-domain=%s" % name)
        j = json.loads(out[out.index("{"):out.rindex("}") + 1])
        for part, key in (("_cert.pem", "certificate"), ("_key.pem", "key")):
            with open(prefix + part, "w") as f:
                f.write("\n".join(j[key]) + "\n")
    keys = {"reality_private": priv, "reality_public": pub, "hy2_pin": pem_sha256(prefix + "_cert.pem"),
            "hy2_cert": prefix + "_cert.pem", "hy2_key": prefix + "_key.pem"}
    with open(KEYS + ".tmp", "w") as f:
        json.dump(keys, f)
    os.replace(KEYS + ".tmp", KEYS)
    say("keys made")
    return keys


def render_template(keys):
    with open(os.path.join(APP, "template.in.json")) as f:
        text = f.read()
    for k in ("reality_private", "hy2_cert", "hy2_key"):
        text = text.replace("__%s__" % k.upper(), keys[k])
    path = os.path.join(STATE, "template.json")
    with open(path + ".tmp", "w") as f:
        f.write(text)
    os.replace(path + ".tmp", path)
    out = run("run", "-test", "-config", path)
    if "Configuration OK" not in out:
        say("template test: " + out[-600:])


class Status(http.server.BaseHTTPRequestHandler):
    token, allow, path_file = "", (), ""

    def do_GET(self):
        if self.client_address[0] not in self.allow or self.path.rstrip("/") != "/pvs/" + self.token:
            self.send_error(404)
            return
        try:
            with open(self.path_file, "rb") as f:
                body = f.read()
        except OSError:
            body = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve_status(cfg):
    st = cfg.get("box_status") or {}
    if not st.get("token"):
        return
    handler = type("H", (Status,), {"token": st["token"], "allow": tuple(st.get("allow", ())),
                                    "path_file": cfg.get("status_file", os.path.join(STATE, "status.json"))})

    class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True
    srv = Server(("0.0.0.0", STATUS_PORT), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def main():
    os.makedirs(STATE, exist_ok=True)
    ensure_xray()
    keys = ensure_keys()
    render_template(keys)
    agent_cfg = os.path.join(APP, "agent.json")
    with open(agent_cfg) as f:
        cfg = json.load(f)
    serve_status(cfg)
    say("xray %s; starting pv-agent" % run("version").split("\n")[0][:60])
    sys.path.insert(0, APP)
    sys.argv = [os.path.join(APP, "pv_agent.py"), agent_cfg]
    import pv_agent
    pv_agent.main()


if __name__ == "__main__":
    main()
