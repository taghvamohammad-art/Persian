#!/usr/bin/env python3
"""pv-agent: keeps a Linux VPN server in step with MikroTik User Manager.

Every minute it
  1. reads the users from User Manager (REST; first router, else the second),
  2. lets in exactly the users that are enabled and have a running profile:
     Xray inbounds (VLESS Reality / XHTTP, Hysteria2, Shadowsocks-2022) and
     AmneziaWG peers, with credentials derived from username + password,
  3. reports each user's traffic to User Manager over RADIUS accounting
     (after an Access-Request, so User Manager's own limits decide), the
     way a MikroTik NAS does: volume and days stay in one place.

Standard library only (Ubuntu's python3). Config: /etc/pv-agent/config.json.
"""

import base64
import copy
import hashlib
import http.client
import json
import logging
import os
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pvcreds  # noqa: E402

log = logging.getLogger("pv-agent")

CONFIG = "/etc/pv-agent/config.json"
IDLE_STOP = 300          # seconds without traffic before the accounting session is closed
BLOCK_RETRY = 600        # a user User Manager rejected is asked again after this long
XRAY_RESTART_GAP = 120   # at most one fallback restart of Xray per this many seconds


# ====================================================================== RADIUS

ACCESS_REQUEST, ACCESS_ACCEPT, ACCESS_REJECT = 1, 2, 3
ACCOUNTING_REQUEST, ACCOUNTING_RESPONSE = 4, 5
START, STOP, INTERIM = 1, 2, 3


def _attr(t, value):
    if isinstance(value, int):
        value = struct.pack("!I", value & 0xFFFFFFFF)
    elif isinstance(value, str):
        value = value.encode("utf-8")
    return struct.pack("!BB", t, len(value) + 2) + value


def _ip(addr):
    return socket.inet_aton(addr)


def pap(password, secret, authenticator):
    p = password.encode("utf-8")
    p += b"\0" * (-len(p) % 16 or (16 if not p else 0))
    out, last = b"", authenticator
    for i in range(0, len(p), 16):
        block = bytes(a ^ b for a, b in zip(p[i:i + 16], hashlib.md5(secret + last).digest()))
        out += block
        last = block
    return out


class Radius:
    """A small RADIUS client: several servers, first one that answers wins."""

    def __init__(self, servers, nas_ip, nas_id, timeout=3.0):
        self.servers = servers            # [{"host", "secret", "auth_port", "acct_port"}]
        self.nas_ip, self.nas_id, self.timeout = nas_ip, nas_id, timeout

    def _exchange(self, code, attrs, acct):
        last = None
        for srv in self.servers:
            secret = srv["secret"].encode()
            ident = secrets.randbelow(256)
            if code == ACCOUNTING_REQUEST:
                body = b"".join(attrs)
                length = 20 + len(body)
                auth = hashlib.md5(struct.pack("!BBH", code, ident, length) + b"\0" * 16 + body + secret).digest()
            else:
                auth = os.urandom(16)
                body = b"".join(attrs(secret, auth))
                length = 20 + len(body)
            packet = struct.pack("!BBH", code, ident, length) + auth + body
            port = srv.get("acct_port", 1813) if acct else srv.get("auth_port", 1812)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            try:
                for _ in range(2):
                    s.sendto(packet, (srv["host"], port))
                    try:
                        data, _ = s.recvfrom(4096)
                    except socket.timeout:
                        continue
                    if len(data) < 20 or data[1] != ident:
                        continue
                    check = hashlib.md5(data[:4] + auth + data[20:] + secret).digest()
                    if check != data[4:20]:
                        log.warning("radius %s: bad response authenticator", srv["host"])
                        continue
                    return data[0], srv["host"]
            except OSError as e:
                last = e
            finally:
                s.close()
        raise OSError("no RADIUS server answered (%s)" % last if last else "no RADIUS server answered")

    def _common(self, user, sid=None):
        a = [_attr(1, user), _attr(4, _ip(self.nas_ip)), _attr(32, self.nas_id),
             _attr(61, 5), _attr(6, 2)]
        if sid:
            a.append(_attr(44, sid))
        return a

    def authorize(self, user, password):
        """True (accept) / False (reject); OSError when nobody answers."""
        def attrs(secret, auth):
            return self._common(user) + [_attr(2, pap(password, secret, auth)), _attr(31, "pv-agent")]
        code, _ = self._exchange(ACCESS_REQUEST, attrs, acct=False)
        return code == ACCESS_ACCEPT

    def account(self, kind, user, sid, seconds=0, octets_in=0, octets_out=0, address=None):
        a = self._common(user, sid) + [_attr(40, kind), _attr(46, int(seconds)),
                                        _attr(42, octets_in), _attr(52, octets_in >> 32),
                                        _attr(43, octets_out), _attr(53, octets_out >> 32)]
        if address:
            a.append(_attr(8, _ip(address)))
        code, host = self._exchange(ACCOUNTING_REQUEST, a, acct=True)
        if code != ACCOUNTING_RESPONSE:
            raise OSError("unexpected RADIUS answer %d" % code)
        return host


# ====================================================================== User Manager over REST

class RouterError(Exception):
    pass


class PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to the router, trusted only if its certificate has the pinned
    SHA-256 (routers use self-signed certificates); checked before any
    credentials are sent."""

    def __init__(self, host, pin, timeout):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        super().__init__(host, timeout=timeout, context=ctx)
        self.pin = pin.lower().replace(":", "")

    def connect(self):
        super().connect()
        cert = self.sock.getpeercert(binary_form=True)
        if not self.pin or hashlib.sha256(cert).hexdigest() != self.pin:
            self.close()
            raise RouterError("router certificate does not match the pin")


def users_from(router, timeout=60):
    """{username: password} of the users allowed right now on one router."""
    url = urllib.parse.urlsplit(router["url"])
    token = base64.b64encode(("%s:%s" % (router["user"], router["password"])).encode()).decode()

    def post(path, body):
        if url.scheme == "https":
            conn = PinnedHTTPS(url.netloc, router.get("pin", ""), timeout)
        else:
            conn = http.client.HTTPConnection(url.netloc, timeout=timeout)
        try:
            conn.request("POST", url.path.rstrip("/") + "/rest" + path, body=json.dumps(body),
                         headers={"Content-Type": "application/json", "Authorization": "Basic " + token})
            r = conn.getresponse()
            data = r.read()
            if r.status != 200:
                raise RouterError("%s: HTTP %d %s" % (router.get("name", url.netloc), r.status, data[:200]))
            return json.loads(data or b"[]")
        except (OSError, ValueError, http.client.HTTPException) as e:
            raise RouterError("%s: %s" % (router.get("name", url.netloc), e))
        finally:
            conn.close()

    users = post("/user-manager/user/print", {".proplist": "name,password,disabled"})
    profiles = post("/user-manager/user-profile/print", {".proplist": "user,state"})
    # a waiting profile starts on the user's first login (our RADIUS
    # Access-Request), so a newly sold user must be let in to start it
    running = {str(p.get("user", "")).lower() for p in profiles
               if str(p.get("state", "")).startswith(("running", "waiting"))}
    allowed = {}
    for u in users:
        name = str(u.get("name", ""))
        if not name or str(u.get("disabled", "false")) == "true" or name.lower() not in running:
            continue
        if not u.get("password"):
            continue          # the agent's router account cannot read passwords
        allowed[name] = u["password"]
    return allowed


def fetch_users(routers):
    errors = []
    for r in routers:
        try:
            return users_from(r), r.get("name", r["url"])
        except RouterError as e:
            errors.append(str(e))
    raise RouterError("; ".join(errors))


# ====================================================================== Xray

def xray_clients(protocol, users):
    """Inbound client list for {username: password}."""
    out = []
    for name, pw in sorted(users.items()):
        email = name.lower()
        if protocol == "vless":
            out.append({"id": pvcreds.vless_uuid(name, pw), "email": email, "flow": ""})
        elif protocol == "vless-vision":
            out.append({"id": pvcreds.vless_uuid(name, pw), "email": email, "flow": "xtls-rprx-vision"})
        elif protocol == "hysteria":
            out.append({"auth": pvcreds.hy2_auth(name, pw), "email": email})
        elif protocol == "shadowsocks":
            out.append({"password": pvcreds.ss_key(name, pw), "email": email})
    return out


class Xray:
    def __init__(self, cfg):
        self.bin = cfg.get("bin", "/usr/local/bin/xray")
        self.api = cfg.get("api", "127.0.0.1:10085")
        self.template = cfg["template"]           # full config with empty client lists
        self.config = cfg.get("config", "/usr/local/etc/xray/config.json")
        self.inbounds = cfg["inbounds"]           # {tag: "vless-vision" | "vless" | "hysteria" | "shadowsocks"}
        self.service = cfg.get("service", "xray")
        self.last_restart = 0.0

    def _cli(self, command, *args, timeout=30):
        p = subprocess.run([self.bin, "api", command, "-s", self.api] + list(args),
                           capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            raise RuntimeError((p.stderr or p.stdout).strip()[:300])
        return p.stdout

    def _template(self):
        with open(self.template) as f:
            return json.load(f)

    def _fill(self, ib, users):
        kind = self.inbounds[ib["tag"]]
        key = "users" if kind == "hysteria" else "clients"
        ib.setdefault("settings", {})[key] = xray_clients(kind, users)
        return ib

    def inbound(self, tag, users):
        """The template's inbound `tag` with these users (for "xray api adu")."""
        ib = next(i for i in self._template()["inbounds"] if i.get("tag") == tag)
        return self._fill(copy.deepcopy(ib), users)

    def render(self, users):
        cfg = self._template()
        for ib in cfg.get("inbounds", []):
            if ib.get("tag") in self.inbounds:
                self._fill(ib, users)
        return cfg

    def write(self, users):
        cfg = self.render(users)
        tmp = self.config + ".tmp"
        with open(tmp, "w") as f:
            json.dump(cfg, f, indent=1)
        os.replace(tmp, self.config)

    def restart(self, users):
        self.write(users)
        subprocess.run(["systemctl", "restart", self.service], check=False, timeout=60)
        self.last_restart = time.time()

    def apply(self, old, new):
        """Change the running Xray from user set old to new without dropping
        everyone; falls back to a (rate-limited) restart. True if in step."""
        added = {k: v for k, v in new.items() if old.get(k) != v}
        removed = [k for k in old if k not in new or old[k] != new[k]]
        if not added and not removed:
            return True
        try:
            for tag, kind in self.inbounds.items():
                if removed:
                    try:
                        self._cli("rmu", "-tag=" + tag, *[n.lower() for n in removed])
                    except RuntimeError as e:
                        if "not found" not in str(e).lower():
                            raise
                if added:
                    doc = {"inbounds": [self.inbound(tag, added)]}
                    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                        json.dump(doc, f)
                    try:
                        self._cli("adu", f.name)
                    finally:
                        os.unlink(f.name)
            self.write(new)               # the next restart starts from the right set
            return True
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as e:
            log.warning("xray api: %s", e)
            if time.time() - self.last_restart >= XRAY_RESTART_GAP:
                log.info("restarting xray with %d users", len(new))
                self.restart(new)
                return True
            return False

    def traffic(self):
        """{email: [uplink, downlink]} since the previous call."""
        try:
            out = self._cli("statsquery", "-pattern", "user>>>", "-reset")
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as e:
            log.warning("xray stats: %s", e)
            return {}
        data = json.loads(out or "{}")
        result = {}
        for st in data.get("stat", []) or []:
            parts = st.get("name", "").split(">>>")
            if len(parts) == 4 and parts[0] == "user":
                pair = result.setdefault(parts[1], [0, 0])
                pair[0 if parts[3] == "uplink" else 1] += int(st.get("value", 0) or 0)
        return result


# ====================================================================== AmneziaWG

class Awg:
    def __init__(self, cfg, keycache):
        self.iface = cfg.get("iface", "awg0")
        self.bin = cfg.get("bin", "awg")
        self.cache = keycache                 # {private: public}

    def _run(self, *args, input=None):
        p = subprocess.run([self.bin] + list(args), capture_output=True, text=True, input=input, timeout=30)
        if p.returncode != 0:
            raise RuntimeError((p.stderr or p.stdout).strip()[:300])
        return p.stdout

    def public(self, private):
        pub = self.cache.get(private)
        if not pub:
            pub = self._run("pubkey", input=private + "\n").strip()
            self.cache[private] = pub
        return pub

    def peers(self, users):
        """{public key: (username, address)} for the allowed users; a username
        whose address is already taken (hash collision) is left out."""
        out, used = {}, {}
        for name in sorted(users, key=str.lower):
            addr = pvcreds.awg_address(name)
            if addr in used:
                log.warning("awg address %s of %s already used by %s", addr, name, used[addr])
                continue
            used[addr] = name
            out[self.public(pvcreds.awg_private(name, users[name]))] = (name, addr)
        return out

    def apply(self, users):
        want = self.peers(users)
        have = set(self._run("show", self.iface, "peers").split())
        for pub in have - set(want):
            self._run("set", self.iface, "peer", pub, "remove")
        for pub in set(want) - have:
            self._run("set", self.iface, "peer", pub, "allowed-ips", want[pub][1] + "/32")
        return want

    def transfer(self):
        """{public key: (received, sent)} as counted by the interface (cumulative)."""
        out = {}
        for line in self._run("show", self.iface, "transfer").splitlines():
            parts = line.split()
            if len(parts) == 3:
                out[parts[0]] = (int(parts[1]), int(parts[2]))
        return out


# ====================================================================== the loop

class Agent:
    def __init__(self, cfg):
        self.cfg = cfg
        self.state_path = cfg.get("state", "/var/lib/pv-agent/state.json")
        self.state = self._load()
        r = cfg["radius"]
        self.radius = Radius(r["servers"], r["nas_ip"], r.get("nas_identifier", "pv-linux"))
        self.xray = Xray(cfg["xray"]) if cfg.get("xray") else None
        self.awg = Awg(cfg["awg"], self.state.setdefault("awg_keys", {})) if cfg.get("awg") else None
        self.users = {}              # what the servers currently let in
        self.first = True

    def _load(self):
        try:
            with open(self.state_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def save(self):
        os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.state, f)
        os.replace(tmp, self.state_path)

    # ---------------------------------------------------------------- users

    def allowed_now(self, from_router):
        """Router's list minus users User Manager rejected a short while ago."""
        blocked = self.state.setdefault("blocked", {})
        now = time.time()
        for name in [n for n, t in blocked.items() if now - t > BLOCK_RETRY]:
            del blocked[name]
        return {n: p for n, p in from_router.items() if n.lower() not in blocked}

    def sync_users(self):
        try:
            users, source = fetch_users(self.cfg["routers"])
        except RouterError as e:
            log.warning("user list unavailable, keeping the current one: %s", e)
            return
        new = self.allowed_now(users)
        if self.xray:
            if self.first:
                self.xray.restart(new)
            elif not self.xray.apply(self.users, new):
                return             # try again next round with the old set as "current"
        if self.awg:
            try:
                self.awg_peers = self.awg.apply(new)
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
                log.warning("awg: %s", e)
        if new.keys() != self.users.keys():
            log.info("%d users allowed (from %s)", len(new), source)
        self.users = new
        self.first = False

    def block(self, name):
        self.state.setdefault("blocked", {})[name.lower()] = time.time()
        log.info("User Manager rejected %s: removed for now", name)

    # ---------------------------------------------------------------- traffic

    def collect(self):
        """{username lower: [in, out]} since the last round."""
        total = {}
        if self.xray:
            for email, (up, down) in self.xray.traffic().items():
                t = total.setdefault(email.lower(), [0, 0])
                t[0] += up
                t[1] += down
        if self.awg:
            try:
                now = self.awg.transfer()
            except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
                log.warning("awg transfer: %s", e)
                now = {}
            prev = self.state.setdefault("awg_transfer", {})
            peers = getattr(self, "awg_peers", {})
            for pub, (rx, tx) in now.items():
                if pub not in peers:
                    continue
                p_rx, p_tx = prev.get(pub, (0, 0))
                d_rx, d_tx = (rx - p_rx, tx - p_tx) if rx >= p_rx and tx >= p_tx else (rx, tx)
                if d_rx or d_tx:
                    t = total.setdefault(peers[pub][0].lower(), [0, 0])
                    t[0] += d_rx           # received by the server = sent by the user
                    t[1] += d_tx
            self.state["awg_transfer"] = {k: list(v) for k, v in now.items()}
        return total

    def account(self, traffic, now=None):
        now = now or time.time()
        sessions = self.state.setdefault("sessions", {})
        names = {n.lower(): n for n in self.users}
        for user, (up, down) in traffic.items():
            name = names.get(user, user)
            s = sessions.get(user)
            if s is None:
                password = self.users.get(name)
                if password is not None:
                    try:
                        if not self.radius.authorize(name, password):
                            self.block(name)
                            continue
                    except OSError as e:
                        log.warning("radius authorize %s: %s (letting the user in)", name, e)
                s = sessions[user] = {"sid": "pv%x%s" % (int(now), secrets.token_hex(3)), "name": name,
                                      "start": now, "in": 0, "out": 0, "last": now, "started": False}
            s["in"] += up
            s["out"] += down
            s["last"] = now
        for user, s in list(sessions.items()):
            idle = now - s["last"] > IDLE_STOP
            kind = STOP if idle else (INTERIM if s["started"] else START)
            try:
                self.radius.account(kind, s["name"], s["sid"], now - s["start"], s["in"], s["out"])
                if kind == START:
                    s["started"] = True
                    # the traffic before Start goes in the first interim update
                    self.radius.account(INTERIM, s["name"], s["sid"], now - s["start"], s["in"], s["out"])
                if idle:
                    del sessions[user]
            except OSError as e:
                log.warning("radius accounting %s: %s (kept for the next round)", s["name"], e)

    # ---------------------------------------------------------------- main

    def round(self):
        self.sync_users()
        traffic = self.collect()
        self.account(traffic)
        removed = [n for n in list(self.users) if n.lower() in self.state.get("blocked", {})]
        if removed:
            self.sync_users()
        self.save()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    path = sys.argv[1] if len(sys.argv) > 1 else CONFIG
    with open(path) as f:
        cfg = json.load(f)
    agent = Agent(cfg)
    every = int(cfg.get("interval", 60))
    while True:
        started = time.time()
        try:
            agent.round()
        except Exception:
            log.exception("round failed")
        time.sleep(max(5, every - (time.time() - started)))


if __name__ == "__main__":
    main()
