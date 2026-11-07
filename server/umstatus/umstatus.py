#!/usr/bin/env python3
"""umstatus - small HTTPS API that tells a User Manager user how much
volume and how many days they have left.

Runs inside a RouterOS container. Talks to the router's REST API
(over the internal veth address) with a read-only account; the admin
credentials never leave the router.

Only the Python standard library is used, so the stock python:alpine
image is enough.

  python3 umstatus.py serve               # run the HTTPS API
  python3 umstatus.py selftest 25g8282    # print what the router returns
  python3 umstatus.py selftest 25g8282 sessions   # also time the slow session scan
"""

import base64
import hmac
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = os.environ.get("UMSTATUS_CONFIG", "/app/config.json")

DEFAULTS = {
    "router_url": "http://172.17.0.1:64/rest",
    "router_user": "umstatus",
    "router_password": "",
    "listen_host": "0.0.0.0",
    "listen_port": 8443,
    "cert_file": "/app/umstatus.crt",
    "key_file": "/app/umstatus.key",
    "key_passphrase": "",
    "router_timeout": 6,
    "session_timeout": 30,
    "cache_seconds": 60,
    "app_config_file": "/app/app_config.signed.json",
    "app_apk_file": "/app/app.apk",
    # brute-force protection
    "max_fail_per_ip": 10,          # per window
    "max_fail_per_user": 20,        # per window
    "fail_window_seconds": 900,
}


# ---------------------------------------------------------------- parsing

_SIZE_UNITS = {
    "": 1, "B": 1,
    "KIB": 1024, "MIB": 1024 ** 2, "GIB": 1024 ** 3, "TIB": 1024 ** 4,
    "KB": 1000, "MB": 1000 ** 2, "GB": 1000 ** 3, "TB": 1000 ** 4,
}


def parse_size(value):
    """'26843545600', '26843545600B', '798.7MiB' -> bytes (int)."""
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip()
    if not s:
        return 0
    m = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*([A-Za-z]*)", s)
    if not m:
        raise ValueError("bad size: %r" % value)
    unit = m.group(2).upper()
    if unit not in _SIZE_UNITS:
        raise ValueError("bad size unit: %r" % value)
    return int(round(float(m.group(1)) * _SIZE_UNITS[unit]))


_DUR_UNITS = {"w": 7 * 86400, "d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}


def parse_duration(value):
    """'4w2d', '13h54m17s', '1d02:03:04', '00:05:00', 'unlimited' -> seconds.
    Returns None for unlimited/empty/zero."""
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in ("", "unlimited", "none", "0", "0s", "00:00:00"):
        return None
    total = 0.0
    m = re.fullmatch(r"(?:(\d+)w)?(?:(\d+)d)?(\d+):(\d{2}):(\d{2})", s)
    if m:
        w, d, h, mi, se = (int(x) if x else 0 for x in m.groups())
        total = w * 7 * 86400 + d * 86400 + h * 3600 + mi * 60 + se
    else:
        parts = re.findall(r"(\d+(?:\.\d+)?)(ms|w|d|h|m|s)", s)
        if not parts or "".join(a + b for a, b in parts) != s:
            raise ValueError("bad duration: %r" % value)
        for num, unit in parts:
            total += float(num) * _DUR_UNITS[unit]
    return int(total) if total > 0 else None


_MONTHS = {m: i + 1 for i, m in enumerate(
    "jan feb mar apr may jun jul aug sep oct nov dec".split())}


def parse_dt(value):
    """'2026-12-05 19:19:16' or 'dec/05/2026 19:19:16' -> naive datetime
    (router local time). Returns None for empty."""
    if not value:
        return None
    s = str(value).strip()
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})", s)
    if m:
        return datetime(*map(int, m.groups()))
    m = re.fullmatch(r"([a-z]{3})/(\d{2})/(\d{4}) (\d{2}):(\d{2}):(\d{2})", s.lower())
    if m:
        mon, day, year, h, mi, se = m.groups()
        return datetime(int(year), _MONTHS[mon], int(day), int(h), int(mi), int(se))
    raise ValueError("bad datetime: %r" % value)


def parse_clock(clock):
    """/system/clock record -> naive datetime (router local time)."""
    date = str(clock.get("date", "")).strip()
    tm = str(clock.get("time", "")).strip()
    return parse_dt(date + " " + tm)


def is_true(v):
    return str(v).lower() in ("true", "yes", "1")


# ---------------------------------------------------------------- router

class RouterError(Exception):
    pass


class Router:
    """Minimal RouterOS REST client (read only)."""

    def __init__(self, base_url, user, password, timeout=6, session_timeout=30):
        self.base = base_url.rstrip("/")
        token = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        self.auth = "Basic " + token
        self.timeout = timeout
        self.session_timeout = session_timeout

    def _req(self, method, path, query=None, body=None, timeout=None):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self.auth)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            detail = e.read()[:300].decode("utf-8", "replace")
            raise RouterError("HTTP %s on %s: %s" % (e.code, path, detail))
        except Exception as e:  # network, timeout
            raise RouterError("%s on %s: %s" % (type(e).__name__, path, e))
        out = json.loads(raw.decode("utf-8")) if raw else []
        if isinstance(out, dict):
            out = [out]
        return out

    def get(self, path, **query):
        return self._req("GET", path, query or None)

    def post(self, path, body, timeout=None):
        return self._req("POST", path, body=body, timeout=timeout)

    # -- User Manager helpers ------------------------------------------

    def user_with_password(self, name):
        """Return (record, method). The password field is sensitive;
        try plain GET first, then print with show-sensitive."""
        rows = self.get("/user-manager/user", name=name)
        if not rows:
            return None, "not-found"
        rec = rows[0]
        if "password" in rec:
            return rec, "get"
        rows = self.post("/user-manager/user/print",
                         {".query": ["name=" + name], "show-sensitive": ""})
        if rows and "password" in rows[0]:
            return rows[0], "print-show-sensitive"
        return rec, "unavailable"

    def user_profiles(self, name):
        return self.get("/user-manager/user-profile", user=name)

    def profile(self, name):
        rows = self.get("/user-manager/profile", name=name)
        return rows[0] if rows else None

    def profile_limitations(self, profile_name):
        links = self.get("/user-manager/profile-limitation", profile=profile_name)
        out = []
        for link in links:
            lim = self.get("/user-manager/limitation", name=link.get("limitation", ""))
            if lim:
                out.append(lim[0])
        return out

    def sessions(self, name):
        # The session table holds every user's history, so this is the
        # slowest call; filter on the router side and fetch only 3 fields.
        return self.post("/user-manager/session/print",
                         {".query": ["user=" + name],
                          ".proplist": ["started", "download", "upload"]},
                         timeout=self.session_timeout)

    def monitor(self, user_id):
        """Lifetime totals of one user. Fast: no session-table scan."""
        rows = self.post("/user-manager/user/monitor",
                         {"numbers": user_id, "once": ""})
        return rows[0] if rows else {}

    def clock(self):
        rows = self.get("/system/clock")
        return rows[0] if rows else {}


# ---------------------------------------------------------------- logic

def limits_of(limitations):
    """Combine several limitations: the strictest non-zero value wins."""
    out = {"transfer": None, "download": None, "upload": None}
    for lim in limitations:
        for key, field in (("transfer", "transfer-limit"),
                           ("download", "download-limit"),
                           ("upload", "upload-limit")):
            v = parse_size(lim.get(field))
            if v > 0 and (out[key] is None or v < out[key]):
                out[key] = v
    return out


def profile_info(router, prof_name, cache):
    if prof_name not in cache:
        prof = router.profile(prof_name) or {}
        lims = router.profile_limitations(prof_name)
        cache[prof_name] = {
            "name": prof_name,
            "display": prof.get("name-for-users") or prof_name,
            "validity_seconds": parse_duration(prof.get("validity")),
            "limits": limits_of(lims),
        }
    return cache[prof_name]


RUNNING_STATES = ("running-active", "running")


def build_status(router, username, user_id, now=None):
    """Everything the app shows, for one user. Password is NOT checked here."""
    if now is None:
        now = parse_clock(router.clock())
    profiles = router.user_profiles(username)
    pcache = {}

    running = [p for p in profiles if p.get("state") in RUNNING_STATES]
    waiting = [p for p in profiles if p.get("state") == "waiting"]
    # User Manager marks the profile actually in use as "running-active".
    # A renewed user can also have an older profile still "running" (its
    # volume is used up but its end-time has not come yet); it is not current.
    running.sort(key=lambda p: (p.get("state") != "running-active",
                                parse_dt(p.get("end-time")) or datetime.max))

    result = {
        "ok": True,
        "username": username,
        "server_time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "current": None,
        "next": [],
    }

    for p in waiting:
        info = profile_info(router, p.get("profile", ""), pcache)
        result["next"].append({
            "profile": info["name"],
            "display": info["display"],
            "validity_days": (info["validity_seconds"] // 86400
                              if info["validity_seconds"] else None),
            "limit_bytes": info["limits"]["transfer"],
        })

    if not running:
        result["state"] = "waiting" if waiting else "no_profile"
        return result

    cur = running[0]
    info = profile_info(router, cur.get("profile", ""), pcache)
    end = parse_dt(cur.get("end-time"))
    start = None
    if end and info["validity_seconds"]:
        start = end - timedelta(seconds=info["validity_seconds"])

    # A user whose only profile is the current one has no earlier usage,
    # so the lifetime totals from monitor are exactly the current usage
    # (fast: no session-table scan).
    has_history = any(p.get("state") not in RUNNING_STATES + ("waiting",)
                      for p in profiles) or len(running) > 1
    if not has_history or start is None:
        mon = router.monitor(user_id)
        down = parse_size(mon.get("total-download"))
        up = parse_size(mon.get("total-upload"))
    else:
        # Renewed user: add up the sessions that started in the current
        # profile. (Lifetime totals minus older sessions does NOT work: the
        # session table no longer holds the user's full history.)
        # A session that was already open when the previous profile ran out
        # is counted entirely in the previous profile.
        down = up = 0
        for s in router.sessions(username):
            started = parse_dt(s.get("started"))
            if started is not None and started >= start:
                down += parse_size(s.get("download"))
                up += parse_size(s.get("upload"))

    lim = info["limits"]
    remaining = []
    if lim["transfer"] is not None:
        remaining.append(lim["transfer"] - (down + up))
    if lim["download"] is not None:
        remaining.append(lim["download"] - down)
    if lim["upload"] is not None:
        remaining.append(lim["upload"] - up)
    remaining_bytes = max(0, min(remaining)) if remaining else None

    seconds_left = None
    if end:
        seconds_left = max(0, int((end - now).total_seconds()))

    result["state"] = "active"
    if remaining_bytes == 0:
        result["state"] = "volume_finished"
    if seconds_left == 0:
        result["state"] = "expired"

    result["current"] = {
        "profile": info["name"],
        "display": info["display"],
        "start": start.strftime("%Y-%m-%d %H:%M:%S") if start else None,
        "end": end.strftime("%Y-%m-%d %H:%M:%S") if end else None,
        "seconds_left": seconds_left,
        "days_left": (seconds_left // 86400) if seconds_left is not None else None,
        "download_bytes": down,
        "upload_bytes": up,
        "used_bytes": down + up,
        "limit_bytes": lim["transfer"],
        "download_limit_bytes": lim["download"],
        "upload_limit_bytes": lim["upload"],
        "remaining_bytes": remaining_bytes,
    }
    return result


# ---------------------------------------------------------------- guards

class FailLimiter:
    def __init__(self, max_ip, max_user, window):
        self.max_ip, self.max_user, self.window = max_ip, max_user, window
        self.ip, self.user = {}, {}
        self.lock = threading.Lock()

    def _recent(self, table, key, now):
        lst = [t for t in table.get(key, []) if now - t < self.window]
        if lst:
            table[key] = lst
        else:
            table.pop(key, None)
        return lst

    def blocked(self, ip, user, now=None):
        now = now or time.monotonic()
        with self.lock:
            return (len(self._recent(self.ip, ip, now)) >= self.max_ip or
                    len(self._recent(self.user, user, now)) >= self.max_user)

    def fail(self, ip, user, now=None):
        now = now or time.monotonic()
        with self.lock:
            self.ip.setdefault(ip, []).append(now)
            self.user.setdefault(user, []).append(now)

    def ok(self, ip):
        with self.lock:
            self.ip.pop(ip, None)


USERNAME_RE = re.compile(r"[A-Za-z0-9_.@-]{1,64}")


class Service:
    def __init__(self, router, cfg):
        self.router = router
        self.cfg = cfg
        self.limiter = FailLimiter(cfg["max_fail_per_ip"], cfg["max_fail_per_user"],
                                   cfg["fail_window_seconds"])
        self.cache = {}
        self.cache_lock = threading.Lock()

    def handle(self, ip, username, password):
        """Returns (http_status, body_dict)."""
        if (not isinstance(username, str) or not isinstance(password, str)
                or not USERNAME_RE.fullmatch(username) or len(password) > 128):
            return 400, {"ok": False, "error": "bad_request"}
        if self.limiter.blocked(ip, username):
            return 429, {"ok": False, "error": "too_many_attempts"}
        try:
            rec, _ = self.router.user_with_password(username)
            if rec is None or "password" not in rec:
                good = False
                if rec is not None:
                    log("password field not readable for user record; "
                        "check the 'sensitive' policy of the API account")
                    return 503, {"ok": False, "error": "server_config"}
            else:
                good = hmac.compare_digest(rec["password"].encode(), password.encode())
            if not good:
                self.limiter.fail(ip, username)
                return 401, {"ok": False, "error": "invalid_credentials"}
            self.limiter.ok(ip)

            now_m = time.monotonic()
            with self.cache_lock:
                hit = self.cache.get(username)
            if hit and now_m - hit[0] < self.cfg["cache_seconds"]:
                body = hit[1]
            else:
                body = build_status(self.router, username, rec.get(".id", username))
                body["disabled"] = is_true(rec.get("disabled"))
                with self.cache_lock:
                    self.cache[username] = (now_m, body)
            return 200, body
        except RouterError as e:
            log("router error: %s" % e)
            return 503, {"ok": False, "error": "router_unavailable"}
        except Exception as e:
            log("internal error: %s: %s" % (type(e).__name__, e))
            return 500, {"ok": False, "error": "internal"}


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def make_handler(service):
    class Handler(BaseHTTPRequestHandler):
        server_version = "umstatus"
        sys_version = ""
        timeout = 60

        def _send(self, code, body):
            data = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/health":
                return self._send(200, {"ok": True})
            if self.path == "/v1/config":
                # Signed by the owner's offline key; the app verifies it,
                # so this file is served as-is.
                try:
                    with open(service.cfg["app_config_file"], "rb") as f:
                        data = f.read(64 * 1024)
                except OSError:
                    return self._send(404, {"ok": False, "error": "no_config"})
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
                return
            if self.path == "/v1/app.apk":
                # The SHA-256 of this file is in the signed config; the app
                # refuses a download that does not match it.
                path = service.cfg["app_apk_file"]
                try:
                    f = open(path, "rb")
                except OSError:
                    return self._send(404, {"ok": False, "error": "no_apk"})
                with f:
                    size = os.fstat(f.fileno()).st_size
                    self.send_response(200)
                    self.send_header("Content-Type", "application/vnd.android.package-archive")
                    self.send_header("Content-Length", str(size))
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    try:
                        while True:
                            chunk = f.read(64 * 1024)
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                    except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
                        pass  # client went away mid-download
                return
            self._send(404, {"ok": False, "error": "not_found"})

        def do_POST(self):
            if self.path != "/v1/status":
                return self._send(404, {"ok": False, "error": "not_found"})
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if n <= 0 or n > 1024:
                return self._send(400, {"ok": False, "error": "bad_request"})
            try:
                req = json.loads(self.rfile.read(n).decode("utf-8"))
                user, pw = req.get("username"), req.get("password")
            except Exception:
                return self._send(400, {"ok": False, "error": "bad_request"})
            code, body = service.handle(self.client_address[0], user, pw)
            if code != 200:
                log("%s %s -> %s" % (self.client_address[0],
                                     user if isinstance(user, str) else "?", code))
            self._send(code, body)

        def log_message(self, fmt, *args):  # quiet default access log
            pass

    return Handler


# ---------------------------------------------------------------- main

def load_config(path=CONFIG_PATH):
    cfg = dict(DEFAULTS)
    with open(path, encoding="utf-8") as f:
        cfg.update(json.load(f))
    return cfg


def router_from(cfg):
    return Router(cfg["router_url"], cfg["router_user"], cfg["router_password"],
                  cfg["router_timeout"], cfg["session_timeout"])


def serve(cfg):
    service = Service(router_from(cfg), cfg)
    httpd = ThreadingHTTPServer((cfg["listen_host"], int(cfg["listen_port"])),
                                make_handler(service))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg["cert_file"], cfg["key_file"],
                        password=cfg["key_passphrase"] or None)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    log("umstatus listening on %s:%s" % (cfg["listen_host"], cfg["listen_port"]))
    httpd.serve_forever()


def selftest(cfg, username):
    r = router_from(cfg)

    def show(title, data):
        print("== %s" % title)
        print(json.dumps(data, ensure_ascii=False, indent=1)[:3000])

    try:
        show("clock", r.clock())
        rec, method = r.user_with_password(username)
        if rec is not None and "password" in rec:
            rec = dict(rec, password="<%d chars>" % len(rec["password"]))
        show("user (password method: %s)" % method, rec)
        show("user-profile", r.user_profiles(username))
        uid = rec.get(".id", username) if rec else username
        t0 = time.monotonic()
        mon = r.monitor(uid)
        show("monitor (%.1f s)" % (time.monotonic() - t0), mon)
        t0 = time.monotonic()
        st = build_status(r, username, uid)
        show("STATUS (%.1f s)" % (time.monotonic() - t0), st)
        if len(sys.argv) > 3 and sys.argv[3] == "sessions":
            t0 = time.monotonic()
            sess = r.sessions(username)
            print("== sessions: %d rows in %.1f s" % (len(sess), time.monotonic() - t0))
    except RouterError as e:
        print("ROUTER ERROR:", e)
        return 1
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "serve":
        serve(load_config())
        return 0
    if len(argv) >= 3 and argv[1] == "selftest":
        return selftest(load_config(), argv[2])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
