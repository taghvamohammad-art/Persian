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
    # public half of the owner's config-signing key; enables /v1/publish
    "config_pubkey_file": "/app/config_key.public.txt",
    "max_apk_bytes": 100 * 1024 * 1024,
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


# ---------------------------------------------------------------- publish

# ECDSA P-256 / SHA-256 verification, same scheme as tools/sign_config.py.
_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_A = _P - 3
_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
      0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
_SPKI = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + _A) * pow(2 * y1, -1, _P) % _P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    return x3, (lam * (x1 - x3) - y1) % _P


def _ec_mul(k, point):
    result, addend = None, point
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def ecdsa_verify(pub_der, data, sig):
    try:
        if not pub_der.startswith(_SPKI) or len(pub_der) != len(_SPKI) + 65:
            return False
        raw = pub_der[len(_SPKI) + 1:]
        q = (int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        if (q[1] * q[1] - (q[0] ** 3 + _A * q[0] + _B)) % _P != 0:
            return False
        if sig[0] != 0x30 or sig[1] != len(sig) - 2:
            return False
        i, rs = 2, []
        for _ in range(2):
            if sig[i] != 0x02:
                return False
            ln = sig[i + 1]
            rs.append(int.from_bytes(sig[i + 2:i + 2 + ln], "big"))
            i += 2 + ln
        r, s_ = rs
        if not (0 < r < _N and 0 < s_ < _N):
            return False
        z = int.from_bytes(__import__("hashlib").sha256(data).digest(), "big")
        w = pow(s_, -1, _N)
        pt = _ec_add(_ec_mul(z * w % _N, _G), _ec_mul(r * w % _N, q))
        return pt is not None and pt[0] % _N == r
    except (IndexError, ValueError):
        return False


def _sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class Publisher:
    """Accepts a new app config (and APK) from the release tool.

    No password: the request is accepted only if the config is signed with
    the owner's offline key, is newer than the one being served, and the
    APK matches the SHA-256 and size inside that signed config. A stolen or
    replayed request cannot install anything the owner did not sign.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()

    def _current(self):
        try:
            with open(self.cfg["app_config_file"], encoding="utf-8") as f:
                env = json.load(f)
            return json.loads(base64.b64decode(env["payload"]))
        except (OSError, ValueError, KeyError):
            return None

    def win_file(self):
        return self.cfg.get("app_win_file") or os.path.join(os.path.dirname(self.cfg["app_apk_file"]), "win.exe")

    def patch_dir(self, beta=False):
        d = self.cfg.get("app_patch_dir") or os.path.join(os.path.dirname(self.cfg["app_apk_file"]), "patches")
        return d + "-beta" if beta else d

    def beta_apk(self):
        return os.path.join(os.path.dirname(self.cfg["app_apk_file"]), "beta.apk")

    def beta_win(self):
        return os.path.join(os.path.dirname(self.win_file()), "beta-win.exe")

    def publish(self, envelope_b64, length, read, dry_run=False):
        """Returns (http_status, body). `read(n)` reads n body bytes.
        dry_run: check signature and version only (the release tool asks
        first, so a rejection never arrives in the middle of an upload)."""
        try:
            with open(self.cfg["config_pubkey_file"], encoding="utf-8") as f:
                pub = base64.b64decode(f.read().strip())
        except OSError:
            return 503, {"ok": False, "error": "publish_not_configured"}

        try:
            envelope_text = base64.b64decode(envelope_b64).decode("utf-8")
            env = json.loads(envelope_text)
            payload = base64.b64decode(env["payload"])
            sig = base64.b64decode(env["sig"])
        except Exception:
            return 400, {"ok": False, "error": "bad_request"}
        if not ecdsa_verify(pub, payload, sig):
            return 403, {"ok": False, "error": "bad_signature"}
        try:
            new = json.loads(payload)
            version = int(new["version"])
        except Exception:
            return 400, {"ok": False, "error": "bad_config"}

        if not self.lock.acquire(blocking=False):
            return 409, {"ok": False, "error": "busy"}
        try:
            cur = self._current()
            if cur is not None and version <= int(cur.get("version", 0)):
                return 409, {"ok": False, "error": "not_newer",
                             "current_version": int(cur.get("version", 0))}
            # public and test builds, each: (apk/exe path, patch dir, update entry);
            # the files arrive in this order: APK, its patches, Windows build, then the same for the test builds
            groups = [(self.cfg["app_apk_file"], self.patch_dir(), new.get("app_update")),
                      (self.win_file(), None, new.get("windows_update")),
                      (self.beta_apk(), self.patch_dir(True), new.get("app_update_beta")),
                      (self.beta_win(), None, new.get("windows_update_beta"))]
            files, keep = [], {}
            try:
                for path, pdir, upd in groups:
                    if not upd:
                        continue
                    files.append((path, int(upd.get("size", 0)), str(upd.get("sha256", "")).lower()))
                    if pdir is None:
                        continue
                    patches = [(str(p["from_sha256"]).lower(), int(p["size"]), str(p["sha256"]).lower())
                               for p in upd.get("patches") or []]
                    if any(not re.fullmatch(r"[0-9a-f]{64}", f) for f, _, _ in patches):
                        raise ValueError
                    files += [(os.path.join(pdir, patch_name(f)), ps, psha) for f, ps, psha in patches]
                    keep[pdir] = {patch_name(f) for f, _, _ in patches}
            except (KeyError, TypeError, ValueError):
                return 400, {"ok": False, "error": "bad_config"}
            # files already here need not come again ("partial"): the body then
            # carries only the missing ones, in the same order
            missing = [f for f in files if not _have(*f)]
            if dry_run:
                return 200, {"ok": True, "dry_run": True, "version": version, "features": ["beta", "partial"],
                             "have": sorted({f[2] for f in files} - {f[2] for f in missing})}
            if not files and length != 0:
                return 400, {"ok": False, "error": "unexpected_apk"}
            if length == 0:
                # config-only release: the files on the router must already match
                if missing:
                    return 400, {"ok": False, "error": "apk_required"}
            else:
                if any(f[1] > self.cfg["max_apk_bytes"] for f in files):
                    return 400, {"ok": False, "error": "apk_size_mismatch"}
                if length == sum(f[1] for f in missing):
                    incoming = missing
                elif length == sum(f[1] for f in files):
                    incoming = files            # an older release tool sends everything
                else:
                    return 400, {"ok": False, "error": "apk_size_mismatch"}
                import hashlib
                for path, want_size, want_sha in incoming:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    h, left = hashlib.sha256(), want_size
                    with open(path + ".part", "wb") as f:
                        while left > 0:
                            chunk = read(min(64 * 1024, left))
                            if not chunk:
                                break
                            h.update(chunk)
                            f.write(chunk)
                            left -= len(chunk)
                    if left != 0 or h.hexdigest() != want_sha:
                        for p_, _, _ in incoming:
                            if os.path.exists(p_ + ".part"):
                                os.remove(p_ + ".part")
                        return 400, {"ok": False, "error": "apk_mismatch"}

            # all files are swapped in only after everything checked out
            if length:
                for path, _, sha in incoming:
                    os.replace(path + ".part", path)
                    _remember_sha(path, sha)
            if True:
                for pdir, names in keep.items():
                    for n in (os.listdir(pdir) if os.path.isdir(pdir) else []):
                        if n not in names and n[:-len(".sha256")] not in names:
                            os.remove(os.path.join(pdir, n))
                # a test build no longer listed: its files go
                if not new.get("app_update_beta"):
                    _drop(self.beta_apk())
                    bdir = self.patch_dir(True)
                    for n in (os.listdir(bdir) if os.path.isdir(bdir) else []):
                        os.remove(os.path.join(bdir, n))
                if not new.get("windows_update_beta"):
                    _drop(self.beta_win())
            tmp = self.cfg["app_config_file"] + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(envelope_text)
            os.replace(tmp, self.cfg["app_config_file"])
            upd = new.get("app_update")
            log("published config version %d%s%s" % (
                version, " with app %s" % upd.get("version_code") if upd else "",
                " and test build %s" % new["app_update_beta"].get("version_code") if new.get("app_update_beta") else ""))
            return 200, {"ok": True, "version": version}
        finally:
            self.lock.release()


def _remember_sha(path, sha):
    try:
        with open(path + ".sha256", "w") as f:
            f.write(sha)
    except OSError:
        pass


def _drop(path):
    for p in (path, path + ".sha256"):
        try:
            os.remove(p)
        except OSError:
            pass


def _have(path, size, sha):
    """The router already holds exactly this file (SHA-256 kept next to it)."""
    try:
        if os.path.getsize(path) != size:
            return False
    except OSError:
        return False
    try:
        with open(path + ".sha256") as f:
            if f.read().strip() == sha:
                return True
    except OSError:
        pass
    if _sha256_file(path) == sha:
        _remember_sha(path, sha)
        return True
    return False


def patch_name(from_sha):
    return from_sha[:16] + ".pvdl"


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
        self.publisher = Publisher(cfg)

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

        def _send_file(self, path):
            try:
                f = open(path, "rb")
            except OSError:
                return self._send(404, {"ok": False, "error": "not_found"})
            with f:
                size = os.fstat(f.fileno()).st_size
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
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
                    pass

        def _send_umsync(self, token):
            """The main User Manager database for the second router (tools/release_tool/um2.py)."""
            import hmac
            d = os.path.dirname(service.cfg["app_apk_file"])
            try:
                with open(os.path.join(d, "umsync.token")) as f:
                    want = f.read().strip()
            except OSError:
                want = ""
            if not want or not hmac.compare_digest(want, token):
                return self._send(404, {"ok": False, "error": "not_found"})
            names = sorted(n for n in os.listdir(d) if n.startswith("umsync-db"))
            if not names:
                return self._send(503, {"ok": False, "error": "not_ready"})
            with open(os.path.join(d, names[0]), "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
                pass

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
            m = re.fullmatch(r"/v1/umsync/([A-Za-z0-9_-]{16,})", self.path)
            if m:
                return self._send_umsync(m.group(1))
            m = re.fullmatch(r"/v1/patch(-beta)?/([0-9a-f]{16}\.pvdl)", self.path)
            if m:
                path = os.path.join(service.publisher.patch_dir(bool(m.group(1))), m.group(2))
                try:
                    f = open(path, "rb")
                except OSError:
                    return self._send(404, {"ok": False, "error": "no_patch"})
                with f:
                    size = os.fstat(f.fileno()).st_size
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
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
                        pass
                return
            if self.path == "/v1/win.exe":
                return self._send_file(service.publisher.win_file())
            if self.path == "/v1/beta-win.exe":
                return self._send_file(service.publisher.beta_win())
            if self.path == "/v1/beta.apk":
                return self._send_file(service.publisher.beta_apk())
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
            if self.path == "/v1/publish":
                return self._publish()
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

        def _publish(self):
            ip = self.client_address[0]
            if service.limiter.blocked(ip, "_publish"):
                return self._send(429, {"ok": False, "error": "too_many_attempts"})
            env = self.headers.get("X-Config", "")
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if not env or len(env) > 32 * 1024 or n < 0:
                return self._send(400, {"ok": False, "error": "bad_request"})
            dry = self.headers.get("X-Dry-Run") == "1"
            if dry and n != 0:
                return self._send(400, {"ok": False, "error": "bad_request"})
            code, body = service.publisher.publish(env, n, self.rfile.read, dry_run=dry)
            if code == 403:
                service.limiter.fail(ip, "_publish")
            log("%s publish -> %s %s" % (ip, code, body.get("error", "")))
            if code != 200:
                self.close_connection = True   # body may be unread
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


class TLSThreadingServer(ThreadingHTTPServer):
    """HTTPS server whose TLS handshake runs in the per-connection thread.

    Wrapping the listening socket instead would run every handshake in the
    single accept thread: one client that connects and stays silent (a
    scanner, a phone that lost its network) then blocks all others, the
    backlog fills up and new clients get "timeout connecting".
    """
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, addr, handler, ssl_ctx, handshake_timeout=10):
        self.ssl_ctx = ssl_ctx
        self.handshake_timeout = handshake_timeout
        super().__init__(addr, handler)

    def finish_request(self, request, client_address):
        # runs in the worker thread (ThreadingMixIn.process_request_thread)
        try:
            request.settimeout(self.handshake_timeout)
            tls = self.ssl_ctx.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError):
            return  # bad or silent client; shutdown_request closes the socket
        try:
            self.RequestHandlerClass(tls, client_address, self)
        finally:
            try:
                tls.close()
            except OSError:
                pass

    def handle_error(self, request, client_address):
        pass  # clients dropping mid-request are normal; avoid traceback spam


def make_server(service, cfg):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg["cert_file"], cfg["key_file"],
                        password=cfg["key_passphrase"] or None)
    return TLSThreadingServer((cfg["listen_host"], int(cfg["listen_port"])),
                              make_handler(service), ctx)


def serve(cfg):
    httpd = make_server(Service(router_from(cfg), cfg), cfg)
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
