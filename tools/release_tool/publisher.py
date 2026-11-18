"""Core of the release tool (no GUI): sign a new app version, upload it to
the router's umstatus service, update the repository on GitHub.

Kept free of GUI code so it can be tested on its own (test_publisher.py).
"""

import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))          # tools/ (sign_config.py)
import sign_config as sc                                # noqa: E402

ASSET_PATH = "app/src/main/assets/app_config.signed.json"
PUBLIC_REPO = "taghvamohammad-art/pv-config"   # public mirror of the signed config
PUBLIC_FILE = "config.txt"


def mirror_urls(public_repo):
    """URLs the app tries when the router is unreachable (raw GitHub, then jsDelivr)."""
    return ["https://raw.githubusercontent.com/%s/main/%s" % (public_repo, PUBLIC_FILE),
            "https://cdn.jsdelivr.net/gh/%s@main/%s" % (public_repo, PUBLIC_FILE)]


# Encoding for the public mirror; same scheme as the app (brand/ConfigCodec.kt).
# Hides server addresses from casual readers and scrapers only: the key is in
# the APK. Authenticity comes from the signature inside.
_CODEC_KEY = bytes.fromhex("76eb86bc2d0bea3f596d86ce523e008f442ef27675478a7f61719792ef083d02")
_CODEC_PREFIX = "PVC1:"


def _keystream_xor(nonce, data):
    out = bytearray(len(data))
    for block in range((len(data) + 31) // 32):
        ks = hashlib.sha256(_CODEC_KEY + nonce + block.to_bytes(4, "big")).digest()
        for j in range(32):
            i = block * 32 + j
            if i >= len(data):
                break
            out[i] = data[i] ^ ks[j]
    return bytes(out)


def encode_public(envelope):
    nonce = os.urandom(16)
    return _CODEC_PREFIX + base64.b64encode(nonce + _keystream_xor(nonce, envelope.encode())).decode()


def decode_public(text):
    raw = base64.b64decode(text.strip()[len(_CODEC_PREFIX):])
    return _keystream_xor(raw[:16], raw[16:]).decode()
BUILD_RE = re.compile(r"persian-vpn-(\d+)", re.IGNORECASE)


class ReleaseError(Exception):
    """A problem the user can fix; the message is shown as-is (Persian)."""


# ------------------------------------------------------------------ workspace

class Workspace:
    """The folder with config.json and config_key.private.json (tools/)."""

    def __init__(self, folder):
        self.folder = folder

    def path(self, name):
        return os.path.join(self.folder, name)

    def check(self):
        missing = [n for n in ("config.json", sc.PRIVATE_FILE) if not os.path.isfile(self.path(n))]
        if missing:
            raise ReleaseError("این فایل‌ها در پوشه‌ی کاری پیدا نشدند: " + "، ".join(missing))

    def load_config(self):
        with open(self.path("config.json"), encoding="utf-8") as f:
            return json.load(f)

    def private_key(self):
        with open(self.path(sc.PRIVATE_FILE), encoding="utf-8") as f:
            return int(json.load(f)["d"], 16)

    def published_version_code(self):
        return int(self.load_config().get("app_update", {}).get("version_code", 0))


# ------------------------------------------------------------------ build file

class Build:
    def __init__(self, apk, version_code, source):
        self.apk = apk
        self.version_code = version_code
        self.source = source

    @property
    def sha256(self):
        return hashlib.sha256(self.apk).hexdigest()


def read_build(path):
    """An artifact zip from GitHub (persian-vpn-16.zip) or a bare .apk."""
    name = os.path.basename(path)
    m = BUILD_RE.search(name)
    code = int(m.group(1)) if m else None
    if zipfile.is_zipfile(path) and not path.lower().endswith(".apk"):
        with zipfile.ZipFile(path) as z:
            apks = [n for n in z.namelist() if n.lower().endswith(".apk")]
            if not apks:
                raise ReleaseError("داخل این فایل zip هیچ APK‌ای نیست.")
            pick = next((n for n in apks if "release" in n.lower()), apks[0])
            if "debug" in pick.lower():
                raise ReleaseError("این بیلد نسخه‌ی debug است و روی نسخه‌ی کاربران نصب نمی‌شود.")
            apk = z.read(pick)
    else:
        with open(path, "rb") as f:
            apk = f.read()
    if apk[:2] != b"PK":
        raise ReleaseError("این فایل APK معتبر نیست.")
    return Build(apk, code, name)


# ------------------------------------------------------------------ signing

APK_HISTORY = 3          # older versions kept to make patches from
PATCH_MAX_SHARE = 0.7    # a patch bigger than this share of the APK is not worth it


def apk_history(ws):
    """[(version_code, path)] of earlier APKs kept in the workspace, newest first."""
    d = ws.path("apks")
    out = []
    if os.path.isdir(d):
        for n in os.listdir(d):
            m = re.fullmatch(r"app-(\d+)\.apk", n)
            if m:
                out.append((int(m.group(1)), os.path.join(d, n)))
    if os.path.isfile(ws.path("app.apk")):
        out.append((-1, ws.path("app.apk")))          # the current one, version unknown
    out.sort(reverse=True)
    return out


def make_patches(ws, build, log=print, only_current=False):
    """{from_sha256: patch bytes} from the kept older APKs to this build.
    only_current: a test build: just from the public version and from the
    previous test build (what testers have; spares the router's disk)."""
    import apkdelta
    out = {}
    history = apk_history(ws)
    if only_current:
        history = [h for h in history if h[0] == -1]
        if os.path.isfile(ws.path(BETA_APK)):
            history.insert(0, (-2, ws.path(BETA_APK)))
    for _, path in history:
        try:
            with open(path, "rb") as f:
                old = f.read()
        except OSError:
            continue
        old_sha = hashlib.sha256(old).hexdigest()
        if old_sha == build.sha256 or old_sha in out:
            continue
        try:
            patch = apkdelta.make_best_patch(old, build.apk, log)
        except (ValueError, zipfile.BadZipFile) as e:
            log("⚠ وصله از %s ساخته نشد: %s" % (os.path.basename(path), e))
            if os.path.dirname(path) == ws.path("apks"):
                try:
                    os.remove(path)          # a damaged copy; no use keeping it
                except OSError:
                    pass
            continue
        if len(patch) <= PATCH_MAX_SHARE * len(build.apk):
            out[old_sha] = patch
        if len(out) >= APK_HISTORY:
            break
    return out


def tester_hashes(names):
    """What the config lists for test builds: not the usernames themselves."""
    out = []
    for n in names:
        n = str(n).strip().lower()
        if n:
            h = hashlib.sha256(("pv-tester\n" + n).encode()).hexdigest()[:16]
            if h not in out:
                out.append(h)
    return out


def router_urls(cfg, path):
    return [u.replace("/v1/config", path) for u in cfg.get("config_urls", []) if u.endswith("/v1/config")]


BETA_APK, BETA_PATCHES, BETA_WIN = "beta.apk", "patches-beta", "beta-win.exe"


def patch_name(from_sha):
    return from_sha[:16] + ".pvdl"


def patch_entries(cfg, patches, beta=False):
    """app_update.patches of the config (the bytes themselves go to the router)."""
    bases = router_urls(cfg, "/v1/patch-beta/" if beta else "/v1/patch/")
    return [{"from_sha256": f, "sha256": hashlib.sha256(b).hexdigest(), "size": len(b),
             "urls": [base + patch_name(f) for base in bases]} for f, b in patches.items()]


def prepare_release(ws, build, version_code, version_name, notes, public_repo=None, patches=None,
                    testers=None, min_version=0):
    """Returns (new_config_dict, envelope_text). Nothing is written yet.
    testers: a test build, offered only to these usernames (app_update_beta);
    the public version stays as it is."""
    cfg = ws.load_config()
    if public_repo:
        # make sure installed apps learn the mirror while the router still works
        urls = cfg.setdefault("config_urls", [])
        for u in mirror_urls(public_repo):
            if u not in urls:
                urls.append(u)
    old = int(cfg.get("app_update", {}).get("version_code", 0))
    if version_code <= old:
        raise ReleaseError("شماره‌ی نسخه (%d) باید از آخرین نسخه‌ی منتشرشده (%d) بزرگ‌تر باشد."
                           % (version_code, old))
    beta = testers is not None
    if beta and not tester_hashes(testers):
        raise ReleaseError("برای نسخه‌ی آزمایشی، یوزرهای تست را در تنظیمات (⚙) وارد کنید.")
    urls = router_urls(cfg, "/v1/beta.apk" if beta else "/v1/app.apk")
    if not urls:
        raise ReleaseError("در config.json هیچ آدرس config_urls با /v1/config نیست.")
    entry = {
        "version_code": version_code,
        "version_name": version_name or "1.0.%d" % version_code,
        "urls": urls,
        "sha256": build.sha256,
        "size": len(build.apk),
        "notes": notes.strip(),
    }
    if patches:
        entry["patches"] = patch_entries(cfg, patches, beta)
    if beta:
        entry["testers"] = tester_hashes(testers)
        cfg["app_update_beta"] = entry
    else:
        cfg["app_update"] = entry
        if int((cfg.get("app_update_beta") or {}).get("version_code", 0)) <= version_code:
            cfg.pop("app_update_beta", None)      # published, or older than the public one
    refresh_beta_urls(ws, cfg, app=not beta)
    if cfg.get("windows_update"):
        # the Windows build goes to the router with the APK; without our copy it cannot stay listed
        if local_win(ws, cfg["windows_update"]) is None:
            cfg.pop("windows_update")
        else:
            cfg["windows_update"]["urls"] = [u.replace("/v1/config", "/v1/win.exe")
                                             for u in cfg.get("config_urls", []) if u.endswith("/v1/config")]
    return sign(ws, cfg, min_version)


def sign(ws, cfg, min_version=0):
    # min_version: the router already has a newer number (an earlier
    # release reached it but was not saved here, e.g. the disk was full)
    cfg["version"] = max(int(cfg.get("version", 0)) + 1, int(min_version or 0))
    cfg = sc.normalise(cfg)
    errors = sc.check_config(cfg)
    if errors:
        raise ReleaseError("config.json مشکل دارد:\n" + "\n".join(errors))

    payload = json.dumps(cfg, ensure_ascii=False, separators=(",", ":")).encode()
    d = ws.private_key()
    sig = sc.sign(d, payload)
    if not sc.verify(sc.public_der(d), payload, sig):
        raise ReleaseError("امضا ساخته شد ولی بررسی آن ناموفق بود.")
    envelope = json.dumps({"payload": base64.b64encode(payload).decode(),
                           "sig": base64.b64encode(sig).decode()})
    return cfg, envelope


def refresh_beta_urls(ws, cfg, app=True):
    """Test builds stay listed only while their files are in the workspace;
    their URLs follow the router in config_urls[0]."""
    b = cfg.get("app_update_beta") if app else None
    if b:
        b["urls"] = router_urls(cfg, "/v1/beta.apk")
        if b.get("patches"):
            b["patches"] = patch_entries(cfg, local_patches(ws, b, beta=True), beta=True)
            if not b["patches"]:
                b.pop("patches")
    w = cfg.get("windows_update_beta")
    if w:
        w["urls"] = router_urls(cfg, "/v1/beta-win.exe")


def local_patches(ws, upd, beta=False):
    """{from_sha256: bytes} of the config's patches still in the workspace."""
    out = {}
    for p in upd.get("patches") or []:
        try:
            with open(os.path.join(ws.path(BETA_PATCHES if beta else "patches"), patch_name(p["from_sha256"])),
                      "rb") as f:
                b = f.read()
        except OSError:
            continue
        if hashlib.sha256(b).hexdigest() == p.get("sha256"):
            out[p["from_sha256"]] = b
    return out


WIN_ARTIFACT = "PersianVPN-Windows"


class WinBuild:
    """The Windows app from GitHub (artifact PersianVPN-Windows): the app,
    its engine (the service checks it against engine_sha256) and the build number."""

    def __init__(self, exe, engine, version_code, name=""):
        self.exe, self.engine, self.version_code, self.name = exe, engine, version_code, name
        self.sha256 = hashlib.sha256(exe).hexdigest()
        self.engine_sha256 = hashlib.sha256(engine).hexdigest()


def read_windows_build(path):
    try:
        with zipfile.ZipFile(path) as z:
            names = {os.path.basename(n): n for n in z.namelist()}
            if not {"PersianVPN.exe", "pvwin.exe", "version.txt"} <= set(names):
                raise ReleaseError("این فایل، خروجی «PersianVPN-Windows» از GitHub نیست.")
            code = int(z.read(names["version.txt"]).decode().strip())
            return WinBuild(z.read(names["PersianVPN.exe"]), z.read(names["pvwin.exe"]), code,
                            os.path.basename(path))
    except (zipfile.BadZipFile, ValueError, OSError) as e:
        raise ReleaseError("فایل نسخه‌ی ویندوز خوانده نشد: %s" % e)


def local_win(ws, wupd, beta=False):
    base = BETA_WIN if beta else "win.exe"
    for name in (base + ".new", base):     # .new: being published right now
        try:
            with open(ws.path(name), "rb") as f:
                data = f.read()
        except OSError:
            continue
        if hashlib.sha256(data).hexdigest() == wupd.get("sha256"):
            return data
    return None


class Body(bytes):
    """All files for the router in order; .parts keeps them apart so a router
    that already holds some (umstatus "partial") gets only the others."""
    parts = ()


def local_files(ws, cfg, new=None):
    """Every file the config names, in the order the router takes them
    (APK, its patches, Windows build, then the same for the test builds),
    as one body; b"" when any is missing (the router then has to have them
    all). new: bytes not saved yet, {"apk"|"beta_apk": bytes,
    "patches"|"beta_patches": {from_sha256: bytes}}."""
    new = new or {}
    parts = []

    def apk_part(upd, name, beta):
        key = "beta_apk" if beta else "apk"
        if key in new:
            apk = new[key]
        else:
            with open(ws.path(name), "rb") as f:
                apk = f.read()
        if hashlib.sha256(apk).hexdigest() != upd["sha256"]:
            raise KeyError(name)
        have = new.get("beta_patches" if beta else "patches")
        if have is None:
            have = local_patches(ws, upd, beta)
        return [apk] + [have[p["from_sha256"]] for p in upd.get("patches") or []]

    def win_part(wupd, beta):
        win = local_win(ws, wupd, beta)
        if win is None:
            raise KeyError("win")
        return [win]

    try:
        if cfg.get("app_update"):
            parts += apk_part(cfg["app_update"], "app.apk", False)
        if cfg.get("windows_update"):
            parts += win_part(cfg["windows_update"], False)
        if cfg.get("app_update_beta"):
            parts += apk_part(cfg["app_update_beta"], BETA_APK, True)
        if cfg.get("windows_update_beta"):
            parts += win_part(cfg["windows_update_beta"], True)
    except (OSError, KeyError):
        return b""
    body = Body(b"".join(parts))
    body.parts = parts
    return body


def prepare_config_only(ws, public_repo=None, with_patches=True, win=None, win_notes="", win_testers=None,
                        min_version=0):
    """New signed config with the same app version: for a server change, or a
    new Windows build (win; a test build for win_testers when given)."""
    cfg = ws.load_config()
    if public_repo:
        urls = cfg.setdefault("config_urls", [])
        for u in mirror_urls(public_repo):
            if u not in urls:
                urls.append(u)
    upd = cfg.get("app_update")
    if upd:
        # the APK is served by the router in config_urls[0]; keep it pointing there
        upd["urls"] = [u.replace("/v1/config", "/v1/app.apk") for u in cfg.get("config_urls", [])
                       if u.endswith("/v1/config")]
        if upd.get("patches"):
            have = local_patches(ws, upd)
            if have and with_patches:
                upd["patches"] = patch_entries(cfg, have)
            else:
                upd.pop("patches")
    if win is not None:
        entry = {"version_code": win.version_code, "version_name": "1.0.%d" % win.version_code,
                 "sha256": win.sha256, "size": len(win.exe),
                 "engine_sha256": win.engine_sha256, "notes": win_notes.strip()}
        if win_testers is not None:
            if not tester_hashes(win_testers):
                raise ReleaseError("برای نسخه‌ی آزمایشی، یوزرهای تست را در تنظیمات (⚙) وارد کنید.")
            entry["testers"] = tester_hashes(win_testers)
            cfg["windows_update_beta"] = entry
        else:
            cfg["windows_update"] = entry
            if int((cfg.get("windows_update_beta") or {}).get("version_code", 0)) <= win.version_code:
                cfg.pop("windows_update_beta", None)
    if cfg.get("windows_update"):
        cfg["windows_update"]["urls"] = router_urls(cfg, "/v1/win.exe")
    refresh_beta_urls(ws, cfg)
    return sign(ws, cfg, min_version)


def _write_patches(d, patches):
    os.makedirs(d, exist_ok=True)
    keep = {patch_name(f) for f in patches}
    for n in os.listdir(d):
        if n not in keep:
            os.remove(os.path.join(d, n))
    for f, b in patches.items():
        with open(os.path.join(d, patch_name(f)), "wb") as out:
            out.write(b)


def save_local(ws, cfg, envelope, build, patches=None, beta=False):
    """Called only after the router accepted the release. beta: build is the
    test build (beta.apk; the public app.apk and its history stay)."""
    if beta:
        with open(ws.path(BETA_APK), "wb") as f:
            f.write(build.apk)
        _write_patches(ws.path(BETA_PATCHES), patches or {})
        build = patches = None
    try:
        prev = int(ws.load_config().get("app_update", {}).get("version_code", 0))
    except (ReleaseError, OSError, ValueError):
        prev = 0
    tmp = ws.path("config.json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
    os.replace(tmp, ws.path("config.json"))
    with open(ws.path(sc.SIGNED_FILE), "w", encoding="utf-8") as f:
        f.write(envelope)
    if build is not None:
        os.makedirs(ws.path("apks"), exist_ok=True)
        if os.path.isfile(ws.path("app.apk")):
            # the previous version stays to make the next patches from
            name = "app-%d.apk" % prev
            os.replace(ws.path("app.apk"), os.path.join(ws.path("apks"), name))
        with open(ws.path("app.apk"), "wb") as f:
            f.write(build.apk)
        for _, path in apk_history(ws)[APK_HISTORY + 1:]:
            if os.path.basename(path) != "app.apk":
                os.remove(path)
    if patches is not None:
        _write_patches(ws.path("patches"), patches)
    # test builds no longer listed: their files go
    if not cfg.get("app_update_beta"):
        for name in (BETA_APK, BETA_PATCHES):
            p = ws.path(name)
            if os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)
            elif os.path.isfile(p):
                os.remove(p)
    if not cfg.get("windows_update_beta") and os.path.isfile(ws.path(BETA_WIN)):
        os.remove(ws.path(BETA_WIN))


# ------------------------------------------------------------------ router

ROUTER_ERRORS = {
    "bad_signature": "روتر امضا را نپذیرفت. کلید عمومی روی روتر با کلید خصوصی شما یکی نیست.",
    "not_newer": "روتر نسخه‌ی جدیدتری از این تنظیمات دارد.",
    "publish_not_configured": "انتشار روی روتر فعال نیست: فایل config_key.public.txt در پوشه‌ی umstatus نیست.",
    "apk_mismatch": "فایل APK در مسیر خراب شد. دوباره امتحان کنید.",
    "apk_size_mismatch": "حجم APK با تنظیمات امضاشده یکی نیست.",
    "busy": "یک انتشار دیگر در حال انجام است.",
    "too_many_attempts": "تعداد تلاش‌های ناموفق زیاد بود؛ چند دقیقه بعد امتحان کنید.",
    "old_umstatus": "سرویس umstatus روتر قدیمی است و نسخه‌ی آزمایشی را نمی‌شناسد؛ "
                    "از تب «سرویس‌ها و بات» آن را به‌روز کنید و دوباره امتحان کنید.",
}


class RouterClient:
    """Talks to umstatus over HTTPS, trusting only the pinned certificate."""

    def __init__(self, config, timeout=30):
        urls = config.get("config_urls") or config.get("status_urls") or []
        if not urls:
            raise ReleaseError("آدرس سرویس روتر در config.json نیست.")
        u = urllib.parse.urlsplit(urls[0])
        self.host, self.port = u.hostname, u.port or 443
        self.pins = {p.replace(":", "").lower() for p in config.get("status_pins", [])}
        self.timeout = timeout

    def _connect(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE      # the pin below is the check
        conn = http.client.HTTPSConnection(self.host, self.port, context=ctx, timeout=self.timeout)
        try:
            conn.connect()
        except (OSError, socket.timeout) as e:
            raise ReleaseError("اتصال به روتر (%s:%s) برقرار نشد: %s" % (self.host, self.port, e))
        der = conn.sock.getpeercert(binary_form=True)
        if self.pins and hashlib.sha256(der).hexdigest() not in self.pins:
            conn.close()
            raise ReleaseError("گواهی روتر با اثر انگشت ثبت‌شده یکی نیست؛ برای امنیت ارسال انجام نشد.")
        return conn

    def health(self):
        conn = self._connect()
        try:
            conn.request("GET", "/health")
            return conn.getresponse().status == 200
        finally:
            conn.close()

    def _call(self, envelope, body, dry_run, progress=None):
        conn = self._connect()
        try:
            conn.putrequest("POST", "/v1/publish")
            conn.putheader("X-Config", base64.b64encode(envelope.encode()).decode())
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(len(body)))
            if dry_run:
                conn.putheader("X-Dry-Run", "1")
            conn.endheaders()
            sent, step = 0, 64 * 1024
            while sent < len(body):
                conn.send(body[sent:sent + step])
                sent = min(len(body), sent + step)
                if progress:
                    progress(sent, len(body))
            resp = conn.getresponse()
            data = json.loads(resp.read() or b"{}")
        except (OSError, socket.timeout, ValueError) as e:
            raise ReleaseError("ارسال به روتر قطع شد: %s" % e)
        finally:
            conn.close()
        if resp.status != 200:
            err = data.get("error", "HTTP %d" % resp.status)
            ex = ReleaseError(ROUTER_ERRORS.get(err, "روتر خطا داد: %s" % err))
            ex.code = err
            ex.data = data
            raise ex
        return data

    def publish(self, envelope, apk, progress=None, need=None):
        # ask first (signature, version, router set up) so a rejection is
        # reported clearly instead of cutting a half-sent upload
        probe = self._call(envelope, b"", dry_run=True)
        if need and need not in (probe.get("features") or []):
            ex = ReleaseError(ROUTER_ERRORS["old_umstatus"])
            ex.code = "old_umstatus"
            raise ex
        if getattr(apk, "parts", None) and "partial" in (probe.get("features") or []):
            # only what the router does not hold yet: less upload, less disk on the router
            have = set(probe.get("have") or [])
            apk = b"".join(p for p in apk.parts if hashlib.sha256(p).hexdigest() not in have)
        return self._call(envelope, apk, dry_run=False, progress=progress)

    def download(self, path, progress=None):
        """A file the router serves (/v1/app.apk ...), or None when it has none."""
        conn = self._connect()
        try:
            conn.request("GET", path)
            resp = conn.getresponse()
            if resp.status != 200:
                resp.read()
                return None
            total = int(resp.getheader("Content-Length") or 0)
            chunks, got = [], 0
            while True:
                b = resp.read(256 * 1024)
                if not b:
                    break
                chunks.append(b)
                got += len(b)
                if progress and total:
                    progress(got, total)
            return b"".join(chunks)
        except (OSError, socket.timeout) as e:
            raise ReleaseError("دریافت %s از روتر قطع شد: %s" % (path, e))
        finally:
            conn.close()


def sync_workspace(ws, log=print, progress=None, client=None):
    """The published files the config names but this workspace lacks (a
    new computer or the phone), from the router: patches for the next
    version are made from them, so users keep small downloads.
    Returns the names fetched."""
    cfg = ws.load_config()
    items = [("app_update", "app.apk", "/v1/app.apk"), ("app_update_beta", BETA_APK, "/v1/beta.apk"),
             ("windows_update", "win.exe", "/v1/win.exe"), ("windows_update_beta", BETA_WIN, "/v1/beta-win.exe")]
    want = []
    for key, name, path in items:
        sha = (cfg.get(key) or {}).get("sha256")
        if not sha:
            continue
        try:
            with open(ws.path(name), "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() == sha:
                    continue
        except OSError:
            pass
        want.append((name, path, sha))
    if not want:
        return []
    client = client or RouterClient(cfg, timeout=120)
    got = []
    for name, path, sha in want:
        log("دریافت %s از روتر (پایه‌ی وصله‌ها)…" % name)
        data = client.download(path, progress)
        if data is None or hashlib.sha256(data).hexdigest() != sha:
            log("⚠ %s روی روتر نبود یا با تنظیمات یکی نیست." % name)
            continue
        with open(ws.path(name) + ".tmp", "wb") as f:
            f.write(data)
        os.replace(ws.path(name) + ".tmp", ws.path(name))
        got.append(name)
    return got


# ------------------------------------------------------------------ GitHub

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHubClient:
    API = "https://api.github.com"

    def __init__(self, token, repo, api=None, opener=None):
        self.token = token.strip()
        self.repo = repo.strip().strip("/")
        self.api = (api or self.API).rstrip("/")
        self.opener = opener or urllib.request.build_opener()
        self.noredirect = urllib.request.build_opener(_NoRedirect)

    def _req(self, method, path, body=None, opener=None):
        req = urllib.request.Request(self.api + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "PersianVPN-Release")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            return (opener or self.opener).open(req, timeout=60)
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                return e
            if e.code == 401:
                raise ReleaseError("توکن GitHub معتبر نیست یا منقضی شده است.")
            if e.code in (403, 404):
                raise ReleaseError("توکن GitHub به مخزن %s دسترسی کافی ندارد (%d)." % (self.repo, e.code))
            raise ReleaseError("GitHub خطا داد: HTTP %d" % e.code)
        except (urllib.error.URLError, OSError) as e:
            raise ReleaseError("اتصال به GitHub برقرار نشد: %s" % e)

    def check(self):
        with self._req("GET", "/repos/%s" % self.repo) as r:
            return json.loads(r.read())["full_name"]

    def put_file(self, path, content, message):
        sha = None
        try:
            with self._req("GET", "/repos/%s/contents/%s" % (self.repo, path)) as r:
                sha = json.loads(r.read()).get("sha")
        except ReleaseError:
            pass   # file does not exist yet
        body = {"message": message, "content": base64.b64encode(content).decode()}
        if sha:
            body["sha"] = sha
        with self._req("PUT", "/repos/%s/contents/%s" % (self.repo, path), body) as r:
            return json.loads(r.read())["commit"]["sha"]

    def latest_build(self):
        """Newest unexpired persian-vpn-N artifact: (number, artifact dict) or None."""
        with self._req("GET", "/repos/%s/actions/artifacts?per_page=50" % self.repo) as r:
            arts = json.loads(r.read()).get("artifacts", [])
        best = None
        for a in arts:
            m = BUILD_RE.fullmatch(a.get("name", ""))
            if m and not a.get("expired"):
                n = int(m.group(1))
                if best is None or n > best[0]:
                    best = (n, a)
        return best

    def latest_windows(self):
        """Newest unexpired PersianVPN-Windows artifact of the main branch, or None."""
        with self._req("GET", "/repos/%s/actions/artifacts?name=%s&per_page=30"
                       % (self.repo, WIN_ARTIFACT)) as r:
            arts = json.loads(r.read()).get("artifacts", [])
        arts = [a for a in arts if a.get("name") == WIN_ARTIFACT and not a.get("expired")
                and (a.get("workflow_run") or {}).get("head_branch", "main") == "main"]
        return max(arts, key=lambda a: a.get("created_at", "")) if arts else None

    def download_artifact(self, artifact, dest_dir, progress=None):
        # GitHub answers with a redirect to signed storage; follow it WITHOUT
        # our token (the storage host rejects foreign Authorization headers).
        resp = self._req("GET", "/repos/%s/actions/artifacts/%d/zip" % (self.repo, artifact["id"]),
                         opener=self.noredirect)
        location = resp.headers.get("Location")
        if not location:
            raise ReleaseError("GitHub آدرس دانلود فایل بیلد را نداد.")
        path = os.path.join(dest_dir, "%s.zip" % artifact["name"])
        try:
            with urllib.request.urlopen(location, timeout=120) as r, open(path, "wb") as f:
                total = int(r.headers.get("Content-Length") or 0)
                done = 0
                for chunk in iter(lambda: r.read(64 * 1024), b""):
                    f.write(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, total)
        except (urllib.error.URLError, OSError) as e:
            raise ReleaseError("دانلود فایل بیلد ناموفق بود: %s" % e)
        return path


# ------------------------------------------------------------------ whole flow

def router_ahead(e):
    """The router's config number when it refused ours as not newer, else 0."""
    if getattr(e, "code", "") == "not_newer":
        try:
            return int(getattr(e, "data", {}).get("current_version", 0))
        except (TypeError, ValueError):
            return 0
    return 0


AHEAD_MSG = ("روتر تنظیمات %d را دارد (انتشار قبلی به روتر رسید ولی اینجا ذخیره نشد)؛ "
             "با شماره‌ی %d دوباره ارسال می‌شود.")


def _needs(cfg):
    return "beta" if cfg.get("app_update_beta") or cfg.get("windows_update_beta") else None


def release(ws, build, version_code, version_name, notes,
            send_router=True, github=None, public_github=None, log=print, progress=None, testers=None):
    """Sign, publish to the router, save locally, update GitHub.

    The local config.json changes only after the router accepted the
    release, so a failed attempt can simply be repeated.
    """
    ws.check()
    patches = make_patches(ws, build, log, only_current=testers is not None)
    if patches:
        log("وصله‌های به‌روزرسانی سبک: %s" % "، ".join(
            "%.1f MB" % (len(b) / 1048576) for b in patches.values()))
    beta = testers is not None
    log("امضای تنظیمات %s %d…" % ("نسخه‌ی آزمایشی" if beta else "نسخه‌ی", version_code))
    pub = public_github.repo if public_github else None
    cfg, envelope = prepare_release(ws, build, version_code, version_name, notes, pub, patches, testers)
    log("✓ امضا شد (نسخه‌ی تنظیمات %d)" % cfg["version"])

    def body_for(cfg, patches):
        new = {"beta_apk": build.apk, "beta_patches": patches} if beta else {"apk": build.apk, "patches": patches}
        body = local_files(ws, cfg, new)
        if not body:
            raise ReleaseError("فایل‌های نسخه‌ی فعلی در پوشه‌ی کاری کامل نیست؛ "
                               "یک بار «انتشار فقط تنظیمات سرور» را بزنید.")
        return body

    if send_router:
        log("ارسال به روتر…")
        try:
            try:
                body = RouterClient(cfg).publish(envelope, body_for(cfg, patches), progress, need=_needs(cfg))
            except ReleaseError as e:
                ahead = router_ahead(e)
                if not ahead:
                    raise
                log(AHEAD_MSG % (ahead, ahead + 1))
                cfg, envelope = prepare_release(ws, build, version_code, version_name, notes, pub, patches,
                                                testers, ahead + 1)
                body = RouterClient(cfg).publish(envelope, body_for(cfg, patches), progress, need=_needs(cfg))
        except ReleaseError as e:
            if beta or not patches or getattr(e, "code", "") != "apk_size_mismatch":
                raise
            # umstatus on the router is older than patches: plain release
            log("⚠ سرویس umstatus روتر قدیمی است و وصله نمی‌پذیرد (از تب سرویس‌ها به‌روزش کنید)؛ "
                "این نسخه بدون وصله منتشر می‌شود.")
            patches = {}
            cfg, envelope = prepare_release(ws, build, version_code, version_name, notes, pub)
            body = RouterClient(cfg).publish(envelope, body_for(cfg, patches), progress)
        log("✓ روتر نسخه‌ی %d را پذیرفت" % body["version"])

    save_local(ws, cfg, envelope, build, patches, beta=beta)
    log("✓ فایل‌ها در پوشه‌ی کاری ذخیره شدند")

    if github is not None:
        log("ارسال تنظیمات به GitHub…")
        github.put_file(ASSET_PATH, envelope.encode(),
                        "Release %sapp %s (config v%d) [skip ci]"
                        % ("test " if beta else "", (cfg["app_update_beta"] if beta else cfg["app_update"])
                           ["version_name"], cfg["version"]))
        log("✓ GitHub به‌روز شد")

    if public_github is not None:
        # the release is already live; a failure here is reported, not fatal
        log("ارسال تنظیمات به مخزن عمومی (پشتیبان)…")
        try:
            public_github.put_file(PUBLIC_FILE, encode_public(envelope).encode(),
                                   "config v%d" % cfg["version"])
            log("✓ مخزن عمومی به‌روز شد")
        except ReleaseError as e:
            log("⚠ مخزن عمومی به‌روز نشد: %s" % e)
            cfg["_public_failed"] = str(e)
    return cfg


def release_config_only(ws, send_router=True, github=None, public_github=None,
                        log=print, progress=None, win=None, win_notes="", win_testers=None):
    """Publish changed server settings (config.json) without a new app version,
    or with a new Windows build (win).

    Sent to the router named in the NEW config (the new server), together
    with the current APK (and Windows build) from the workspace, so a
    freshly set-up router can serve updates too.
    """
    ws.check()
    win_name = BETA_WIN if win_testers is not None else "win.exe"
    if win is not None:
        cur = (ws.load_config().get("windows_update") or {}).get("version_code", 0)
        if win.version_code <= int(cur):
            raise ReleaseError("نسخه‌ی ویندوز %d از نسخه‌ی منتشرشده (%d) جدیدتر نیست." % (win.version_code, cur))
        with open(ws.path(win_name + ".new"), "wb") as f:
            f.write(win.exe)
    log("امضای تنظیمات سرور…")
    pub = public_github.repo if public_github else None
    cfg, envelope = prepare_config_only(ws, pub, win=win, win_notes=win_notes, win_testers=win_testers)
    log("✓ امضا شد (نسخه‌ی تنظیمات %d)" % cfg["version"])

    if send_router:
        def body_for(cfg):
            return local_files(ws, cfg)
        log("ارسال به روتر %s…" % (cfg.get("config_urls") or ["?"])[0].split("/v1/")[0])
        try:
            try:
                body = RouterClient(cfg).publish(envelope, body_for(cfg), progress, need=_needs(cfg))
            except ReleaseError as e:
                ahead = router_ahead(e)
                if not ahead:
                    raise
                log(AHEAD_MSG % (ahead, ahead + 1))
                cfg, envelope = prepare_config_only(ws, pub, win=win, win_notes=win_notes,
                                                    win_testers=win_testers, min_version=ahead + 1)
                body = RouterClient(cfg).publish(envelope, body_for(cfg), progress, need=_needs(cfg))
        except ReleaseError as e:
            if not (cfg.get("app_update") or {}).get("patches") or \
                    getattr(e, "code", "") not in ("apk_size_mismatch", "apk_required"):
                raise
            log("⚠ روتر وصله‌های به‌روزرسانی را نمی‌پذیرد یا ندارد؛ بدون وصله منتشر می‌شود.")
            cfg, envelope = prepare_config_only(ws, pub, with_patches=False, win=win, win_notes=win_notes,
                                                win_testers=win_testers)
            body = RouterClient(cfg).publish(envelope, body_for(cfg), progress)
        log("✓ روتر نسخه‌ی %d را پذیرفت" % body["version"])

    if win is not None:
        os.replace(ws.path(win_name + ".new"), ws.path(win_name))
    save_local(ws, cfg, envelope, None)
    log("✓ فایل‌ها در پوشه‌ی کاری ذخیره شدند")

    if github is not None:
        log("ارسال تنظیمات به GitHub…")
        github.put_file(ASSET_PATH, envelope.encode(),
                        "Server settings (config v%d) [skip ci]" % cfg["version"])
        log("✓ GitHub به‌روز شد")

    if public_github is not None:
        log("ارسال تنظیمات به مخزن عمومی (پشتیبان)…")
        try:
            public_github.put_file(PUBLIC_FILE, encode_public(envelope).encode(),
                                   "config v%d" % cfg["version"])
            log("✓ مخزن عمومی به‌روز شد")
        except ReleaseError as e:
            log("⚠ مخزن عمومی به‌روز نشد: %s" % e)
            cfg["_public_failed"] = str(e)
    return cfg


# ------------------------------------------------------------------ test builds

def beta_status(ws):
    """(app test build entry or None, Windows test build entry or None)."""
    cfg = ws.load_config()
    return cfg.get("app_update_beta"), cfg.get("windows_update_beta")


def promote_beta(ws, send_router=True, github=None, public_github=None, log=print, progress=None):
    """The tested app build, unchanged, for everyone."""
    upd = ws.load_config().get("app_update_beta")
    if not upd:
        raise ReleaseError("نسخه‌ی آزمایشی اندرویدی منتشر نشده است.")
    try:
        with open(ws.path(BETA_APK), "rb") as f:
            apk = f.read()
    except OSError:
        raise ReleaseError("فایل نسخه‌ی آزمایشی در پوشه‌ی کاری نیست.")
    if hashlib.sha256(apk).hexdigest() != upd["sha256"]:
        raise ReleaseError("فایل نسخه‌ی آزمایشی در پوشه‌ی کاری با نسخه‌ی منتشرشده یکی نیست.")
    build = Build(apk, int(upd["version_code"]), BETA_APK)
    return release(ws, build, build.version_code, upd.get("version_name", ""), upd.get("notes", ""),
                   send_router, github, public_github, log, progress)


def promote_win_beta(ws, send_router=True, github=None, public_github=None, log=print, progress=None):
    """The tested Windows build, unchanged, for everyone."""
    w = ws.load_config().get("windows_update_beta")
    if not w:
        raise ReleaseError("نسخه‌ی آزمایشی ویندوز منتشر نشده است.")
    exe = local_win(ws, w, beta=True)
    if exe is None:
        raise ReleaseError("فایل نسخه‌ی آزمایشی ویندوز در پوشه‌ی کاری نیست.")
    win = WinBuild(exe, b"", int(w["version_code"]))
    win.engine_sha256 = w["engine_sha256"]
    return release_config_only(ws, send_router, github, public_github, log, progress, win=win,
                               win_notes=w.get("notes", ""))
