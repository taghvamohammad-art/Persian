"""Full backups of the routers: everything needed to rebuild one elsewhere.

One backup is an encrypted file (.pvbk) holding a zip:

  manifest.json      router, time, RouterOS version, parts, cert passphrase
  export.rsc         /export show-sensitive terse: the whole configuration
  info/*.txt         resource, packages, license, interfaces, addresses, routes
  certs/*.p12|*.crt  every certificate (with private key when it has one)
  um/*               User Manager database (users, profiles, usage history)
  system.backup      binary backup (same-hardware restore only, a last resort)
  files/...          the router's files: umstatus, the bot, scripts' data...

Encryption: AES-256-GCM, key from the backup password with scrypt. The
password is the only way back in, so the owner keeps it outside this PC.
"""

import datetime as _dt
import hashlib
import io
import json
import os
import re
import secrets
import zipfile

from publisher import ReleaseError
from routeros import RouterOSError, SSHRouter, q

MAGIC = b"PVBK1\n"
TMP = "pvbk-"
EXT = ".pvbk"
SCRYPT = dict(n=2 ** 15, r=8, p=1)
SKIP_EXT = (".npk",)
MAX_FILE = 200 * 1024 * 1024

INFO = {
    "identity": "/system identity print",
    "resource": "/system resource print",
    "packages": "/system package print",
    "license": "/system license print",
    "routerboard": "/system routerboard print",
    "interfaces": "/interface print detail without-paging",
    "addresses": "/ip address print detail without-paging",
    "routes": "/ip route print detail without-paging",
    "dns": "/ip dns print",
    "users": "/user print detail without-paging",
}


# ---------------------------------------------------------------- encryption

def _key(password, salt):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, **SCRYPT).derive(password.encode("utf-8"))


def encrypt(data, password):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not password:
        raise ReleaseError("رمز بکاپ تنظیم نشده است (⚙ تنظیمات).")
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, data, MAGIC)


def decrypt(blob, password):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not blob.startswith(MAGIC):
        raise ReleaseError("این فایل، بکاپ این برنامه نیست.")
    salt, nonce, ct = blob[6:22], blob[22:34], blob[34:]
    try:
        return AESGCM(_key(password, salt)).decrypt(nonce, ct, MAGIC)
    except InvalidTag:
        raise ReleaseError("رمز بکاپ اشتباه است (یا فایل خراب شده).")


# ---------------------------------------------------------------- reading a router

def parse_version(resource_text):
    m = re.search(r"version:\s*([0-9][0-9.]*)", resource_text)
    return m.group(1) if m else ""


def _find_created(router, prefix):
    """Names of files the router created whose name starts with prefix."""
    return [p for p, _ in router.walk("", skip=lambda p: "/" in p) if p.startswith(prefix)]


def collect(router, log=print, progress=None):
    """Read everything from a connected router. Returns (manifest, parts dict)."""
    parts = {}
    manifest = {"format": 1, "created": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
                "host": router.host, "parts": {}, "warnings": []}

    def warn(text):
        manifest["warnings"].append(text)
        log("⚠ " + text)

    log("خواندن مشخصات روتر…")
    for name, cmd in INFO.items():
        try:
            parts["info/%s.txt" % name] = router.run(cmd).encode()
        except RouterOSError:
            pass   # e.g. no routerboard on CHR
    res = parts.get("info/resource.txt", b"").decode()
    manifest["routeros"] = parse_version(res)
    pk = parts.get("info/packages.txt", b"").decode()
    manifest["has_user_manager"] = "user-manager" in pk
    manifest["has_container"] = "container" in pk

    log("خواندن همه‌ی تنظیمات (export)…")
    parts["export.rsc"] = router.run("/export show-sensitive terse", timeout=600).encode()

    # leftovers of an interrupted backup
    router.run('/file remove [find where name~"^%s"]' % TMP, check=False)

    log("گواهی‌ها…")
    passphrase = secrets.token_urlsafe(24)
    manifest["cert_passphrase"] = passphrase
    certs = []
    for i, line in enumerate(router.lines(
            ':foreach c in=[/certificate find] do={:put ([/certificate get $c name] . "\\t" . '
            '[/certificate get $c private-key] . "\\t" . [/certificate get $c fingerprint])}')):
        name, _, rest = line.partition("\t")
        haskey, _, fp = rest.partition("\t")
        haskey = haskey.strip() == "true"
        fname = "%scert%d_" % (TMP, i)
        cmd = '/certificate export-certificate [find where name=%s] file-name=%s ' % (q(name), fname)
        cmd += ("type=pkcs12 export-passphrase=%s" % q(passphrase)) if haskey else "type=pem"
        try:
            router.run(cmd)
        except RouterOSError as e:
            warn("گواهی %s خوانده نشد: %s" % (name, e))
            continue
        files = _find_created(router, fname)
        for f in files:
            parts["certs/%d-%s" % (i, f[len(fname):].lstrip("_.") or "bin")] = router.get(f)
        certs.append({"index": i, "name": name, "private_key": haskey, "fingerprint": fp.strip(),
                      "files": ["%d-%s" % (i, f[len(fname):].lstrip("_.") or "bin") for f in files]})
    manifest["certificates"] = certs

    if manifest["has_user_manager"]:
        log("دیتابیس یوزر منیجر…")
        try:
            router.run("/user-manager database save name=%sum" % TMP, timeout=600)
            files = _find_created(router, TMP + "um")
            if not files:
                warn("فایل دیتابیس یوزر منیجر ساخته نشد.")
            for f in files:
                parts["um/" + f[len(TMP):]] = router.get(f)
            manifest["um_files"] = [f[len(TMP):] for f in files]
        except RouterOSError as e:
            warn("دیتابیس یوزر منیجر ذخیره نشد: %s" % e)

    log("بکاپ باینری…")
    try:
        router.run("/system backup save name=%ssys dont-encrypt=yes" % TMP, timeout=600)
        for f in _find_created(router, TMP + "sys"):
            parts["system.backup"] = router.get(f)
    except RouterOSError as e:
        warn("بکاپ باینری ساخته نشد: %s" % e)

    log("فایل‌های روتر…")
    roots = set()
    if manifest["has_container"]:
        try:
            for line in router.lines(':foreach c in=[/container find] do={:put [/container get $c root-dir]}'):
                roots.add(line.strip().strip("/"))
        except RouterOSError:
            pass
    manifest["container_roots"] = sorted(r for r in roots if r)

    def skip(p):
        base = p.rsplit("/", 1)[-1]
        return (base.startswith(TMP) or p.endswith(SKIP_EXT) or p in roots
                or any(p.startswith(r + "/") for r in roots if r))

    files = list(router.walk("", skip))
    total = sum(s for _, s in files) or 1
    done = 0
    for p, size in files:
        if size > MAX_FILE:
            warn("فایل %s خیلی بزرگ است و در بکاپ نیامد." % p)
            continue
        try:
            parts["files/" + p] = router.get(p)
        except (IOError, OSError) as e:
            warn("فایل %s خوانده نشد: %s" % (p, e))
        done += size
        if progress:
            progress(done, total)

    router.run('/file remove [find where name~"^%s"]' % TMP, check=False)

    for name, data in parts.items():
        manifest["parts"][name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    return manifest, parts


def pack(manifest, parts):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=1))
        for name, data in parts.items():
            z.writestr(name, data)
    return buf.getvalue()


def unpack(zip_bytes):
    """(manifest, parts) of a decrypted backup, every part checked against its hash."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        manifest = json.loads(z.read("manifest.json"))
        parts = {n: z.read(n) for n in z.namelist() if n != "manifest.json"}
    for name, meta in manifest.get("parts", {}).items():
        if name not in parts or hashlib.sha256(parts[name]).hexdigest() != meta["sha256"]:
            raise ReleaseError("بکاپ ناقص است: %s" % name)
    return manifest, parts


def open_backup(path_or_bytes, password):
    blob = path_or_bytes
    if isinstance(path_or_bytes, str):
        with open(path_or_bytes, "rb") as f:
            blob = f.read()
    return unpack(decrypt(blob, password))


# ---------------------------------------------------------------- storage

def slug(text):
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")
    return s or "router"


def stamp(now=None):
    return (now or _dt.datetime.now()).strftime("%Y%m%d-%H%M%S")


STAMP_RE = re.compile(r"(\d{8}-\d{6})")


def keep_set(names, now=None, recent=28, daily_days=30):
    """Which backups to keep: the newest `recent`, plus the newest of each day
    for the last `daily_days` days. names carry a YYYYmmdd-HHMMSS stamp."""
    now = now or _dt.datetime.now()
    dated = []
    for n in names:
        m = STAMP_RE.search(n)
        if m:
            dated.append((_dt.datetime.strptime(m.group(1), "%Y%m%d-%H%M%S"), n))
    dated.sort(reverse=True)
    keep = {n for _, n in dated[:recent]}
    seen_days = set()
    for t, n in dated:
        if (now - t).days < daily_days and t.date() not in seen_days:
            seen_days.add(t.date())
            keep.add(n)
    keep.update(n for n in names if not STAMP_RE.search(n))   # never touch unknown files
    return keep


class LocalStore:
    def __init__(self, root):
        self.root = root

    def dir(self, router_id):
        return os.path.join(self.root, slug(router_id))

    def save(self, router_id, name, blob):
        d = self.dir(router_id)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, name)
        with open(path + ".tmp", "wb") as f:
            f.write(blob)
        os.replace(path + ".tmp", path)
        return path

    def list(self, router_id):
        d = self.dir(router_id)
        if not os.path.isdir(d):
            return []
        return sorted((f for f in os.listdir(d) if f.endswith(EXT)), reverse=True)

    def prune(self, router_id, now=None):
        names = self.list(router_id)
        keep = keep_set(names, now)
        for n in names:
            if n not in keep:
                os.remove(os.path.join(self.dir(router_id), n))


class GitHubStore:
    """Backups as GitHub release assets of the private backup repository.

    Release assets, unlike committed files, really free their space when
    deleted, so old backups do not grow the repository forever.
    """

    def __init__(self, gh):
        self.gh = gh

    def _json(self, method, path, body=None):
        with self.gh._req(method, path, body) as r:
            raw = r.read()
        return json.loads(raw) if raw else None

    def _ensure_initialised(self):
        repo = self._json("GET", "/repos/%s" % self.gh.repo)
        if repo.get("private") is False:
            raise ReleaseError("مخزن بکاپ (%s) عمومی است! بکاپ فقط در مخزن خصوصی ذخیره می‌شود." % self.gh.repo)
        try:
            self._json("GET", "/repos/%s/commits?per_page=1" % self.gh.repo)
        except ReleaseError:
            # an empty repository cannot have releases: give it a first commit
            self.gh.put_file("README.md", b"Encrypted router backups (Persian VPN release tool).\n",
                             "Initialise backup repository")
        return repo.get("default_branch") or "main"

    def upload(self, router_id, name, blob, note="", progress=None):
        import urllib.request
        branch = self._ensure_initialised()
        tag = "bk-%s-%s" % (slug(router_id), STAMP_RE.search(name).group(1))
        rel = self._json("POST", "/repos/%s/releases" % self.gh.repo,
                         {"tag_name": tag, "target_commitish": branch, "name": tag,
                          "body": note, "draft": False, "prerelease": True})
        up = "https://uploads.github.com" if self.gh.api == self.gh.API else self.gh.api
        url = "%s/repos/%s/releases/%d/assets?name=%s" % (up, self.gh.repo, rel["id"], name)
        req = urllib.request.Request(url, data=blob, method="POST")
        req.add_header("Authorization", "Bearer " + self.gh.token)
        req.add_header("Content-Type", "application/octet-stream")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("User-Agent", "PersianVPN-Release")
        try:
            with self.gh.opener.open(req, timeout=600) as r:
                r.read()
        except Exception as e:
            try:
                self.delete_tag(tag, rel["id"])
            except ReleaseError:
                pass
            raise ReleaseError("آپلود بکاپ به GitHub ناموفق بود: %s" % e)
        return tag

    def releases(self, router_id=None):
        out, page = [], 1
        prefix = "bk-%s-" % slug(router_id) if router_id else "bk-"
        while True:
            batch = self._json("GET", "/repos/%s/releases?per_page=100&page=%d" % (self.gh.repo, page)) or []
            out += [r for r in batch if r.get("tag_name", "").startswith(prefix)]
            if len(batch) < 100:
                return out
            page += 1

    def delete_tag(self, tag, release_id):
        self._json("DELETE", "/repos/%s/releases/%d" % (self.gh.repo, release_id))
        try:
            self._json("DELETE", "/repos/%s/git/refs/tags/%s" % (self.gh.repo, tag))
        except ReleaseError:
            pass

    def prune(self, router_id, now=None):
        rels = self.releases(router_id)
        keep = keep_set([r["tag_name"] for r in rels], now)
        for r in rels:
            if r["tag_name"] not in keep:
                self.delete_tag(r["tag_name"], r["id"])

    def download(self, release):
        import urllib.request
        assets = release.get("assets") or []
        if not assets:
            raise ReleaseError("این بکاپ فایل ندارد.")
        req = urllib.request.Request(assets[0]["url"])
        req.add_header("Authorization", "Bearer " + self.gh.token)
        req.add_header("Accept", "application/octet-stream")
        req.add_header("User-Agent", "PersianVPN-Release")
        with urllib.request.urlopen(req, timeout=600) as r:
            return r.read()


# ---------------------------------------------------------------- one backup

def backup_router(router_cfg, password, local, github=None, log=print, progress=None, connect=None):
    """Backup one router to the local store (and GitHub). Returns a result dict."""
    rid = router_cfg["id"]
    conn = (connect or (lambda c: SSHRouter(c["host"], c.get("port", 22), c.get("user", ""),
                                            c.get("password", ""), c.get("hostkey", ""))))(router_cfg)
    log("اتصال به %s (%s)…" % (router_cfg.get("name") or rid, router_cfg["host"]))
    with conn as r:
        hostkey = getattr(r, "seen_hostkey", "")
        manifest, parts = collect(r, log, progress)
    manifest.update(router_id=rid, router_name=router_cfg.get("name", ""), role=router_cfg.get("role", "main"),
                    ssh_port=router_cfg.get("port", 22))
    blob = encrypt(pack(manifest, parts), password)
    name = "%s-%s%s" % (slug(rid), stamp(), EXT)
    path = local.save(rid, name, blob)
    local.prune(rid)
    size_mb = len(blob) / 1048576
    log("✓ بکاپ ذخیره شد: %s (%.1f MB)" % (name, size_mb))
    result = {"ok": True, "router": rid, "file": path, "size": len(blob), "time": manifest["created"],
              "warnings": manifest["warnings"], "hostkey": hostkey, "github": None}
    if github is not None:
        log("ارسال بکاپ به GitHub…")
        store = GitHubStore(github)
        note = "%s — %s — RouterOS %s" % (router_cfg.get("name", rid), router_cfg["host"], manifest["routeros"])
        result["github"] = store.upload(rid, name, blob, note)
        store.prune(rid)
        log("✓ بکاپ در GitHub ذخیره شد")
    return result


# ---------------------------------------------------------------- all routers (manual or scheduled)

def backup_all(settings, log=print, progress=None, only=None, connect=None, github_factory=None):
    """Backup every router; returns {router_id: result}. Remembers new SSH
    host keys and the outcome (shown by the GUI, also after scheduled runs)."""
    import settings as st
    from publisher import GitHubClient
    status = st.load_status()
    results = {}
    local = LocalStore(settings.backup_dir())
    changed = False
    for rc in settings.routers:
        if only and rc["id"] not in only:
            continue
        gh = None
        if settings.token and settings.backup_repo:
            gh = (github_factory or GitHubClient)(settings.token, settings.backup_repo)
        try:
            res = backup_router(rc, settings.backup_password, local, gh, log, progress, connect)
        except ReleaseError as e:
            res = {"ok": False, "router": rc["id"], "error": str(e),
                   "time": _dt.datetime.now().astimezone().isoformat(timespec="seconds")}
            log("✗ %s: %s" % (rc.get("name") or rc["id"], e))
        except Exception as e:      # keep going with the other routers
            res = {"ok": False, "router": rc["id"], "error": "خطای پیش‌بینی‌نشده: %s" % e,
                   "time": _dt.datetime.now().astimezone().isoformat(timespec="seconds")}
            log("✗ %s: %s" % (rc.get("name") or rc["id"], e))
        if res.get("ok") and res.get("hostkey") and not rc.get("hostkey"):
            rc["hostkey"] = res["hostkey"]
            changed = True
        prev = status.get(rc["id"], {})
        entry = {"last_try": res["time"], "ok": res["ok"], "error": res.get("error", ""),
                 "warnings": res.get("warnings", []), "github": res.get("github")}
        entry["last_ok"] = res["time"] if res["ok"] else prev.get("last_ok", "")
        entry["last_file"] = res.get("file") or prev.get("last_file", "")
        status[rc["id"]] = entry
        results[rc["id"]] = res
    if changed:
        settings.save()
    st.save_status(status)
    return results


def run_scheduled():
    """Entry point of the Windows scheduled task (no window)."""
    import settings as st
    s = st.Settings.load()
    os.makedirs(st.APP_DIR, exist_ok=True)
    with open(st.LOG_FILE, "a", encoding="utf-8") as f:
        def log(line):
            f.write("%s %s\n" % (_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), line))
            f.flush()
        if not s.routers:
            log("هیچ روتری تعریف نشده است.")
            return 0
        res = backup_all(s, log)
    _trim_log(st.LOG_FILE)
    return 0 if all(r["ok"] for r in res.values()) else 1


def _trim_log(path, keep=2000):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
        if len(lines) > keep:
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(lines[-keep:])
    except OSError:
        pass


# ---------------------------------------------------------------- Windows scheduled task

TASK_NAME = "PersianVPN Backup"


def schedule_command():
    import sys
    if getattr(sys, "frozen", False):
        return '"%s" --backup-all' % sys.executable
    pyw = sys.executable.replace("python.exe", "pythonw.exe")
    return '"%s" "%s" --backup-all' % (pyw, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                       "release_gui.py"))


def set_schedule(enabled, hours=6):
    """Create/remove the scheduled task (current user, runs while logged on:
    the saved passwords are encrypted for this Windows user)."""
    import subprocess
    if enabled:
        args = ["schtasks", "/Create", "/F", "/TN", TASK_NAME, "/TR", schedule_command(),
                "/SC", "HOURLY", "/MO", str(int(hours))]
    else:
        args = ["schtasks", "/Delete", "/F", "/TN", TASK_NAME]
    p = subprocess.run(args, capture_output=True, text=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if p.returncode != 0 and enabled:
        raise ReleaseError("ساخت زمان‌بندی ویندوز ناموفق بود:\n%s" % (p.stderr or p.stdout).strip())
