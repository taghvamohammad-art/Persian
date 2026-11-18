"""New features without downloading the whole .exe again.

The .exe carries Python, Qt and the libraries; the tool's own code is a
few hundred KB of .py files. "Get new features" fetches only the source
files that changed (from the newest commit whose release-tool CI passed,
through the GitHub token already in the settings) into
%APPDATA%\\PersianVPNRelease\\code; the launcher loads them in place of the
copies inside the .exe. Every file is checked against its git hash, the
set is compiled before it replaces the old one, and if it fails to start
the .exe's own copy is used.

A new .exe is still needed when the libraries inside it change; the
number in BASE says which .exe a set of files needs.
"""

import hashlib
import json
import os
import py_compile
import shutil
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
APP_DIR = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"), "PersianVPNRelease")
CODE_DIR = os.path.join(APP_DIR, "code")
MANIFEST = "manifest.json"
BAD = "BAD"
WORKFLOW = os.environ.get("PV_WORKFLOW", "release-tool.yml")
# the phone version shares the code but has its own entry and compatibility number
ENTRY = os.environ.get("PV_ENTRY", "release_gui")
BASE_FILE = os.environ.get("PV_BASE_FILE", "BASE")
API = "https://api.github.com"


class UpdateError(Exception):
    pass


def overlay_name(path):
    """Where a repository file goes in the code folder (None: not part of the tool)."""
    name = path.rsplit("/", 1)[-1]
    if path.startswith("tools/release_tool/") and path.count("/") == 2:
        if name == "BASE" or (name.endswith(".py") and not name.startswith("test_")):
            return name
        return None
    if path.startswith("tools/") and path.count("/") == 1 and name.endswith(".py"):
        return name
    if path in ("server/umstatus/umstatus.py", "server/linux/pv_agent.py", "server/linux/pvcreds.py",
                "server/mikrotik/awgrelay.py"):
        return name
    if path == "tools/admin_android/BASE":
        return "BASE_ANDROID"
    if path == "tools/admin_android/src/admin_app.py":
        return "admin_app.py"
    if path.startswith("server/linux/site/"):
        return "site/" + path[len("server/linux/site/"):]
    return None


def git_blob_sha(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def bundled_base():
    for d in (getattr(sys, "_MEIPASS", None), HERE):
        if d and os.path.isfile(os.path.join(d, BASE_FILE)):
            with open(os.path.join(d, BASE_FILE)) as f:
                return f.read().strip()
    return "0"


def manifest(code_dir=CODE_DIR):
    try:
        with open(os.path.join(code_dir, MANIFEST)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def usable(code_dir=CODE_DIR, base=None):
    """The code folder the launcher may load, or None."""
    m = manifest(code_dir)
    if not m or os.path.exists(os.path.join(code_dir, BAD)):
        return None
    if m.get("base") != (base or bundled_base()):
        return None                           # made for another .exe
    if not os.path.isfile(os.path.join(code_dir, ENTRY + ".py")):
        return None
    return code_dir


def version_text(code_dir=CODE_DIR):
    m = manifest(code_dir) if usable(code_dir) else None
    if not m:
        return "نسخه‌ی داخل برنامه"
    return "کد #%s (%s)" % (m.get("run") or "?", m.get("sha", "")[:7])


def mark_bad(code_dir, why):
    try:
        with open(os.path.join(code_dir, BAD), "w", encoding="utf-8") as f:
            f.write(why)
    except OSError:
        pass


def revert(code_dir=CODE_DIR):
    shutil.rmtree(code_dir, ignore_errors=True)


class Plan:
    def __init__(self, sha, run, tested, base, changes, removed, current):
        self.sha, self.run, self.tested, self.base = sha, run, tested, base
        self.changes = changes          # [(repo path, overlay name, blob sha, size)]
        self.removed = removed          # [overlay name]
        self.current = current          # manifest in use, or None

    @property
    def needs_new_exe(self):
        return self.base != bundled_base()

    @property
    def up_to_date(self):
        return not self.changes and not self.removed

    @property
    def size(self):
        return sum(c[3] for c in self.changes)


class Updater:
    def __init__(self, token, repo, api=API, opener=None, code_dir=CODE_DIR):
        if not token or not repo:
            raise UpdateError("برای دریافت امکانات جدید، توکن GitHub و نام مخزن در تنظیمات لازم است.")
        self.token, self.repo, self.api = token.strip(), repo.strip().strip("/"), api.rstrip("/")
        self.opener = opener or urllib.request.build_opener()
        self.code_dir = code_dir

    def _get(self, path, raw=False):
        req = urllib.request.Request(self.api + path)
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("Accept", "application/vnd.github.raw" if raw else "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "PersianVPN-Release")
        try:
            with self.opener.open(req, timeout=60) as r:
                data = r.read()
        except urllib.error.HTTPError as e:
            raise UpdateError("GitHub خطا داد (HTTP %d)." % e.code) from e
        except (urllib.error.URLError, OSError) as e:
            raise UpdateError("اتصال به GitHub برقرار نشد: %s" % e) from e
        return data if raw else json.loads(data)

    def latest(self):
        """(commit, CI run number, tested?): the newest commit whose tool CI passed;
        main's head when the token may not read Actions."""
        try:
            runs = self._get("/repos/%s/actions/workflows/%s/runs?branch=main&status=success&per_page=1"
                             % (self.repo, WORKFLOW)).get("workflow_runs") or []
            if runs:
                return runs[0]["head_sha"], runs[0].get("run_number"), True
        except UpdateError:
            pass
        return self._get("/repos/%s/commits/main" % self.repo)["sha"], None, False

    def check(self):
        sha, run, tested = self.latest()
        tree = self._get("/repos/%s/git/trees/%s?recursive=1" % (self.repo, sha))
        if tree.get("truncated"):
            raise UpdateError("فهرست فایل‌های مخزن کامل نیامد.")
        files = {}
        for e in tree.get("tree", []):
            name = overlay_name(e.get("path", "")) if e.get("type") == "blob" else None
            if name:
                files[name] = (e["path"], e["sha"], int(e.get("size") or 0))
        if ENTRY + ".py" not in files or BASE_FILE not in files:
            raise UpdateError("کد ابزار در این نسخه‌ی مخزن پیدا نشد.")
        base = self._get("/repos/%s/git/blobs/%s" % (self.repo, files[BASE_FILE][1]), raw=True).decode().strip()
        current = manifest(self.code_dir) if usable(self.code_dir) else None
        have = (current or {}).get("files", {})
        changes = [(p, n, s, size) for n, (p, s, size) in sorted(files.items()) if have.get(n) != s]
        removed = sorted(n for n in have if n not in files)
        return Plan(sha, run, tested, base, changes, removed, current)

    def apply(self, plan, log=print):
        """Download the changed files, check them, and swap the code folder."""
        if plan.needs_new_exe:
            raise UpdateError("این امکانات به نسخه‌ی جدید خود برنامه نیاز دارد.")
        new = self.code_dir + ".new"
        shutil.rmtree(new, ignore_errors=True)
        if plan.current:
            shutil.copytree(self.code_dir, new)
        else:
            os.makedirs(new)
        files = dict((plan.current or {}).get("files", {}))
        for i, (path, name, sha, _size) in enumerate(plan.changes, 1):
            log("دریافت %s (%d از %d)…" % (name, i, len(plan.changes)))
            data = self._get("/repos/%s/git/blobs/%s" % (self.repo, sha), raw=True)
            if git_blob_sha(data) != sha:
                shutil.rmtree(new, ignore_errors=True)
                raise UpdateError("فایل %s سالم نرسید." % name)
            dst = os.path.join(new, *name.split("/"))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(data)
            files[name] = sha
        for name in plan.removed:
            try:
                os.remove(os.path.join(new, *name.split("/")))
            except OSError:
                pass
            files.pop(name, None)
        for name in files:
            if name.endswith(".py"):
                try:
                    py_compile.compile(os.path.join(new, name), doraise=True,
                                       cfile=os.path.join(new, "__pycache__", "check.pyc"))
                except py_compile.PyCompileError as e:
                    shutil.rmtree(new, ignore_errors=True)
                    raise UpdateError("فایل %s خراب است: %s" % (name, e)) from e
        shutil.rmtree(os.path.join(new, "__pycache__"), ignore_errors=True)
        try:
            os.remove(os.path.join(new, BAD))
        except OSError:
            pass
        with open(os.path.join(new, MANIFEST), "w") as f:
            json.dump({"sha": plan.sha, "run": plan.run, "tested": plan.tested, "base": plan.base,
                       "files": files}, f, indent=1)
        old = self.code_dir + ".old"
        shutil.rmtree(old, ignore_errors=True)
        if os.path.exists(self.code_dir):
            os.rename(self.code_dir, old)
        os.rename(new, self.code_dir)
        shutil.rmtree(old, ignore_errors=True)
        return files
