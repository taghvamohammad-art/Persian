"""Backup of the release tool itself: its settings (with the passwords,
tokens and Linux server keys in plain form) and the workspace files that
cannot be made again (config.json, the signing key).

The secrets in settings.json are locked to this Windows user (DPAPI), so a
copy of that file is useless on another computer; this file, locked with a
password instead, can be imported anywhere. It is made by hand
(export) and with every automatic router backup (with the backup password,
next to the router backups: locally and in the private GitHub repository).
"""

import base64
import datetime as _dt
import json
import os

import backup as bk
import settings as st
from publisher import ReleaseError

FORMAT = "pv-tool-settings"
TOOL_ID = "tool"                       # its folder / GitHub tag prefix among the backups
WORKSPACE_FILES = ("config.json", "config_key.private.json", "config_key.public.txt")


def snapshot(settings):
    """Everything to rebuild the tool elsewhere, secrets in plain form."""
    routers = []
    for r in settings.routers:
        r = dict(r)
        if r.get("params"):
            r["params"] = st.decrypt_blob(r["params"]) or {}
        routers.append(r)
    files = {}
    for name in WORKSPACE_FILES:
        path = os.path.join(settings.workspace or "", name)
        if settings.workspace and os.path.isfile(path):
            with open(path, "rb") as f:
                files[name] = base64.b64encode(f.read()).decode()
    return {"format": FORMAT, "version": 1,
            "created": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "settings": {"workspace": settings.workspace, "repo": settings.repo,
                         "public_repo": settings.public_repo, "token": settings.token,
                         "backup_repo": settings.backup_repo, "backup_password": settings.backup_password,
                         "auto_backup": settings.auto_backup, "backup_hours": settings.backup_hours,
                         "routers": routers},
            "files": files}


def export_bytes(settings, password):
    if not password:
        raise ReleaseError("برای خروجی گرفتن رمز لازم است.")
    return bk.encrypt(json.dumps(snapshot(settings), ensure_ascii=False).encode("utf-8"), password)


def read(blob, password):
    try:
        data = json.loads(bk.decrypt(blob, password).decode("utf-8"))
    except ValueError:
        raise ReleaseError("این فایل، خروجی تنظیمات برنامه نیست.")
    if data.get("format") != FORMAT:
        raise ReleaseError("این فایل بکاپ یک روتر است، نه تنظیمات برنامه.")
    return data


def apply(data, settings, workspace):
    """Put an export in place: workspace files into `workspace`, settings
    into `settings` (saved, secrets locked to this computer again).
    Existing workspace files are kept as .bak."""
    os.makedirs(workspace, exist_ok=True)
    written = []
    for name, b64 in (data.get("files") or {}).items():
        if name not in WORKSPACE_FILES:
            continue
        path = os.path.join(workspace, name)
        raw = base64.b64decode(b64)
        if os.path.isfile(path):
            with open(path, "rb") as f:
                if f.read() == raw:
                    written.append(name)
                    continue
            os.replace(path, path + ".bak")
        with open(path + ".tmp", "wb") as f:
            f.write(raw)
        os.replace(path + ".tmp", path)
        written.append(name)
    s = data.get("settings") or {}
    settings.workspace = workspace
    for key in ("repo", "public_repo", "token", "backup_repo", "backup_password", "auto_backup", "backup_hours"):
        if key in s:
            setattr(settings, key, s[key])
    settings.routers = []
    for r in s.get("routers", []):
        r = {k: r.get(k, "") for k in st.ROUTER_FIELDS}
        r["port"] = int(r["port"] or 22)
        r["role"] = r["role"] or "main"
        r["params"] = st.encrypt_blob(r["params"]) if isinstance(r["params"], dict) else (r["params"] or "")
        settings.routers.append(r)
    settings.save()
    return written


def auto_backup(settings, log=print, github=None):
    """With the router backups: the tool's own settings, locked with the
    backup password, kept like a router's backups (local and GitHub)."""
    blob = export_bytes(settings, settings.backup_password)
    name = "%s-%s%s" % (TOOL_ID, bk.stamp(), bk.EXT)
    local = bk.LocalStore(settings.backup_dir())
    local.save(TOOL_ID, name, blob)
    local.prune(TOOL_ID)
    where = "محلی"
    if github is not None:
        store = bk.GitHubStore(github)
        store.upload(TOOL_ID, name, blob, note="Release tool settings (encrypted with the backup password)")
        store.prune(TOOL_ID)
        where += " و GitHub"
    log("✓ تنظیمات خود برنامه هم بکاپ شد (%s)." % where)
    return name
