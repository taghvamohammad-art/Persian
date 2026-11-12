"""CI: a "get new features" code folder made from this checkout, with a
marker in release_gui.py, so the built .exe can be checked to load it."""
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools", "release_tool"))
import selfupdate as su  # noqa: E402

dst = sys.argv[1]
files = {}
for path in subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).split():
    name = su.overlay_name(path)
    if name:
        out = os.path.join(dst, *name.split("/"))
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copy(os.path.join(ROOT, *path.split("/")), out)
        files[name] = "ci"
with open(os.path.join(dst, "release_gui.py"), "a", encoding="utf-8") as f:
    f.write('\nif os.environ.get("PV_MARK"):\n    open(os.environ["PV_MARK"], "w").write(__file__)\n')
with open(os.path.join(ROOT, "tools", "release_tool", "BASE")) as f:
    base = f.read().strip()
with open(os.path.join(dst, "manifest.json"), "w") as f:
    json.dump({"sha": "ci", "run": 0, "base": base, "files": files}, f)
print(len(files), "files")
