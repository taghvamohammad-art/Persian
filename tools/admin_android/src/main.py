"""Entry of the Persian Admin app (flet build apk).

The tool's modules are copied next to this file at build time (see the
admin-android workflow). "Get new features" puts newer copies of them in
the app's data folder; the launcher runs those, like on Windows.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("FLET_APP_STORAGE_DATA") or os.path.join(HERE, ".data")
os.makedirs(DATA, exist_ok=True)
os.environ["APPDATA"] = DATA                      # settings.py / selfupdate.py keep their files here
os.environ["PV_ENTRY"] = "admin_app"
os.environ["PV_BASE_FILE"] = "BASE_ANDROID"
os.environ["PV_WORKFLOW"] = "admin-android.yml"
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import launcher  # noqa: E402

launcher.main()
