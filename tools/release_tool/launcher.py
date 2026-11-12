"""Entry point of the .exe: runs the newer code from "get new features"
(see selfupdate.py) when there is one, otherwise the code inside the .exe.
Kept tiny on purpose: this file itself is never replaced by an update."""

import importlib.abc
import importlib.util
import os
import sys
import traceback


class _CodeFolder(importlib.abc.MetaPathFinder):
    """Top-level modules from the code folder win over the .exe's copies."""

    def __init__(self, folder):
        self.folder = folder

    def find_spec(self, name, path=None, target=None):
        if "." in name:
            return None
        f = os.path.join(self.folder, name + ".py")
        return importlib.util.spec_from_file_location(name, f) if os.path.isfile(f) else None


def _forget(folder):
    for name, mod in list(sys.modules.items()):
        if (getattr(mod, "__file__", None) or "").startswith(folder):
            del sys.modules[name]


def main():
    import selfupdate
    folder = None
    if "--builtin" not in sys.argv:
        folder = selfupdate.usable()
    finder = None
    if folder:
        finder = _CodeFolder(folder)
        sys.meta_path.insert(0, finder)
        os.environ["PV_CODE_DIR"] = folder
        sys.modules.pop("selfupdate", None)          # the new copy from now on
    try:
        import release_gui
    except Exception:
        if not finder:
            raise
        # the new code does not even load: back to the .exe's own copy
        selfupdate.mark_bad(folder, traceback.format_exc())
        sys.meta_path.remove(finder)
        os.environ.pop("PV_CODE_DIR", None)
        _forget(folder)
        import release_gui
    return release_gui.main()


if __name__ == "__main__":
    sys.exit(main())
