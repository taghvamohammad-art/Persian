import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import selfupdate as su  # noqa: E402


class FakeGitHub:
    """Answers the few API calls the updater makes, from {repo path: bytes}."""

    def __init__(self, files, actions=True, run=57):
        self.files, self.actions, self.run = files, actions, run
        self.blob_calls = 0
        self.sha = "c0ffee" * 6 + "abcd"

    def blobs(self):
        return {su.git_blob_sha(v): v for v in self.files.values()}

    def open(self, req, timeout=None):
        url = req.full_url.split("api.github.com", 1)[1]
        if "/actions/workflows/" in url:
            if not self.actions:
                raise urllib.error.HTTPError(url, 403, "no", {}, None)
            body = {"workflow_runs": [{"head_sha": self.sha, "run_number": self.run}]}
        elif url.endswith("/commits/main"):
            body = {"sha": self.sha}
        elif "/git/trees/" in url:
            body = {"truncated": False, "tree": [
                {"path": p, "type": "blob", "sha": su.git_blob_sha(v), "size": len(v)}
                for p, v in self.files.items()] + [{"path": "tools", "type": "tree", "sha": "x"}]}
        elif "/git/blobs/" in url:
            self.blob_calls += 1
            return io.BytesIO(self.blobs()[url.rsplit("/", 1)[1]])
        else:
            raise urllib.error.HTTPError(url, 404, "no", {}, None)
        return io.BytesIO(json.dumps(body).encode())


def repo_files(gui=b"def main():\n    return 0\n", base=b"1\n"):
    return {
        "tools/release_tool/release_gui.py": gui,
        "tools/release_tool/linux.py": b"X = 1\n",
        "tools/release_tool/test_linux.py": b"ignored\n",
        "tools/release_tool/it/chr.py": b"ignored\n",
        "tools/release_tool/BASE": base,
        "tools/sign_config.py": b"Y = 2\n",
        "server/linux/pv_agent.py": b"Z = 3\n",
        "server/linux/site/index.html": b"<html></html>",
        "app/src/main/Big.kt": b"ignored\n",
    }


class SelfUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.code = os.path.join(self.tmp, "code")
        self._base = su.bundled_base
        su.bundled_base = lambda: "1"

    def tearDown(self):
        su.bundled_base = self._base
        shutil.rmtree(self.tmp, ignore_errors=True)

    def updater(self, gh):
        return su.Updater("tok", "o/Persian", opener=gh, code_dir=self.code)

    def test_names(self):
        self.assertEqual(su.overlay_name("tools/release_tool/um2.py"), "um2.py")
        self.assertIsNone(su.overlay_name("tools/release_tool/test_um2.py"))
        self.assertIsNone(su.overlay_name("tools/release_tool/it/chr.py"))
        self.assertEqual(su.overlay_name("server/linux/site/index.html"), "site/index.html")
        self.assertEqual(su.overlay_name("server/umstatus/umstatus.py"), "umstatus.py")
        self.assertIsNone(su.overlay_name("server/umstatus/test_umstatus.py"))
        self.assertEqual(su.overlay_name("server/mikrotik/awgrelay.py"), "awgrelay.py")

    def test_first_then_only_changes(self):
        gh = FakeGitHub(repo_files())
        up = self.updater(gh)
        plan = up.check()
        self.assertTrue(plan.tested)
        self.assertEqual(plan.run, 57)
        self.assertEqual(sorted(c[1] for c in plan.changes),
                         ["BASE", "linux.py", "pv_agent.py", "release_gui.py", "sign_config.py", "site/index.html"])
        up.apply(plan, log=lambda *_: None)
        self.assertEqual(su.usable(self.code, "1"), self.code)
        with open(os.path.join(self.code, "site", "index.html"), "rb") as f:
            self.assertEqual(f.read(), b"<html></html>")
        self.assertTrue(up.check().up_to_date)

        gh.files["tools/release_tool/linux.py"] = b"X = 2\n"          # one file changed, one removed
        del gh.files["tools/sign_config.py"]
        gh.blob_calls = 0
        plan = up.check()
        self.assertEqual([c[1] for c in plan.changes], ["linux.py"])
        self.assertEqual(plan.removed, ["sign_config.py"])
        up.apply(plan, log=lambda *_: None)
        self.assertEqual(gh.blob_calls, 2)                           # BASE (check) + linux.py
        with open(os.path.join(self.code, "linux.py"), "rb") as f:
            self.assertEqual(f.read(), b"X = 2\n")
        self.assertFalse(os.path.exists(os.path.join(self.code, "sign_config.py")))

    def test_new_exe_needed(self):
        plan = self.updater(FakeGitHub(repo_files(base=b"2\n"))).check()
        self.assertTrue(plan.needs_new_exe)
        with self.assertRaises(su.UpdateError):
            self.updater(FakeGitHub(repo_files(base=b"2\n"))).apply(plan)
        self.assertFalse(os.path.exists(self.code))

    def test_broken_file_keeps_old_code(self):
        up = self.updater(FakeGitHub(repo_files()))
        up.apply(up.check(), log=lambda *_: None)
        gh = FakeGitHub(repo_files(gui=b"def main(:\n"))
        up = self.updater(gh)
        with self.assertRaises(su.UpdateError):
            up.apply(up.check(), log=lambda *_: None)
        with open(os.path.join(self.code, "release_gui.py"), "rb") as f:
            self.assertIn(b"return 0", f.read())

    def test_without_actions_access_uses_main(self):
        plan = self.updater(FakeGitHub(repo_files(), actions=False)).check()
        self.assertFalse(plan.tested)
        self.assertIsNone(plan.run)

    def test_bad_or_other_exe_not_used(self):
        up = self.updater(FakeGitHub(repo_files()))
        up.apply(up.check(), log=lambda *_: None)
        self.assertIsNone(su.usable(self.code, "2"))
        su.mark_bad(self.code, "x")
        self.assertIsNone(su.usable(self.code, "1"))


class LauncherTests(unittest.TestCase):
    """The launcher runs the code folder, and falls back when it does not load."""

    def run_launcher(self, gui_in_folder):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        exe = os.path.join(tmp, "exe")
        os.makedirs(exe)
        for f in ("launcher.py", "selfupdate.py"):
            shutil.copy(os.path.join(HERE, f), exe)
        with open(os.path.join(exe, "BASE"), "w") as f:
            f.write("1\n")
        with open(os.path.join(exe, "release_gui.py"), "w") as f:
            f.write("def main():\n    print('builtin')\n    return 0\n")
        code = os.path.join(tmp, "appdata", "PersianVPNRelease", "code")
        os.makedirs(code)
        with open(os.path.join(code, "release_gui.py"), "w") as f:
            f.write(gui_in_folder)
        with open(os.path.join(code, "helper.py"), "w") as f:
            f.write("WHO = 'folder'\n")
        with open(os.path.join(code, "manifest.json"), "w") as f:
            json.dump({"base": "1", "files": {}}, f)
        env = dict(os.environ, APPDATA=os.path.join(tmp, "appdata"))
        out = subprocess.run([sys.executable, os.path.join(exe, "launcher.py")], env=env, cwd=tmp,
                             capture_output=True, text=True, timeout=60)
        return out, code

    def test_runs_new_code(self):
        out, _ = self.run_launcher("import helper\ndef main():\n    print('new', helper.WHO)\n    return 0\n")
        self.assertEqual(out.stdout.strip(), "new folder", out.stderr)

    def test_falls_back_when_new_code_fails(self):
        out, code = self.run_launcher("import helper\nraise RuntimeError('boom')\n")
        self.assertEqual(out.stdout.strip(), "builtin", out.stderr)
        self.assertTrue(os.path.exists(os.path.join(code, su.BAD)))


if __name__ == "__main__":
    unittest.main()
