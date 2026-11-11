"""Tests of the router backup (fake router over the same interface as SSH)."""

import datetime as dt
import json
import os
import re
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import backup as bk          # noqa: E402
import publisher as pb       # noqa: E402
import settings as st        # noqa: E402
from routeros import RouterOSError, check_output, q   # noqa: E402


class FakeRouter:
    """Answers the commands backup.collect sends, like RouterOS 7 does."""

    def __init__(self, host="10.0.0.1"):
        self.host = host
        self.seen_hostkey = "SHA256:fake"
        self.files = {
            "umstatus/umstatus.py": b"print('hi')",
            "umstatus/app.apk": b"APK" * 1000,
            "umbot/data/umbot.sqlite3": b"SQLITE",
            "containers/umstatus/bin/sh": b"ELF",
            "routeros-7.23.2.npk": b"NPK",
            "user-manager5/sqldb": b"live db",
        }
        self.dirs = {"skins"}
        self.commands = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def run(self, cmd, timeout=300, check=True):
        self.commands.append(cmd)
        out = self._answer(cmd)
        return check_output(cmd, out) if check else out

    def _answer(self, cmd):
        if cmd == "/system routerboard print":
            return "failure: not supported on CHR"   # check=True turns this into an error
        if cmd == "/system resource print":
            return "  version: 7.23.2 (stable)\n  board-name: CHR\n"
        if cmd == "/system package print":
            return " 0 routeros 7.23.2\n 1 container 7.23.2\n 2 user-manager 7.23.2\n"
        m = re.fullmatch(r"/system backup save name=(\S+) dont-encrypt=yes", cmd)
        if m:
            self.files[m.group(1) + ".backup"] = b"BACKUP"
            return "Configuration backup saved\n"
        if cmd.startswith("/system ") or cmd.startswith("/interface") or cmd.startswith("/ip ") \
                or cmd.startswith("/user print"):
            return "some info\n"
        if cmd == "/export show-sensitive terse":
            return "/ppp secret add name=a password=b\n/interface sstp-server server set enabled=yes\n"
        m = re.fullmatch(r'/file remove \[find where name~"\^(.+)"\]', cmd)
        if m:
            for k in [k for k in self.files if k.split("/")[-1].startswith(m.group(1)) and "/" not in k]:
                del self.files[k]
            return ""
        if cmd.startswith(":foreach c in=[/certificate find]"):
            return "CA\tfalse\taa\nserver\ttrue\tbb\n"
        m = re.fullmatch(r'/certificate export-certificate \[find where name="(.+?)"\] file-name=(\S+) (.*)', cmd)
        if m:
            ext = ".p12" if "pkcs12" in m.group(3) else ".crt"
            self.files[m.group(2) + ext] = ("cert " + m.group(1)).encode()
            return ""
        m = re.fullmatch(r"/user-manager database save name=(\S+)", cmd)
        if m:
            self.files[m.group(1) + ".umb"] = b"UMDB"
            return ""
        m = re.fullmatch(r"/system backup save name=(\S+) dont-encrypt=yes", cmd)
        if m:
            self.files[m.group(1) + ".backup"] = b"BACKUP"
            return "Configuration backup saved\n"
        if cmd.startswith(":foreach c in=[/container find]"):
            return "containers/umstatus\n"
        return "bad command name %s\n" % cmd

    def listdir(self, path=""):
        pre = path + "/" if path else ""
        names = {}
        for f, data in self.files.items():
            if f.startswith(pre):
                rest = f[len(pre):]
                head, sep, _ = rest.partition("/")
                names[head] = (bool(sep), 0 if sep else len(data))
        for d in self.dirs:
            if d.startswith(pre) and "/" not in d[len(pre):]:
                names[d[len(pre):]] = (True, 0)
        return [(n, isd, size) for n, (isd, size) in sorted(names.items())]

    def get(self, path, progress=None):
        return self.files[path]

    def walk(self, path="", skip=lambda p: False):
        from routeros import SSHRouter
        return SSHRouter.walk(self, path, skip)

    def lines(self, script):
        return [l for l in self.run(script).split("\n") if l.strip()]


class FakeReleases:
    """GitHub releases API, enough for GitHubStore."""

    def __init__(self, private=True):
        self.private = private
        self.releases = {}
        self.assets = {}
        self.commits = False
        self.next_id = 1
        gh = self

        class H(BaseHTTPRequestHandler):
            def _json(self, code, obj=None):
                data = json.dumps(obj).encode() if obj is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self):
                return self.rfile.read(int(self.headers.get("Content-Length") or 0))

            def do_GET(self):
                if self.path == "/repos/o/bk":
                    return self._json(200, {"private": gh.private, "default_branch": "main"})
                if self.path.startswith("/repos/o/bk/commits"):
                    return self._json(200, [{}]) if gh.commits else self._json(409, {})
                if self.path.startswith("/repos/o/bk/contents/"):
                    return self._json(404, {})
                if self.path.startswith("/repos/o/bk/releases?"):
                    page = int(re.search(r"[?&]page=(\d+)", self.path).group(1))
                    rels = sorted(gh.releases.values(), key=lambda r: -r["id"])
                    return self._json(200, rels[(page - 1) * 100: page * 100])
                if self.path.startswith("/asset/"):
                    data = gh.assets[int(self.path[7:])]
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    return self.wfile.write(data)
                return self._json(404, {})

            def do_PUT(self):
                self._body()
                gh.commits = True
                return self._json(201, {"commit": {"sha": "x"}})

            def do_POST(self):
                body = self._body()
                if self.path == "/repos/o/bk/releases":
                    if not gh.commits:
                        return self._json(422, {})
                    b = json.loads(body)
                    rid = gh.next_id
                    gh.next_id += 1
                    gh.releases[rid] = {"id": rid, "tag_name": b["tag_name"], "assets": []}
                    return self._json(201, gh.releases[rid])
                m = re.match(r"/repos/o/bk/releases/(\d+)/assets\?name=(.+)", self.path)
                if m:
                    rid = int(m.group(1))
                    gh.assets[rid] = body
                    gh.releases[rid]["assets"] = [{"name": m.group(2),
                                                   "url": "http://127.0.0.1:%d/asset/%d" % (gh.port, rid)}]
                    return self._json(201, {})
                return self._json(404, {})

            def do_DELETE(self):
                m = re.match(r"/repos/o/bk/releases/(\d+)$", self.path)
                if m:
                    gh.releases.pop(int(m.group(1)), None)
                return self._json(204)

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def client(self):
        return pb.GitHubClient("tok", "o/bk", api="http://127.0.0.1:%d" % self.port)


class Crypto(unittest.TestCase):
    def test_roundtrip_and_wrong_password(self):
        blob = bk.encrypt(b"secret data", "pw1")
        self.assertNotIn(b"secret", blob)
        self.assertEqual(bk.decrypt(blob, "pw1"), b"secret data")
        with self.assertRaises(pb.ReleaseError):
            bk.decrypt(blob, "pw2")
        with self.assertRaises(pb.ReleaseError):
            bk.encrypt(b"x", "")

    def test_quote(self):
        self.assertEqual(q('a"b$c\\'), '"a\\"b\\$c\\\\"')
        with self.assertRaises(RouterOSError):
            check_output("/x", "failure: no such thing")


class Collect(unittest.TestCase):
    def test_everything_collected(self):
        r = FakeRouter()
        m, parts = bk.collect(r, log=lambda *_: None)
        self.assertEqual(m["routeros"], "7.23.2")
        self.assertIn("/ppp secret add", parts["export.rsc"].decode())
        self.assertEqual(parts["um/um.umb"], b"UMDB")
        self.assertEqual(parts["system.backup"], b"BACKUP")
        self.assertEqual(parts["certs/1-p12"], b"cert server")
        self.assertEqual(parts["certs/0-crt"], b"cert CA")
        self.assertEqual([c["private_key"] for c in m["certificates"]], [False, True])
        self.assertEqual(parts["files/umstatus/umstatus.py"], b"print('hi')")
        self.assertIn("files/umbot/data/umbot.sqlite3", parts)
        self.assertNotIn("files/containers/umstatus/bin/sh", parts)    # container root skipped
        self.assertNotIn("files/routeros-7.23.2.npk", parts)
        self.assertFalse(any("pvbk-" in p for p in parts))                # temp files not copied twice
        self.assertFalse(any(k.startswith("pvbk-") for k in r.files))    # and removed from the router
        export = [c for c in r.commands if "export-certificate" in c and "pkcs12" in c][0]
        self.assertIn(m["cert_passphrase"], export)

    def test_pack_unpack_detects_tampering(self):
        m, parts = bk.collect(FakeRouter(), log=lambda *_: None)
        z = bk.pack(m, parts)
        m2, p2 = bk.unpack(z)
        self.assertEqual(p2, parts)
        m["parts"]["export.rsc"]["sha256"] = "0" * 64
        with self.assertRaises(pb.ReleaseError):
            bk.unpack(bk.pack(m, parts))


class Retention(unittest.TestCase):
    def test_keep_set(self):
        now = dt.datetime(2026, 11, 30, 12, 0, 0)
        names = []
        for d in range(60):                       # 60 days, 4 backups a day
            for h in (0, 6, 12, 18):
                t = now - dt.timedelta(days=d, hours=h)
                names.append("r1-%s.pvbk" % t.strftime("%Y%m%d-%H%M%S"))
        names.append("notes.txt")
        keep = bk.keep_set(names, now)
        self.assertIn("notes.txt", keep)
        newest = sorted(n for n in names if n.endswith(".pvbk"))[-28:]
        self.assertTrue(set(newest) <= keep)
        old = [n for n in keep if n.endswith(".pvbk") and n < "r1-20261030"]
        self.assertEqual(old, [])                 # nothing older than 30 days
        self.assertLessEqual(len(keep), 28 + 31 + 1)


class Storage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.s = st.Settings(workspace=self.tmp, token="tok")
        self.s.backup_repo = "o/bk"
        self.s.backup_password = "pass word"
        self.s.routers = [{"id": "r1", "name": "اصلی", "role": "main", "host": "10.0.0.1", "port": 2200,
                           "user": "pvtool", "password": "x", "hostkey": ""}]
        st.FILE = os.path.join(self.tmp, "settings.json")
        st.STATUS_FILE = os.path.join(self.tmp, "status.json")
        st.APP_DIR = self.tmp
        self.gh = FakeReleases()

    def test_backup_all_to_disk_and_github(self):
        router = FakeRouter()
        res = bk.backup_all(self.s, log=lambda *_: None, connect=lambda c: router,
                            github_factory=lambda t, r: self.gh.client())
        r = res["r1"]
        self.assertTrue(r["ok"], r)
        m, parts = bk.open_backup(r["file"], "pass word")
        self.assertEqual(m["router_id"], "r1")
        self.assertEqual(m["ssh_port"], 2200)
        # the router's backup and the tool's own settings
        tags = sorted(rel["tag_name"] for rel in self.gh.releases.values())
        self.assertEqual(len(tags), 2)
        self.assertTrue(tags[0].startswith("bk-r1-") and tags[1].startswith("bk-tool-"), tags)
        store = bk.GitHubStore(self.gh.client())
        m2, _ = bk.open_backup(store.download(store.releases("r1")[0]), "pass word")
        self.assertEqual(m2["created"], m["created"])
        # host key remembered, status written
        self.assertEqual(st.Settings.load().routers[0]["hostkey"], "SHA256:fake")
        self.assertTrue(st.load_status()["r1"]["ok"])

    def test_public_backup_repo_refused(self):
        self.gh.private = False
        res = bk.backup_all(self.s, log=lambda *_: None, connect=lambda c: FakeRouter(),
                            github_factory=lambda t, r: self.gh.client())
        self.assertFalse(res["r1"]["ok"])
        self.assertIn("عمومی", res["r1"]["error"])
        self.assertEqual(len(bk.LocalStore(self.s.backup_dir()).list("r1")), 1)   # local copy still made

    def test_failure_recorded_and_others_continue(self):
        self.s.routers.append(dict(self.s.routers[0], id="r2", host="10.0.0.2"))

        def connect(c):
            if c["id"] == "r1":
                raise RouterOSError("اتصال برقرار نشد")
            return FakeRouter(c["host"])
        res = bk.backup_all(self.s, log=lambda *_: None, connect=connect,
                            github_factory=lambda t, r: self.gh.client())
        self.assertFalse(res["r1"]["ok"])
        self.assertTrue(res["r2"]["ok"])
        status = st.load_status()
        self.assertIn("اتصال", status["r1"]["error"])
        self.assertEqual(status["r1"]["last_ok"], "")

    def test_settings_roundtrip(self):
        self.s.auto_backup = True
        self.s.save()
        s2 = st.Settings.load()
        self.assertEqual(s2.backup_password, "pass word")
        self.assertEqual(s2.routers[0]["port"], 2200)
        self.assertTrue(s2.auto_backup)
        with open(st.FILE) as f:
            self.assertNotIn("pass word", f.read())


if __name__ == "__main__":
    unittest.main()
