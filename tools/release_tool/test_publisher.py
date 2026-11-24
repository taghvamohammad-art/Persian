"""End-to-end tests of the release core against a real umstatus server
(HTTPS, pinned) and a fake GitHub API."""

import base64
import hashlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "server", "umstatus"))

import publisher as pb          # noqa: E402
import umstatus as um           # noqa: E402
import test_umstatus as tum     # noqa: E402


class FakeGitHub:
    def __init__(self):
        self.files = {}
        self.public_denied = False
        self.blob_auth = []
        self.artifacts = [
            {"id": 7, "name": "persian-vpn-15", "expired": False},
            {"id": 8, "name": "persian-vpn-16", "expired": False},
            {"id": 9, "name": "persian-vpn-17", "expired": True},
            {"id": 10, "name": "something-else", "expired": False},
        ]
        self.zipdata = b""
        gh = self

        class H(BaseHTTPRequestHandler):
            def _json(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path.startswith("/blob/"):
                    gh.blob_auth.append(self.headers.get("Authorization"))
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(gh.zipdata)))
                    self.end_headers()
                    self.wfile.write(gh.zipdata)
                    return
                if self.headers.get("Authorization") != "Bearer tok":
                    return self._json(401, {})
                if self.path in ("/repos/o/r", "/repos/o/pub"):
                    return self._json(200, {"full_name": self.path[7:]})
                if self.path.startswith("/repos/o/r/actions/artifacts?"):
                    return self._json(200, {"artifacts": gh.artifacts})
                if self.path == "/repos/o/r/actions/artifacts/8/zip":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:%d/blob/8" % gh.port)
                    self.end_headers()
                    return
                p = self.path[len("/repos/"):].replace("/contents/", ":", 1)
                if p in gh.files:
                    return self._json(200, {"sha": hashlib.sha1(gh.files[p]).hexdigest()})
                return self._json(404, {})

            def do_PUT(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if gh.public_denied and self.path.startswith("/repos/o/pub/"):
                    return self._json(403, {})
                p = self.path[len("/repos/"):].replace("/contents/", ":", 1)
                if p in gh.files and body.get("sha") != hashlib.sha1(gh.files[p]).hexdigest():
                    return self._json(409, {})
                gh.files[p] = base64.b64decode(body["content"])
                gh.last_message = body["message"]
                return self._json(200, {"commit": {"sha": "abc"}})

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def client(self, token="tok", repo="o/r"):
        return pb.GitHubClient(token, repo, api="http://127.0.0.1:%d" % self.port)


def apkdelta_apk(tag):
    """A small valid APK-like zip with one changing entry."""
    import io
    import zipfile
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("lib/arm64-v8a/libgojni.so", b"\0" * 200_000)
        z.writestr("classes.dex", tag * 1000)
    return b.getvalue()


class ReleaseFlow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        crt, key = os.path.join(cls.d, "c.crt"), os.path.join(cls.d, "k.key")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=t"],
                       check=True, capture_output=True)
        der = ssl.PEM_cert_to_DER_cert(open(crt).read())
        cls.pin = hashlib.sha256(der).hexdigest()
        cls.crt, cls.key = crt, key

    def setUp(self):
        # workspace = the owner's tools folder
        self.ws_dir = tempfile.mkdtemp()
        cwd = os.getcwd()
        os.chdir(self.ws_dir)
        try:
            pb.sc.cmd_genkey()
        finally:
            os.chdir(cwd)
        self.ws = pb.Workspace(self.ws_dir)

        # router: umstatus with the workspace public key
        srv = tempfile.mkdtemp()
        cfg = dict(um.DEFAULTS, cert_file=self.crt, key_file=self.key, key_passphrase="",
                   listen_host="127.0.0.1", listen_port=0,
                   app_config_file=os.path.join(srv, "app.json"),
                   app_apk_file=os.path.join(srv, "app.apk"),
                   config_pubkey_file=self.ws.path(pb.sc.PUBLIC_FILE))
        self.srv_cfg = cfg
        self.httpd = um.make_server(um.Service(tum.FakeRouter(), cfg), cfg)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        port = self.httpd.server_address[1]
        base = "https://127.0.0.1:%d" % port

        with open(os.path.join(REPO, "tools", "config.example.json"), encoding="utf-8") as f:
            conf = json.load(f)
        conf["status_urls"] = [base + "/v1/status"]
        conf["config_urls"] = [base + "/v1/config"]
        conf["status_pins"] = [self.pin]
        conf.pop("app_update", None)
        with open(self.ws.path("config.json"), "w", encoding="utf-8") as f:
            json.dump(conf, f)

        self.apk = b"PK" + os.urandom(300000)
        self.zip_path = os.path.join(self.ws_dir, "persian-vpn-16.zip")
        with zipfile.ZipFile(self.zip_path, "w") as z:
            z.writestr("app-release.apk", self.apk)
        self.gh = FakeGitHub()

    def tearDown(self):
        self.httpd.shutdown()
        self.gh.httpd.shutdown()

    def test_read_build_from_artifact_zip(self):
        b = pb.read_build(self.zip_path)
        self.assertEqual((b.version_code, b.apk), (16, self.apk))

    def test_debug_build_refused(self):
        p = os.path.join(self.ws_dir, "persian-vpn-3.zip")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("app-debug.apk", b"PKxx")
        with self.assertRaises(pb.ReleaseError):
            pb.read_build(p)

    def test_full_release(self):
        build = pb.read_build(self.zip_path)
        lines, prog = [], []
        cfg = pb.release(self.ws, build, 16, "1.0.16", "رفع قطع و وصل",
                         github=self.gh.client(), log=lines.append,
                         progress=lambda a, b: prog.append(a))
        # router serves exactly what was signed, and the APK
        with open(self.srv_cfg["app_config_file"]) as f:
            served = f.read()
        with open(self.srv_cfg["app_apk_file"], "rb") as f:
            self.assertEqual(f.read(), self.apk)
        env = json.loads(served)
        payload = json.loads(base64.b64decode(env["payload"]))
        self.assertEqual(payload["app_update"]["version_code"], 16)
        self.assertEqual(payload["app_update"]["notes"], "رفع قطع و وصل")
        self.assertEqual(payload["app_update"]["sha256"], hashlib.sha256(self.apk).hexdigest())
        # local workspace updated only now
        self.assertEqual(self.ws.load_config()["version"], cfg["version"])
        self.assertEqual(self.ws.published_version_code(), 16)
        with open(self.ws.path("app.apk"), "rb") as f:
            self.assertEqual(f.read(), self.apk)
        # GitHub got the same envelope, without triggering a build
        self.assertEqual(self.gh.files["o/r:" + pb.ASSET_PATH].decode(), served)
        self.assertIn("[skip ci]", self.gh.last_message)
        self.assertEqual(prog[-1], len(self.apk))
        # releasing the same versionCode again is refused before anything is sent
        with self.assertRaises(pb.ReleaseError):
            pb.release(self.ws, build, 16, "1.0.16", "", log=lambda *_: None)
        # a newer build replaces the file on GitHub (sha handled)
        build2 = pb.Build(b"PK" + os.urandom(1000), 17, "x")
        pb.release(self.ws, build2, 17, "", "", github=self.gh.client(), log=lambda *_: None)
        self.assertIn("1.0.17", self.gh.last_message)

    def served(self):
        with open(self.srv_cfg["app_config_file"]) as f:
            return json.loads(base64.b64decode(json.loads(f.read())["payload"]))

    def test_required_update(self):
        q = lambda *_: None
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=q)
        self.assertNotIn("min_version_code", self.served()["app_update"])
        pb.release(self.ws, pb.Build(b"PK" + os.urandom(1000), 17, "x"), 17, "", "", log=q, required=True)
        self.assertEqual(self.served()["app_update"]["min_version_code"], 17)
        # a later ordinary release keeps the requirement
        pb.release(self.ws, pb.Build(b"PK" + os.urandom(1000), 18, "x"), 18, "", "", log=q)
        self.assertEqual(self.served()["app_update"]["min_version_code"], 17)
        # the published version made required without a new build
        pb.release_config_only(self.ws, log=q, require_app=True)
        self.assertEqual(self.served()["app_update"]["min_version_code"], 18)

    def test_test_build_then_public(self):
        q = lambda *_: None
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=q)
        # no testers: refused
        beta_apk = b"PK" + os.urandom(2000)
        with self.assertRaises(pb.ReleaseError):
            pb.release(self.ws, pb.Build(beta_apk, 17, "b"), 17, "", "test", log=q, testers=[" "])
        pb.release(self.ws, pb.Build(beta_apk, 17, "b"), 17, "", "test", log=q, testers=["Mohammad", "ali"])
        cfg = self.served()
        self.assertEqual(cfg["app_update"]["version_code"], 16)          # public one untouched
        beta = cfg["app_update_beta"]
        self.assertEqual(beta["version_code"], 17)
        self.assertEqual(beta["testers"], pb.tester_hashes(["mohammad", "ALI "]))
        self.assertNotIn("mohammad", json.dumps(cfg).lower())             # names are not published
        self.assertTrue(all(u.endswith("/v1/beta.apk") for u in beta["urls"]))
        srv_dir = os.path.dirname(self.srv_cfg["app_apk_file"])
        with open(os.path.join(srv_dir, "beta.apk"), "rb") as f:
            self.assertEqual(f.read(), beta_apk)
        with open(self.srv_cfg["app_apk_file"], "rb") as f:
            self.assertEqual(f.read(), self.apk)
        # a server-settings release keeps the test build
        pb.release_config_only(self.ws, log=q)
        self.assertEqual(self.served()["app_update_beta"]["version_code"], 17)
        # promoted: the same bytes for everyone, the test entry gone
        pb.promote_beta(self.ws, log=q)
        cfg = self.served()
        self.assertEqual((cfg["app_update"]["version_code"], cfg["app_update"]["notes"]), (17, "test"))
        self.assertEqual(cfg["app_update"]["sha256"], hashlib.sha256(beta_apk).hexdigest())
        self.assertNotIn("app_update_beta", cfg)
        self.assertFalse(os.path.exists(self.ws.path(pb.BETA_APK)))
        with open(self.srv_cfg["app_apk_file"], "rb") as f:
            self.assertEqual(f.read(), beta_apk)

    def test_patches_from_skipped_test_builds(self):
        """A tester on 1.0.17 when 19 comes (18 came and went): a patch from 17 too."""
        import apkdelta
        q = lambda *_: None
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=q)
        betas = {c: b"PK" + os.urandom(3000) for c in (17, 18, 19, 20, 21)}
        real = apkdelta.make_best_patch
        apkdelta.make_best_patch = lambda old, new, log=None: b"P" + hashlib.sha256(old).digest()
        try:
            for c in (17, 18, 19):
                pb.release(self.ws, pb.Build(betas[c], c, "b"), c, "", "", log=q, testers=["mohammad"])
            self.assertEqual([c for c, _ in pb.beta_history(self.ws)], [18, 17])
            out = pb.make_patches(self.ws, pb.Build(betas[20], 20, "b"), q, only_current=True)
            want = {hashlib.sha256(b).hexdigest() for b in (betas[17], betas[18], betas[19], self.apk)}
            self.assertEqual(set(out), want)
            for c in (20, 21):
                pb.release(self.ws, pb.Build(betas[c], c, "b"), c, "", "", log=q, testers=["mohammad"])
            self.assertEqual([c for c, _ in pb.beta_history(self.ws)], [20, 19, 18])   # 3 kept
        finally:
            apkdelta.make_best_patch = real
        pb.promote_beta(self.ws, log=q)
        self.assertFalse(os.path.exists(self.ws.path(pb.BETA_OLD)))

    def test_router_gets_only_what_it_lacks(self):
        q = lambda *_: None
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=q)
        sent = []
        real = pb.RouterClient._call

        def spy(self_, envelope, body, dry_run, progress=None):
            if not dry_run:
                sent.append(len(body))
            return real(self_, envelope, body, dry_run, progress)
        pb.RouterClient._call = spy
        try:
            beta_apk = b"PK" + os.urandom(2000)
            pb.release(self.ws, pb.Build(beta_apk, 17, "b"), 17, "", "", log=q, testers=["mohammad"])
        finally:
            pb.RouterClient._call = real
        self.assertEqual(sent, [len(beta_apk)])           # the public APK was not sent again

    def test_next_test_build_patches_from_the_previous_one(self):
        q = lambda *_: None
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=q)
        first = apkdelta_apk(b"one")
        pb.release(self.ws, pb.Build(first, 17, "b"), 17, "", "", log=q, testers=["mohammad"])
        second = apkdelta_apk(b"two")
        pb.release(self.ws, pb.Build(second, 18, "b"), 18, "", "", log=q, testers=["mohammad"])
        froms = {p["from_sha256"] for p in self.served()["app_update_beta"]["patches"]}
        self.assertIn(hashlib.sha256(first).hexdigest(), froms)       # testers on the last test build

    def test_patch_from_the_version_users_have_now(self):
        """With APK_HISTORY older versions kept, the current public one was
        skipped and its users downloaded the whole app (139 -> 146)."""
        q = lambda *_: None
        apks = {}
        for v in range(20, 20 + pb.APK_HISTORY + 2):
            apks[v] = apkdelta_apk(b"v%d" % v)
            pb.release(self.ws, pb.Build(apks[v], v, "b"), v, "", "", log=q)
        last = max(apks)
        new = apkdelta_apk(b"new")
        pb.release(self.ws, pb.Build(new, last + 1, "b"), last + 1, "", "", log=q)
        froms = {p["from_sha256"] for p in self.served()["app_update"]["patches"]}
        self.assertIn(hashlib.sha256(apks[last]).hexdigest(), froms)
        self.assertEqual(len(froms), pb.APK_HISTORY)

    def test_windows_test_build(self):
        q = lambda *_: None
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=q)
        win = pb.WinBuild(b"MZ" + os.urandom(3000), b"engine", 5)
        pb.release_config_only(self.ws, log=q, win=win, win_notes="w", win_testers=["mohammad"])
        cfg = self.served()
        self.assertNotIn("windows_update", cfg)
        self.assertEqual(cfg["windows_update_beta"]["engine_sha256"], hashlib.sha256(b"engine").hexdigest())
        pb.promote_win_beta(self.ws, log=q)
        cfg = self.served()
        self.assertEqual(cfg["windows_update"]["sha256"], win.sha256)
        self.assertEqual(cfg["windows_update"]["engine_sha256"], win.engine_sha256)
        self.assertNotIn("windows_update_beta", cfg)
        with open(os.path.join(os.path.dirname(self.srv_cfg["app_apk_file"]), "win.exe"), "rb") as f:
            self.assertEqual(f.read(), win.exe)

    def test_router_failure_keeps_workspace(self):
        before = self.ws.load_config()
        os.remove(self.srv_cfg["config_pubkey_file"])     # router not set up
        with self.assertRaises(pb.ReleaseError) as ctx:
            pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=lambda *_: None)
        self.assertIn("config_key.public.txt", str(ctx.exception))
        self.assertEqual(self.ws.load_config(), before)
        self.assertFalse(os.path.exists(self.ws.path("app.apk")))

    def test_router_ahead_after_lost_local_save(self):
        q = lambda *_: None
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=q)
        before = self.ws.load_config()
        real = pb.save_local
        pb.save_local = lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
        try:
            with self.assertRaises(OSError):
                pb.release(self.ws, pb.Build(b"PK" + os.urandom(900), 17, "b"), 17, "", "", log=q,
                           testers=["mohammad"])
        finally:
            pb.save_local = real
        self.assertEqual(self.ws.load_config(), before)            # router got it, the workspace did not
        lines = []
        pb.release(self.ws, pb.Build(b"PK" + os.urandom(900), 17, "b"), 17, "", "", log=lines.append,
                   testers=["mohammad"])
        self.assertTrue(any("دوباره ارسال" in l for l in lines))
        self.assertEqual(self.served()["version"], before["version"] + 2)
        self.assertEqual(self.served()["app_update_beta"]["version_code"], 17)

    def test_stale_workspace_refused_then_adopted(self):
        """Another device published since this workspace's last release (the
        phone tool published 1.0.152 from a days-old copy: no Linux servers,
        app 116 instead of 146). Refused, then the published one is taken."""
        q = lambda *_: None
        import shutil
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=q)
        old = os.path.join(self.ws_dir, "stale-copy.json")
        shutil.copy(self.ws.path("config.json"), old)
        pb.release(self.ws, pb.Build(apkdelta_apk(b"x"), 17, "b"), 17, "", "", log=q)   # "the other device"
        shutil.copy(old, self.ws.path("config.json"))                                  # this one is behind
        with self.assertRaises(pb.ReleaseError) as ctx:
            pb.release(self.ws, pb.Build(apkdelta_apk(b"y"), 18, "b"), 18, "", "", log=q)
        self.assertIn("قدیمی", str(ctx.exception))
        with self.assertRaises(pb.ReleaseError):
            pb.release_config_only(self.ws, log=q)
        self.assertEqual(pb.adopt_published(self.ws, log=q), self.served()["version"])
        self.assertEqual(self.ws.published_version_code(), 17)
        pb.release(self.ws, pb.Build(apkdelta_apk(b"y"), 18, "b"), 18, "", "", log=q)  # now fine
        self.assertEqual(self.served()["app_update"]["version_code"], 18)

    def test_a_current_workspace_repairs_a_bad_publish(self):
        """The bad config from the old copy knows less than this workspace:
        publishing from here (to repair it) is allowed."""
        q = lambda *_: None
        import shutil
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=q)
        good = os.path.join(self.ws_dir, "good.json")
        old = os.path.join(self.ws_dir, "old.json")
        shutil.copy(self.ws.path("config.json"), old)
        pb.release(self.ws, pb.Build(apkdelta_apk(b"x"), 17, "b"), 17, "", "", log=q)
        shutil.copy(self.ws.path("config.json"), good)
        with open(old) as f:                                          # the old copy publishes (old tool,
            stale = json.load(f)                                      # no check): served as is
        _, env = pb.sign(self.ws, dict(stale, version=self.served()["version"]))
        with open(self.srv_cfg["app_config_file"], "w") as f:
            f.write(env)
        self.assertEqual(self.served()["app_update"]["version_code"], 16)
        shutil.copy(good, self.ws.path("config.json"))                # the current workspace repairs it
        pb.release_config_only(self.ws, log=q)
        self.assertEqual(self.served()["app_update"]["version_code"], 17)

    def test_cut_upload_sent_again(self):
        q, lines = (lambda *_: None), []
        real = pb.RouterClient._call
        cuts = []

        def flaky(self_, envelope, body, dry_run, progress=None):
            if not dry_run and not cuts:
                cuts.append(1)
                ex = pb.ReleaseError("ارسال به روتر قطع شد: EOF occurred in violation of protocol")
                ex.code = "cut"
                raise ex
            return real(self_, envelope, body, dry_run, progress)
        pb.RouterClient._call = flaky
        old_sleep = pb.time.sleep
        pb.time.sleep = lambda s: None
        try:
            pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=lines.append)
        finally:
            pb.RouterClient._call = real
            pb.time.sleep = old_sleep
        self.assertEqual(cuts, [1])
        self.assertTrue(any("دوباره (2 از 3)" in l for l in lines))
        self.assertEqual(self.served()["app_update"]["version_code"], 16)

    def test_pin_mismatch_refuses_to_send(self):
        conf = self.ws.load_config()
        conf["status_pins"] = ["00" * 32]
        with open(self.ws.path("config.json"), "w") as f:
            json.dump(conf, f)
        with self.assertRaises(pb.ReleaseError) as ctx:
            pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=lambda *_: None)
        self.assertIn("اثر انگشت", str(ctx.exception))
        self.assertFalse(os.path.exists(self.srv_cfg["app_apk_file"]))

    def test_github_latest_build_and_download(self):
        gh = self.gh.client()
        self.assertEqual(gh.check(), "o/r")
        n, art = gh.latest_build()
        self.assertEqual(n, 16)                        # 17 is expired
        with open(self.zip_path, "rb") as f:
            self.gh.zipdata = f.read()
        path = gh.download_artifact(art, tempfile.mkdtemp())
        self.assertEqual(pb.read_build(path).apk, self.apk)
        self.assertEqual(self.gh.blob_auth, [None])    # token not leaked to storage

    def test_github_latest_windows(self):
        self.gh.artifacts += [
            {"id": 20, "name": "PersianVPN-Windows", "expired": False, "created_at": "2026-11-10T10:00:00Z",
             "workflow_run": {"head_branch": "main"}},
            {"id": 21, "name": "PersianVPN-Windows", "expired": False, "created_at": "2026-11-12T10:00:00Z",
             "workflow_run": {"head_branch": "main"}},
            {"id": 22, "name": "PersianVPN-Windows", "expired": False, "created_at": "2026-11-13T10:00:00Z",
             "workflow_run": {"head_branch": "test"}},
            {"id": 23, "name": "PersianVPN-Windows", "expired": True, "created_at": "2026-11-14T10:00:00Z"},
        ]
        self.assertEqual(self.gh.client().latest_windows()["id"], 21)
        self.gh.artifacts = []
        self.assertIsNone(self.gh.client().latest_windows())

    def test_public_mirror(self):
        build = pb.read_build(self.zip_path)
        cfg = pb.release(self.ws, build, 16, "", "", github=self.gh.client(),
                         public_github=self.gh.client(repo="o/pub"), log=lambda *_: None)
        mirror = self.gh.files["o/pub:" + pb.PUBLIC_FILE].decode()
        self.assertTrue(mirror.startswith("PVC1:"))
        self.assertNotIn("127.0.0.1", mirror)                 # addresses not readable
        with open(self.srv_cfg["app_config_file"]) as f:
            self.assertEqual(pb.decode_public(mirror), f.read())  # same signed envelope
        # installed apps learn the mirror URLs through this release
        for u in pb.mirror_urls("o/pub"):
            self.assertIn(u, cfg["config_urls"])
        self.assertEqual(cfg["config_urls"][0].split("/v1/")[0],
                         self.ws.load_config()["config_urls"][0].split("/v1/")[0])  # router stays first
        # app_update URLs still point only at the router
        self.assertTrue(all("/v1/app.apk" in u for u in cfg["app_update"]["urls"]))

    def test_public_mirror_failure_is_not_fatal(self):
        self.gh.public_denied = True
        logs = []
        cfg = pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "",
                         github=self.gh.client(), public_github=self.gh.client(repo="o/pub"),
                         log=logs.append)
        self.assertIn("_public_failed", cfg)
        self.assertTrue(any("⚠" in l for l in logs))
        self.assertEqual(self.ws.published_version_code(), 16)   # release itself done

    def test_config_only_to_new_server(self):
        # first a normal release on the current router
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=lambda *_: None)
        # a NEW router (fresh: no config, no APK yet) on another port, same cert
        srv2 = tempfile.mkdtemp()
        cfg2 = dict(self.srv_cfg, app_config_file=os.path.join(srv2, "app.json"),
                    app_apk_file=os.path.join(srv2, "app.apk"), listen_port=0)
        httpd2 = um.make_server(um.Service(tum.FakeRouter(), cfg2), cfg2)
        threading.Thread(target=httpd2.serve_forever, daemon=True).start()
        new_base = "https://127.0.0.1:%d" % httpd2.server_address[1]
        try:
            conf = self.ws.load_config()
            conf["servers"] = [{"name": "new", "host": "10.9.8.7", "port": 443}]
            conf["status_urls"] = [new_base + "/v1/status"]
            conf["config_urls"] = [new_base + "/v1/config"] + conf["config_urls"][1:]
            with open(self.ws.path("config.json"), "w") as f:
                json.dump(conf, f)
            before = self.ws.load_config()["version"]
            cfg = pb.release_config_only(self.ws, github=self.gh.client(),
                                         public_github=self.gh.client(repo="o/pub"),
                                         log=lambda *_: None)
            self.assertEqual(cfg["version"], before + 1)
            self.assertEqual(cfg["app_update"]["version_code"], 16)        # app unchanged
            self.assertTrue(cfg["app_update"]["urls"][0].startswith(new_base))
            with open(cfg2["app_apk_file"], "rb") as f:                  # new router got the APK
                self.assertEqual(f.read(), self.apk)
            with open(cfg2["app_config_file"]) as f:
                served = f.read()
            payload = json.loads(base64.b64decode(json.loads(served)["payload"]))
            self.assertEqual(payload["servers"][0]["host"], "10.9.8.7")
            self.assertEqual(pb.decode_public(self.gh.files["o/pub:" + pb.PUBLIC_FILE].decode()), served)
            self.assertEqual(self.gh.files["o/r:" + pb.ASSET_PATH].decode(), served)
            # router-unreachable case: GitHub only
            conf = self.ws.load_config()
            cfg = pb.release_config_only(self.ws, send_router=False, github=self.gh.client(),
                                         public_github=self.gh.client(repo="o/pub"),
                                         log=lambda *_: None)
            self.assertEqual(cfg["version"], conf["version"] + 1)
        finally:
            httpd2.shutdown()

    def test_windows_build_release_then_android_release(self):
        pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=lambda *_: None)
        win_exe, engine = b"MZ" + os.urandom(5000), b"MZengine" + os.urandom(100)
        zp = os.path.join(self.ws_dir, "PersianVPN-Windows.zip")
        with zipfile.ZipFile(zp, "w") as z:
            z.writestr("PersianVPN.exe", win_exe)
            z.writestr("pvwin.exe", engine)
            z.writestr("version.txt", "7\n")
        win = pb.read_windows_build(zp)
        cfg = pb.release_config_only(self.ws, win=win, win_notes="ویندوز", log=lambda *_: None)
        wu = cfg["windows_update"]
        self.assertEqual((wu["version_code"], wu["sha256"], wu["engine_sha256"]),
                         (7, hashlib.sha256(win_exe).hexdigest(), hashlib.sha256(engine).hexdigest()))
        self.assertTrue(wu["urls"][0].endswith("/v1/win.exe"))
        srv_dir = os.path.dirname(self.srv_cfg["app_apk_file"])
        with open(os.path.join(srv_dir, "win.exe"), "rb") as f:
            self.assertEqual(f.read(), win_exe)
        with self.assertRaises(pb.ReleaseError):                # not newer
            pb.release_config_only(self.ws, win=win, log=lambda *_: None)
        # a later Android release keeps the Windows build listed and on the router
        build2 = pb.Build(b"PK" + os.urandom(1000), 17, "x")
        cfg = pb.release(self.ws, build2, 17, "", "", log=lambda *_: None)
        self.assertEqual(cfg["windows_update"]["version_code"], 7)
        cfg = pb.release_config_only(self.ws, log=lambda *_: None)    # and a plain config-only one too
        self.assertEqual(cfg["windows_update"]["version_code"], 7)

    def test_bad_token(self):
        with self.assertRaises(pb.ReleaseError) as ctx:
            self.gh.client("wrong").check()
        self.assertIn("توکن", str(ctx.exception))



class SyncWorkspaceTests(unittest.TestCase):
    """A new device fetches the published files it lacks from the router."""

    def test_fetches_only_missing_and_checks_hash(self):
        import hashlib, json, tempfile, shutil
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        apk, win = b"PK-apk-bytes", b"MZ-win"
        cfg = {"app_update": {"sha256": hashlib.sha256(apk).hexdigest()},
               "windows_update": {"sha256": hashlib.sha256(win).hexdigest()},
               "app_update_beta": {"sha256": "00" * 32}}
        with open(os.path.join(d, "config.json"), "w") as f:
            json.dump(cfg, f)
        with open(os.path.join(d, "win.exe"), "wb") as f:
            f.write(win)

        class Client:
            calls = []

            def download(self, path, progress=None):
                self.calls.append(path)
                return {"/v1/app.apk": apk, "/v1/beta.apk": b"other"}.get(path)
        c = Client()
        ws = pb.Workspace(d)
        got = pb.sync_workspace(ws, log=lambda *_: None, client=c)
        self.assertEqual(got, ["app.apk"])
        self.assertEqual(c.calls, ["/v1/app.apk", "/v1/beta.apk"])     # win.exe already right
        self.assertFalse(os.path.exists(os.path.join(d, "beta.apk")))   # wrong hash: not kept
        self.assertEqual(pb.sync_workspace(ws, log=lambda *_: None, client=c), [])


class BusyRouterTests(unittest.TestCase):
    """A cut upload keeps the router busy for a minute: wait instead of failing."""

    def test_waits_for_busy(self):
        c = pb.RouterClient({"status_urls": ["https://r.example:8443/v1/status"], "status_pins": []}, log=lambda *_: None)
        c.BUSY_WAIT = 0
        calls = []

        def call(env, body, dry_run=False, progress=None):
            calls.append(dry_run)
            if len(calls) <= 2:
                e = pb.ReleaseError(pb.ROUTER_ERRORS["busy"])
                e.code = "busy"
                raise e
            return {"ok": True, "features": ["beta", "partial"], "have": []}
        c._call = call
        self.assertEqual(c.publish("env", b"x"), {"ok": True, "features": ["beta", "partial"], "have": []})
        self.assertEqual(calls, [True, True, True, False])

    def test_other_errors_not_retried(self):
        c = pb.RouterClient({"status_urls": ["https://r.example:8443/v1/status"], "status_pins": []})
        c.BUSY_WAIT = 0
        n = []

        def call(env, body, dry_run=False, progress=None):
            n.append(1)
            e = pb.ReleaseError("x")
            e.code = "bad_signature"
            raise e
        c._call = call
        with self.assertRaises(pb.ReleaseError):
            c.publish("env", b"")
        self.assertEqual(len(n), 1)

if __name__ == "__main__":
    unittest.main()
