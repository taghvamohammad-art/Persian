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
                if self.path == "/repos/o/r":
                    return self._json(200, {"full_name": "o/r"})
                if self.path.startswith("/repos/o/r/actions/artifacts?"):
                    return self._json(200, {"artifacts": gh.artifacts})
                if self.path == "/repos/o/r/actions/artifacts/8/zip":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:%d/blob/8" % gh.port)
                    self.end_headers()
                    return
                p = self.path[len("/repos/o/r/contents/"):]
                if p in gh.files:
                    return self._json(200, {"sha": hashlib.sha1(gh.files[p]).hexdigest()})
                return self._json(404, {})

            def do_PUT(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                p = self.path[len("/repos/o/r/contents/"):]
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

    def client(self, token="tok"):
        return pb.GitHubClient(token, "o/r", api="http://127.0.0.1:%d" % self.port)


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
        self.assertEqual(self.gh.files[pb.ASSET_PATH].decode(), served)
        self.assertIn("[skip ci]", self.gh.last_message)
        self.assertEqual(prog[-1], len(self.apk))
        # releasing the same versionCode again is refused before anything is sent
        with self.assertRaises(pb.ReleaseError):
            pb.release(self.ws, build, 16, "1.0.16", "", log=lambda *_: None)
        # a newer build replaces the file on GitHub (sha handled)
        build2 = pb.Build(b"PK" + os.urandom(1000), 17, "x")
        pb.release(self.ws, build2, 17, "", "", github=self.gh.client(), log=lambda *_: None)
        self.assertIn("1.0.17", self.gh.last_message)

    def test_router_failure_keeps_workspace(self):
        before = self.ws.load_config()
        os.remove(self.srv_cfg["config_pubkey_file"])     # router not set up
        with self.assertRaises(pb.ReleaseError) as ctx:
            pb.release(self.ws, pb.read_build(self.zip_path), 16, "", "", log=lambda *_: None)
        self.assertIn("config_key.public.txt", str(ctx.exception))
        self.assertEqual(self.ws.load_config(), before)
        self.assertFalse(os.path.exists(self.ws.path("app.apk")))

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

    def test_bad_token(self):
        with self.assertRaises(pb.ReleaseError) as ctx:
            self.gh.client("wrong").check()
        self.assertIn("توکن", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
