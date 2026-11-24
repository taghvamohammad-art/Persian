"""Logic of the Windows app that does not need Windows: config codec and signature."""
import base64
import json
import os
import secrets
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
sys.path.insert(0, os.path.join(HERE, "..", "tools", "release_tool"))

try:
    import pvclient as pc
except ImportError as e:            # PySide6 missing on this machine
    raise unittest.SkipTest(str(e))
import publisher                    # noqa: E402
import sign_config as sc            # noqa: E402


class SignedConfig(unittest.TestCase):
    def setUp(self):
        self.d = secrets.randbelow(sc.N - 1) + 1
        self.pub = base64.b64encode(sc.public_der(self.d)).decode()

    def envelope(self, cfg):
        payload = json.dumps(cfg).encode()
        return json.dumps({"payload": base64.b64encode(payload).decode(),
                           "sig": base64.b64encode(sc.sign(self.d, payload)).decode()})

    def test_plain_and_public_mirror_encoding(self):
        env = self.envelope({"version": 3, "linux_servers": [{"name": "l"}]})
        self.assertEqual(pc.verify(env, self.pub)["version"], 3)
        self.assertEqual(pc.verify(publisher.encode_public(env), self.pub)["linux_servers"][0]["name"], "l")

    def test_tampered_is_refused(self):
        env = json.loads(self.envelope({"version": 3}))
        env["payload"] = base64.b64encode(b'{"version": 99}').decode()
        self.assertIsNone(pc.verify(json.dumps(env), self.pub))

    def test_bypass_names(self):
        self.assertEqual(pc.clean_bypass(
            ["C:\\Program Files\\Mozilla Firefox\\firefox.exe", "Telegram.exe", "FIREFOX.EXE", "notes.txt", ""]),
            ["firefox.exe", "Telegram.exe"])

    def test_test_build_only_for_testers(self):
        cfg = {"windows_update": {"version_code": 5},
               "windows_update_beta": {"version_code": 6, "testers": [pc.tester_hash("Mohammad")]}}
        self.assertEqual(pc.update_for(cfg, "mohammad ")["version_code"], 6)
        self.assertEqual(pc.update_for(cfg, "ali")["version_code"], 5)
        self.assertEqual(pc.update_for(cfg, "")["version_code"], 5)
        cfg["windows_update"]["version_code"] = 6                 # published for everyone meanwhile
        self.assertNotIn("testers", pc.update_for(cfg, "mohammad"))

    def test_secret_roundtrip(self):
        self.assertEqual(pc.unseal(pc.seal("pw-1")), "pw-1")


if __name__ == "__main__":
    unittest.main()


class Shield(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows paths")
    def test_clean_shield(self):
        p = r"C:\Program Files\Telegram\Telegram.exe"
        got = pc.clean_shield([p, p.lower(), "Telegram.exe", "", r"D:\a\b.txt", r"C:\z\Alpha.EXE"])
        self.assertEqual(got, [r"C:\z\Alpha.EXE", p])


def test_format_diag():
    d = {"version": 162, "state": "connected", "protocols": ["ubu-2/hysteria2 500ms"],
         "engine": {"running": "pool", "steps": [{"name": "trace", "ok": True, "ms": 300, "info": "ip=1.2.3.4"},
                                                 {"name": "download", "ok": False, "ms": 9000, "error": "timeout"}]},
         "probes": [{"name": "ubu-2", "result": {"hysteria2": 500, "amneziawg": -1,
                                                 "errors": {"amneziawg": "no handshake"}}}],
         "log": ["2026-11-24 16:00:00 connect"]}
    txt = pc.format_diag(d, "mohammad")
    assert "user: mohammad" in txt and "✓ Hysteria2 500ms" in txt and "✗ AmneziaWG no handshake" in txt
    assert "✓ صفحه با IP" in txt and "✗ دانلود" in txt and "connect" in txt
    awg = pc.format_diag({"engine": {"running": "amneziawg", "awg": {"handshake_age_s": 20, "rx_bytes": 2048,
                                                                          "tx_bytes": 10, "port": 5000}}})
    assert "handshake 20s" in awg and "2.0 KB" in awg and "(اول وصل شوید)" in awg
