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

    def test_secret_roundtrip(self):
        self.assertEqual(pc.unseal(pc.seal("pw-1")), "pw-1")


if __name__ == "__main__":
    unittest.main()
