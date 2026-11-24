import base64
import hashlib
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request

import xraybox


class Helpers(unittest.TestCase):
    def test_x25519_formats(self):
        self.assertEqual(xraybox.parse_x25519("Private key: AAA\nPublic key: BBB\n"), ("AAA", "BBB"))
        self.assertEqual(xraybox.parse_x25519("PrivateKey: AAA\nPassword (PublicKey): BBB\nHash32: x"),
                         ("AAA", "BBB"))

    def test_pem_pin(self):
        der = os.urandom(300)
        b = base64.encodebytes(der).decode()
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
            f.write("-----BEGIN CERTIFICATE-----\n%s-----END CERTIFICATE-----\n" % b)
        self.assertEqual(xraybox.pem_sha256(f.name), hashlib.sha256(der).hexdigest())

    def test_status_page(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"users_online": 3}, f)
        port = 18000 + os.getpid() % 1000
        xraybox.STATUS_PORT = port
        xraybox.serve_status({"box_status": {"token": "tok", "allow": ["127.0.0.1"]}, "status_file": f.name})
        with urllib.request.urlopen("http://127.0.0.1:%d/pvs/tok" % port, timeout=5) as r:
            self.assertEqual(json.load(r)["users_online"], 3)
        with self.assertRaises(urllib.error.HTTPError):
            urllib.request.urlopen("http://127.0.0.1:%d/pvs/other" % port, timeout=5)


if __name__ == "__main__":
    unittest.main()
