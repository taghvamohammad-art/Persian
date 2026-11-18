import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import settings as st  # noqa: E402


class AppPasswordTests(unittest.TestCase):
    """The phone version: secrets locked with the app password."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.saved = (st.APP_DIR, st.FILE, st.UNLOCK_FILE, st.MASTER_KEY)
        st.APP_DIR = self.tmp
        st.FILE = os.path.join(self.tmp, "settings.json")
        st.UNLOCK_FILE = os.path.join(self.tmp, "unlock.json")

    def tearDown(self):
        st.APP_DIR, st.FILE, st.UNLOCK_FILE, st.MASTER_KEY = self.saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_roundtrip(self):
        self.assertFalse(st.has_app_password())
        st.set_app_password("123456")
        s = st.Settings()
        s.token = "ghp_secret"
        s.routers = [{"id": "r1", "name": "a", "role": "main", "host": "h", "port": 22, "user": "u",
                      "password": "router-pw", "hostkey": "", "params": st.encrypt_blob({"k": 1})}]
        s.save()
        raw = open(st.FILE).read()
        self.assertNotIn("ghp_secret", raw)
        self.assertNotIn("router-pw", raw)
        self.assertIn('"aes:', raw)
        st.MASTER_KEY = None
        self.assertFalse(st.unlock("wrong"))
        self.assertIsNone(st.MASTER_KEY)
        self.assertTrue(st.unlock("123456"))
        s2 = st.Settings.load()
        self.assertEqual(s2.token, "ghp_secret")
        self.assertEqual(s2.routers[0]["password"], "router-pw")
        self.assertEqual(st.decrypt_blob(s2.routers[0]["params"]), {"k": 1})


if __name__ == "__main__":
    unittest.main()
