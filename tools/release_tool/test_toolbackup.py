import json
import os
import tempfile
import unittest
from unittest import mock

import settings as st
import toolbackup as tb
from publisher import ReleaseError


class ToolBackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.patch = mock.patch.multiple(st, APP_DIR=self.tmp, FILE=os.path.join(self.tmp, "settings.json"))
        self.patch.start()
        self.ws = os.path.join(self.tmp, "old-ws")
        os.makedirs(self.ws)
        for name, text in (("config.json", '{"v": 1}'), ("config_key.private.json", '{"d": "secret"}')):
            with open(os.path.join(self.ws, name), "w") as f:
                f.write(text)

    def tearDown(self):
        self.patch.stop()

    def test_roundtrip_to_another_computer(self):
        s = st.Settings(workspace=self.ws, token="ghp_x")
        s.backup_password = "bkpw"
        s.routers = [{"id": "r1", "name": "lin", "role": "linux", "host": "1.2.3.4", "port": 22, "user": "root",
                      "password": "rootpw", "hostkey": "SHA256:x",
                      "params": st.encrypt_blob({"reality_private": "K", "cf_token": "T"})}]
        blob = tb.export_bytes(s, "pw1")
        self.assertNotIn(b"rootpw", blob)
        with self.assertRaises(ReleaseError):
            tb.read(blob, "wrong")
        data = tb.read(blob, "pw1")
        new_ws = os.path.join(self.tmp, "new-ws")
        target = st.Settings()
        written = tb.apply(data, target, new_ws)
        self.assertEqual(sorted(written), ["config.json", "config_key.private.json"])
        with open(os.path.join(new_ws, "config_key.private.json")) as f:
            self.assertEqual(json.load(f), {"d": "secret"})
        again = st.Settings.load()
        self.assertEqual((again.token, again.backup_password, again.workspace), ("ghp_x", "bkpw", new_ws))
        r = again.routers[0]
        self.assertEqual(r["password"], "rootpw")
        self.assertEqual(st.decrypt_blob(r["params"])["cf_token"], "T")

    def test_auto_backup_kept_with_router_backups(self):
        s = st.Settings(workspace=self.ws)
        s.backup_password = "bkpw"
        name = tb.auto_backup(s, log=lambda *_: None)
        path = os.path.join(s.backup_dir(), tb.TOOL_ID, name)
        with open(path, "rb") as f:
            self.assertEqual(tb.read(f.read(), "bkpw")["files"].keys(), {"config.json", "config_key.private.json"})


if __name__ == "__main__":
    unittest.main()
