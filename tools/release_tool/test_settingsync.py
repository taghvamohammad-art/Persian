import os
import shutil
import tempfile
import unittest
from unittest import mock

import settings as st
import settingsync as ss


class FakeRouter:
    """The main MikroTik's files (shared by the two devices)."""

    def __init__(self):
        self.files = {}

    def get(self, path):
        if path not in self.files:
            raise IOError("no such file")
        return self.files[path]

    def put(self, path, data):
        self.files[path] = data

    def close(self):
        pass


class Device:
    """One copy of the tool: its own settings folder and workspace."""

    def __init__(self, root, name):
        self.dir = os.path.join(root, name)
        self.ws = os.path.join(self.dir, "ws")
        os.makedirs(self.ws)
        with open(os.path.join(self.ws, "config.json"), "w") as f:
            f.write('{"v": 1}')

    def __enter__(self):
        self.patch = mock.patch.multiple(st, APP_DIR=self.dir, FILE=os.path.join(self.dir, "settings.json"))
        self.patch.start()
        return self

    def __exit__(self, *exc):
        self.patch.stop()


def base_settings(ws):
    s = st.Settings(workspace=ws, token="ghp_x")
    s.backup_password = "bk"
    s.routers = [
        {"id": "r1", "name": "main", "role": "main", "host": "91.207.18.201", "port": 22, "user": "admin",
         "password": "pw", "hostkey": ""},
        {"id": "r2", "name": "لینوکس 1", "role": "linux", "host": "94.158.245.210", "port": 22, "user": "root",
         "password": "rootpw", "hostkey": "", "params": st.encrypt_blob({"status_token": "OLD"})}]
    s.save()
    return s


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.router = FakeRouter()
        self.phone = Device(self.tmp, "phone")
        self.pc = Device(self.tmp, "pc")
        ss._last_pull = 0
        self.saved_hook = st.ON_SAVE
        st.ON_SAVE = None

    def tearDown(self):
        st.ON_SAVE = self.saved_hook
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sync(self, s, **kw):
        ss._last_pull = 0
        return ss.sync(s, connect=lambda: self.router, log=lambda *_: None, **kw)

    def token(self, s):
        return st.decrypt_blob(s.routers[1]["params"])["status_token"]

    def set_token(self, s, value):
        s.routers[1]["params"] = st.encrypt_blob({"status_token": value})
        s.save()

    def test_first_device_pushes_second_takes_it(self):
        with self.phone:
            phone = base_settings(self.phone.ws)
            self.assertEqual(self.sync(phone), "pushed")
        self.assertIn(ss.REMOTE_FILE, self.router.files)
        self.assertNotIn(b"rootpw", self.router.files[ss.REMOTE_FILE])
        with self.pc:
            pc = st.Settings(workspace=self.pc.ws)
            pc.backup_password = "bk"
            pc.routers = [dict(phone.routers[0])]
            # an empty pc has no change of its own since it never synced: the user is asked
            with self.assertRaises(ss.SyncConflict):
                self.sync(pc)
            self.assertEqual(self.sync(pc, choose=lambda c: True), "pulled")
            self.assertEqual(self.token(pc), "OLD")
            self.assertEqual(pc.workspace, self.pc.ws)
            self.assertEqual(self.sync(pc), "same")

    def test_change_travels_both_ways(self):
        with self.phone:
            phone = base_settings(self.phone.ws)
            self.sync(phone)
        with self.pc:
            pc = base_settings(self.pc.ws)
            self.assertEqual(self.sync(pc), "same")          # same content: nothing to ask
            self.set_token(pc, "NEW")
            self.assertEqual(self.sync(pc), "pushed")
        with self.phone:
            self.assertEqual(self.sync(phone), "pulled")
            self.assertEqual(self.token(phone), "NEW")
            reloaded = st.Settings.load()
            self.assertEqual(self.token(reloaded), "NEW")
            self.assertEqual(self.sync(phone), "same")
            self.set_token(phone, "NEWER")
            self.assertEqual(self.sync(phone), "pushed")
        with self.pc:
            self.assertEqual(self.sync(pc), "pulled")
            self.assertEqual(self.token(pc), "NEWER")

    def test_conflict_is_asked_and_either_side_can_win(self):
        with self.phone:
            phone = base_settings(self.phone.ws)
            self.sync(phone)
        with self.pc:
            pc = base_settings(self.pc.ws)
            self.sync(pc)
            self.set_token(pc, "PC")
            self.sync(pc)
        with self.phone:
            self.set_token(phone, "PHONE")
            with self.assertRaises(ss.SyncConflict) as cm:
                self.sync(phone)
            self.assertIn("status_token", cm.exception.summary)
            self.assertEqual(self.token(phone), "PHONE")     # nothing overwritten
            self.assertEqual(self.sync(phone, choose=lambda c: False), "pushed")
            aside = os.listdir(os.path.join(self.phone.dir, "sync_old"))
            self.assertEqual(len(aside), 1)               # the computer's copy, kept on the phone
        with self.pc:
            self.assertEqual(self.sync(pc), "pulled")
            self.assertEqual(self.token(pc), "PHONE")

    def test_wrong_backup_password_is_explained(self):
        with self.phone:
            phone = base_settings(self.phone.ws)
            self.sync(phone)
        with self.pc:
            pc = base_settings(self.pc.ws)
            pc.backup_password = "other"
            with self.assertRaises(ss.ReleaseError) as cm:
                self.sync(pc)
            self.assertIn("رمز بکاپ", str(cm.exception))

    def test_off_without_password_or_main_router(self):
        with self.phone:
            s = st.Settings(workspace=self.phone.ws)
            self.assertEqual(self.sync(s), "off")

    def test_xray_box_settings_survive_save_and_sync(self):
        with self.phone:
            phone = base_settings(self.phone.ws)
            phone.routers[0]["xray_box"] = True
            phone.routers[0]["xray_params"] = st.encrypt_blob({"status_token": "BOX"})
            phone.save()
            loaded = st.Settings.load()
            self.assertTrue(loaded.routers[0]["xray_box"])
            self.sync(phone)
        with self.pc:
            pc = base_settings(self.pc.ws)
            self.sync(pc, choose=lambda c: True)
            self.assertTrue(pc.routers[0]["xray_box"])
            self.assertEqual(st.decrypt_blob(pc.routers[0]["xray_params"]), {"status_token": "BOX"})
            self.assertEqual(self.sync(pc), "same")


if __name__ == "__main__":
    unittest.main()
