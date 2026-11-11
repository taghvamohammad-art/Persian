import io
import os
import unittest
import zipfile

import apkdelta


def apk(dex, lib, extra=None):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("AndroidManifest.xml", b"<manifest/>" * 50, zipfile.ZIP_DEFLATED)
        z.writestr("classes.dex", dex, zipfile.ZIP_DEFLATED)
        z.writestr(zipfile.ZipInfo("lib/arm64-v8a/libgojni.so"), lib)      # stored, like Android
        if extra:
            z.writestr("assets/extra.bin", extra, zipfile.ZIP_DEFLATED)
    return b.getvalue() + os.urandom(3000)       # stands in for the signing block area


class Delta(unittest.TestCase):
    def test_unchanged_library_is_copied(self):
        lib = os.urandom(3_000_000)
        old = apk(os.urandom(200_000), lib)
        new = apk(os.urandom(220_000), lib, extra=b"x" * 1000)
        patch = apkdelta.make_patch(old, new)
        self.assertEqual(apkdelta.apply_patch(old, patch), new)
        self.assertLess(len(patch), 400_000)            # not the 3 MB library

    def test_wrong_base_does_not_give_the_new_apk(self):
        lib = os.urandom(100_000)
        old, new = apk(b"a" * 1000, lib), apk(b"b" * 1000, lib)
        other = apk(b"a" * 1000, os.urandom(100_000))
        patch = apkdelta.make_patch(old, new)
        self.assertNotEqual(apkdelta.apply_patch(other, patch), new)


if __name__ == "__main__":
    unittest.main()
