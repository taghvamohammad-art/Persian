import io
import os
import unittest
import zipfile

import apkdelta


def apk(dex, lib, extra=None, bsdiff=False):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        if bsdiff:
            z.writestr(apkdelta.FEATURE_FILE, b"bsdiff\n")
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


    def test_changed_library_with_bsdiff(self):
        try:
            import bsdiff4  # noqa: F401
        except ImportError:
            self.skipTest("bsdiff4 not installed")
        lib = bytearray(os.urandom(3_000_000))
        old = apk(os.urandom(50_000), bytes(lib), bsdiff=True)
        for i in range(0, len(lib), 300_000):       # the engine changed a little all over
            lib[i:i + 200] = os.urandom(200)
        new = apk(os.urandom(50_000), bytes(lib), bsdiff=True)
        patch = apkdelta.make_best_patch(old, new)
        self.assertTrue(patch.startswith(apkdelta.BSDIFF_MAGIC))
        self.assertEqual(apkdelta.apply_patch(old, patch), new)
        self.assertLess(len(patch), 300_000)            # not the 3 MB library
        # an installed app without the feature gets the plain format
        plain_old = apk(os.urandom(50_000), bytes(lib))
        self.assertFalse(apkdelta.make_best_patch(plain_old, new).startswith(apkdelta.BSDIFF_MAGIC))



def naive_diff(a, b):
    """Stand-in for the Go library: same-offset diff for the common prefix, the rest as extra."""
    n = min(len(a), len(b))
    return [n, len(b) - n, 0], bytes((b[i] - a[i]) & 255 for i in range(n)), b[n:]


class ByEntry(unittest.TestCase):
    """BSDIFF40 made one zip entry at a time (the phone, without bsdiff4)."""

    def pair(self):
        lib = os.urandom(200000)
        lib2 = bytearray(lib)
        lib2[5000:5010] = os.urandom(10)
        lib2[150000:150000] = os.urandom(333)                    # inserted bytes: offsets shift
        old = apk(os.urandom(3000), lib, extra=b"same" * 100, bsdiff=True)
        new = apk(os.urandom(3100), bytes(lib2), extra=b"same" * 100 + b"more",
                  bsdiff=True)
        return old, new

    def test_assembly_is_standard_bsdiff(self):
        old, new = self.pair()
        patch = apkdelta.bsdiff_by_entry(old, new, naive_diff)
        self.assertTrue(patch.startswith(apkdelta.BSDIFF_MAGIC))
        self.assertEqual(apkdelta.bspatch(old, patch), new)

    @unittest.skipUnless(os.environ.get("PV_NATIVE_DIR"), "Go library (mobile/pvdiff) not built")
    def test_go_library(self):
        apkdelta._NATIVE.clear()
        native = apkdelta.native_diff()
        self.assertIsNotNone(native)
        old, new = self.pair()
        patch = apkdelta.bsdiff_by_entry(old, new, native)
        self.assertEqual(apkdelta.bspatch(old, patch), new)
        self.assertLess(len(patch), 12000)                       # the 200 KB library: only what changed
        try:
            import bsdiff4
        except ImportError:
            return
        self.assertEqual(bsdiff4.patch(old, patch), new)         # the format the app reads

if __name__ == "__main__":
    unittest.main()
