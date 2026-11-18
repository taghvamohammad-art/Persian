"""Small app updates: a patch that rebuilds the new APK from the old one.

An APK is a zip; between two builds most entries (the Xray/AmneziaWG
engine libraries, resources) are byte-for-byte the same. The patch copies
those from the APK already installed on the phone and carries only what
changed, so a user downloads a few MB instead of the whole app.

Format (gzip-compressed): MAGIC, then operations
  b"C" + offset(8) + length(8)   copy bytes of the old APK
  b"D" + length(4) + bytes       new bytes
  b"E"                           end
The result is checked against the signed SHA-256 of the new APK, so a
wrong patch can never install anything else.

When the installed app can apply it (FEATURE in its assets) the patch can
instead be a BSDIFF40 one (bsdiff4): it also carries only the changed bytes
INSIDE changed files, which matters for the engine library that changes a
little in almost every version. The smaller of the two is used.
"""

import bz2
import gzip
import hashlib
import io
import os
import platform
import struct
import zipfile

MAGIC = b"PVDL1\n"
BSDIFF_MAGIC = b"BSDIFF40"
FEATURE_FILE = "assets/pv_features.txt"     # in the APK: what its updater can apply


def features(apk):
    try:
        z = zipfile.ZipFile(io.BytesIO(apk))
        return set(z.read(FEATURE_FILE).decode().split())
    except (KeyError, zipfile.BadZipFile, UnicodeDecodeError):
        return set()


def make_best_patch(old, new, log=None):
    """The smallest patch the installed APK (old) can apply."""
    best = make_patch(old, new)
    if "bsdiff" in features(old):
        try:
            import bsdiff4
            b = bsdiff4.diff(old, new)
        except ImportError:                     # the phone: the Go library instead
            native = native_diff()
            b = None
            if native is None:
                if log:
                    log("⚠ bsdiff در این نسخه‌ی ابزار نیست؛ وصله‌ی ساده ساخته شد.")
            else:
                try:
                    b = bsdiff_by_entry(old, new, native)
                except (ValueError, MemoryError, zipfile.BadZipFile) as e:
                    if log:
                        log("⚠ وصله‌ی bsdiff ساخته نشد (%s)؛ وصله‌ی ساده." % e)
        if b is not None and len(b) < len(best):
            best = b
    return best


# ---------------------------------------------------------------- BSDIFF40 without bsdiff4 (the phone)

def _offtout(v):
    return struct.pack("<Q", v) if v >= 0 else struct.pack("<Q", (-v) | (1 << 63))


def _offtin(b):
    v = struct.unpack("<Q", b)[0]
    return -(v & ~(1 << 63)) if v & (1 << 63) else v


def bsdiff_file(ctrl, diff, extra, new_size):
    c = bz2.compress(b"".join(_offtout(v) for v in ctrl))
    d = bz2.compress(bytes(diff))
    e = bz2.compress(bytes(extra))
    return BSDIFF_MAGIC + _offtout(len(c)) + _offtout(len(d)) + _offtout(new_size) + c + d + e


def bsdiff_by_entry(old, new, diff):
    """A standard BSDIFF40 patch, made one zip entry at a time: each entry of
    the new APK is diffed against the entry of the same name in the old one
    (memory stays at a few times the largest entry, not the whole APK).
    diff(old_bytes, new_bytes) -> (ctrl list, diff bytes, extra bytes)."""
    old_by_name, _ = _entries(old)
    _, ordered = _entries(new)
    ctrl, dbuf, ebuf = [], bytearray(), bytearray()
    np = op = 0

    def literal(upto):
        nonlocal np
        if upto > np:
            ctrl.extend((0, upto - np, 0))
            ebuf.extend(new[np:upto])
            np = upto
    for name, _hoff, data, size in ordered:
        if data < np:
            continue
        literal(data)
        o = old_by_name.get(name)
        if o is None or not o[1] or not size:
            literal(data + size)
            continue
        odata, osize = o[0], o[1]
        if odata != op:
            ctrl.extend((0, 0, odata - op))
            op = odata
        seg_old, seg_new = old[odata:odata + osize], new[data:data + size]
        if seg_old == seg_new:
            c, d, e = [size, 0, 0], bytes(size), b""
        else:
            c, d, e = diff(seg_old, seg_new)
        if sum(c[i] + c[i + 1] for i in range(0, len(c), 3)) != size:
            raise ValueError("bad delta for %s" % name)
        ctrl.extend(c)
        dbuf.extend(d)
        ebuf.extend(e)
        op += sum(c[i] + c[i + 2] for i in range(0, len(c), 3))
        np = data + size
    literal(len(new))
    return bsdiff_file(ctrl, dbuf, ebuf, len(new))


def bspatch(old, patch):
    """Apply a BSDIFF40 patch in plain Python (tests; slow for big files)."""
    if not patch.startswith(BSDIFF_MAGIC):
        raise ValueError("not a BSDIFF40 patch")
    lc, ld, size = _offtin(patch[8:16]), _offtin(patch[16:24]), _offtin(patch[24:32])
    ctrl = bz2.decompress(patch[32:32 + lc])
    diff = bz2.decompress(patch[32 + lc:32 + lc + ld])
    extra = bz2.decompress(patch[32 + lc + ld:])
    out, op, di, ei = bytearray(), 0, 0, 0
    for i in range(0, len(ctrl), 24):
        add, cp, seek = (_offtin(ctrl[i + k:i + k + 8]) for k in (0, 8, 16))
        for j in range(add):
            o = old[op + j] if 0 <= op + j < len(old) else 0
            out.append((diff[di + j] + o) & 255)
        di += add
        op += add
        out += extra[ei:ei + cp]
        ei += cp
        op += seek
    if len(out) != size:
        raise ValueError("patch made %d bytes, expected %d" % (len(out), size))
    return bytes(out)


_NATIVE = []


def native_diff():
    """pvdiff (Go, mobile/pvdiff) through ctypes, or None where it is not bundled."""
    if _NATIVE:
        return _NATIVE[0]
    _NATIVE.append(None)
    import ctypes
    arch = {"aarch64": "arm64", "arm64": "arm64", "armv7l": "arm", "armv8l": "arm", "arm": "arm",
            "x86_64": "x86_64", "amd64": "x86_64"}.get(platform.machine().lower())
    dirs = [os.environ.get("PV_NATIVE_DIR"), os.path.dirname(os.path.abspath(__file__))]
    for d in dirs:
        f = os.path.join(d, "libpvdiff-%s.so" % arch) if d and arch else None
        if not f or not os.path.isfile(f):
            continue
        try:
            lib = ctypes.CDLL(f)
        except OSError:
            continue
        lib.PvDiff.restype = ctypes.c_void_p
        lib.PvDiff.argtypes = [ctypes.c_char_p, ctypes.c_longlong, ctypes.c_char_p, ctypes.c_longlong,
                               ctypes.POINTER(ctypes.c_longlong)]
        lib.PvFree.argtypes = [ctypes.c_void_p]

        def diff(a, b, lib=lib):
            n = ctypes.c_longlong(0)
            p = lib.PvDiff(a, len(a), b, len(b), ctypes.byref(n))
            if not p:
                raise ValueError("pvdiff failed")
            try:
                raw = ctypes.string_at(p, n.value)
            finally:
                lib.PvFree(p)
            k = struct.unpack_from("<q", raw, 0)[0]
            ctrl = list(struct.unpack_from("<%dq" % k, raw, 8))
            o = 8 + 8 * k
            dl = struct.unpack_from("<q", raw, o)[0]
            d = raw[o + 8:o + 8 + dl]
            o += 8 + dl
            el = struct.unpack_from("<q", raw, o)[0]
            return ctrl, d, raw[o + 8:o + 8 + el]
        _NATIVE[0] = diff
        break
    return _NATIVE[0]
LOCAL_HEADER = 30


def _entries(apk):
    """{name: (data_offset, compressed_size, crc, method)} and, in file order,
    [(name, header_offset, data_offset, compressed_size)]."""
    z = zipfile.ZipFile(io.BytesIO(apk))
    by_name, ordered = {}, []
    for info in z.infolist():
        off = info.header_offset
        if apk[off:off + 4] != b"PK\x03\x04":
            raise ValueError("bad local header for %s" % info.filename)
        name_len, extra_len = struct.unpack("<HH", apk[off + 26:off + 30])
        data = off + LOCAL_HEADER + name_len + extra_len
        by_name[info.filename] = (data, info.compress_size, info.CRC, info.compress_type)
        ordered.append((info.filename, off, data, info.compress_size))
    ordered.sort(key=lambda e: e[1])
    return by_name, ordered


def make_patch(old, new):
    """Patch bytes turning `old` into `new` (both whole APK files)."""
    old_by_name, _ = _entries(old)
    new_by_name, ordered = _entries(new)
    ops = []                       # ("C", off, len) | ("D", bytes)

    def data(b):
        if not b:
            return
        if ops and ops[-1][0] == "D":
            ops[-1] = ("D", ops[-1][1] + b)
        else:
            ops.append(("D", b))

    def copy(off, ln):
        if ln == 0:
            return
        if ops and ops[-1][0] == "C" and ops[-1][1] + ops[-1][2] == off:
            ops[-1] = ("C", ops[-1][1], ops[-1][2] + ln)
        else:
            ops.append(("C", off, ln))

    pos = 0
    for name, header, start, size in ordered:
        data(new[pos:start])                       # anything before + the local header
        _, _, crc, method = new_by_name[name]
        same = old_by_name.get(name)
        if same and same[1] == size and same[2] == crc and same[3] == method \
                and old[same[0]:same[0] + size] == new[start:start + size]:
            copy(same[0], size)
        else:
            data(new[start:start + size])
        pos = start + size
    data(new[pos:])                                # signing block, central directory

    out = io.BytesIO()
    out.write(MAGIC)
    for op in ops:
        if op[0] == "C":
            out.write(b"C" + struct.pack(">QQ", op[1], op[2]))
        else:
            for i in range(0, len(op[1]), 1 << 20):
                chunk = op[1][i:i + (1 << 20)]
                out.write(b"D" + struct.pack(">I", len(chunk)) + chunk)
    out.write(b"E")
    return gzip.compress(out.getvalue(), 9)


def apply_patch(old, patch):
    """The new APK (the phone does the same in Kotlin/Go; this is for tests)."""
    if patch.startswith(BSDIFF_MAGIC):
        try:
            import bsdiff4
        except ImportError:
            return bspatch(old, patch)
        return bsdiff4.patch(old, patch)
    raw = gzip.decompress(patch)
    if not raw.startswith(MAGIC):
        raise ValueError("not a patch")
    i, out = len(MAGIC), io.BytesIO()
    while True:
        op = raw[i:i + 1]
        i += 1
        if op == b"C":
            off, ln = struct.unpack(">QQ", raw[i:i + 16])
            i += 16
            out.write(old[off:off + ln])
        elif op == b"D":
            (ln,) = struct.unpack(">I", raw[i:i + 4])
            i += 4
            out.write(raw[i:i + ln])
            i += ln
        elif op == b"E":
            return out.getvalue()
        else:
            raise ValueError("bad patch")


def sha256(b):
    return hashlib.sha256(b).hexdigest()
