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
"""

import gzip
import hashlib
import io
import struct
import zipfile

MAGIC = b"PVDL1\n"
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
    """The new APK (the phone does the same in Kotlin; this is for tests)."""
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
