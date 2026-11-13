"""Reference BSDIFF40 encoder (naive matching, standard format) that made
mobile/pvcore/testdata/bsdiff.*: python bsdiff_ref.py SEED -> old, new, p."""
import bz2, os, struct, random, sys
def off(v):
    b = struct.pack("<q", abs(v)) if v >= 0 else struct.pack("<Q", (-v) | (1 << 63))
    return b
def encode(old, new, rnd):
    ctrl, diff, extra = b"", bytearray(), bytearray()
    np = op = 0
    while np < len(new):
        x = min(rnd.randint(0, 5000), len(new) - np)
        y = min(rnd.randint(0, 3000), len(new) - np - x)
        for i in range(x):
            o = old[op + i] if 0 <= op + i < len(old) else 0
            diff.append((new[np + i] - o) & 255)
        extra += new[np + x:np + x + y]
        z = rnd.randint(-2000, 4000)
        ctrl += off(x) + off(y) + off(z)
        np += x + y
        op += x + z
    c, d, e = bz2.compress(ctrl), bz2.compress(bytes(diff)), bz2.compress(bytes(extra))
    return b"BSDIFF40" + off(len(c)) + off(len(d)) + off(len(new)) + c + d + e
rnd = random.Random(int(sys.argv[1]))
old = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(15000, 20000)))
new = bytearray(old[:])
for _ in range(50):
    p = rnd.randint(0, max(0, len(new) - 1))
    new[p:p + rnd.randint(0, 500)] = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 800)))
new = bytes(new)
open("old", "wb").write(old); open("new", "wb").write(new); open("p", "wb").write(encode(old, new, rnd))
