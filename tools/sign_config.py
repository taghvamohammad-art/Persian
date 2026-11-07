#!/usr/bin/env python3
"""Sign the app's server configuration (ECDSA P-256 / SHA-256).

Pure Python standard library, so it runs on any PC with Python 3.8+.

  python sign_config.py genkey
      -> config_key.private.json  (KEEP SECRET, never upload anywhere)
      -> config_key.public.txt    (copy into the app: app/src/main/assets/)

  python sign_config.py sign config.json
      -> app_config.signed.json   (copy into the app assets AND upload to
                                   the router's umstatus folder)

  python sign_config.py verify app_config.signed.json
      -> checks the signature with config_key.public.txt

  python sign_config.py app <path-to-apk> <versionCode> [versionName] [notes]
      -> publishes a new app version: copies the APK to app.apk, writes its
         SHA-256 and size into config.json, raises "version" by 1 and signs.
         Upload app.apk and app_config.signed.json to the router.
         <versionCode> must equal versionCode in app/build.gradle.

The app only accepts a config whose signature matches the public key
built into it, and only if its "version" is higher than the one it has.
"""

import base64
import hashlib
import json
import os
import secrets
import sys

# ---- NIST P-256 -------------------------------------------------------
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

SPKI_PREFIX = bytes.fromhex(
    "3059301306072a8648ce3d020106082a8648ce3d030107034200")

PRIVATE_FILE = "config_key.private.json"
PUBLIC_FILE = "config_key.public.txt"
SIGNED_FILE = "app_config.signed.json"


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, point):
    result, addend = None, point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def _on_curve(pt):
    x, y = pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def public_der(d):
    x, y = _mul(d, G)
    return SPKI_PREFIX + b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _der_int(v):
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def sign(d, data):
    z = int.from_bytes(hashlib.sha256(data).digest(), "big")
    while True:
        k = secrets.randbelow(N - 1) + 1
        r = _mul(k, G)[0] % N
        if r == 0:
            continue
        s = pow(k, -1, N) * (z + r * d) % N
        if s == 0:
            continue
        if s > N // 2:          # low-S form
            s = N - s
        body = _der_int(r) + _der_int(s)
        return b"\x30" + bytes([len(body)]) + body


def _parse_der_sig(sig):
    if sig[0] != 0x30 or sig[1] != len(sig) - 2:
        raise ValueError("bad signature encoding")
    i, out = 2, []
    for _ in range(2):
        if sig[i] != 0x02:
            raise ValueError("bad signature encoding")
        ln = sig[i + 1]
        out.append(int.from_bytes(sig[i + 2:i + 2 + ln], "big"))
        i += 2 + ln
    return out


def verify(pub_der, data, sig):
    if not pub_der.startswith(SPKI_PREFIX) or len(pub_der) != len(SPKI_PREFIX) + 65:
        raise ValueError("bad public key")
    raw = pub_der[len(SPKI_PREFIX) + 1:]
    q = (int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    if not _on_curve(q):
        return False
    r, s = _parse_der_sig(sig)
    if not (0 < r < N and 0 < s < N):
        return False
    z = int.from_bytes(hashlib.sha256(data).digest(), "big")
    w = pow(s, -1, N)
    pt = _add(_mul(z * w % N, G), _mul(r * w % N, q))
    return pt is not None and pt[0] % N == r


# ---- config checks ----------------------------------------------------

def check_config(cfg):
    errors = []
    if not isinstance(cfg.get("version"), int) or cfg["version"] < 1:
        errors.append('"version" must be a positive integer')
    servers = cfg.get("servers") or []
    if not servers:
        errors.append('"servers" is empty')
    for s in servers:
        if not s.get("host") or not isinstance(s.get("port"), int):
            errors.append("each server needs host and port")
    for key in ("sstp_pins", "status_pins", "config_pins"):
        for pin in cfg.get(key, []):
            h = pin.replace(":", "").lower()
            if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
                errors.append("%s: %r is not a SHA-256 fingerprint" % (key, pin))
    if not cfg.get("sstp_pins"):
        errors.append('"sstp_pins" is empty (the app would refuse every server)')
    upd = cfg.get("app_update")
    if upd is not None:
        if not isinstance(upd.get("version_code"), int) or upd["version_code"] < 1:
            errors.append("app_update.version_code must be a positive integer")
        h = str(upd.get("sha256", ""))
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            errors.append("app_update.sha256 is not a SHA-256 hex string")
        if not upd.get("urls"):
            errors.append("app_update.urls is empty")
        if not isinstance(upd.get("size"), int) or upd["size"] < 1:
            errors.append("app_update.size must be a positive integer")
    if cfg.get("status_urls") and not cfg.get("status_pins"):
        errors.append('"status_pins" is empty but "status_urls" is set')
    return errors


def normalise(cfg):
    for key in ("sstp_pins", "status_pins", "config_pins"):
        cfg[key] = [p.replace(":", "").lower() for p in cfg.get(key, [])]
    return cfg


# ---- commands ---------------------------------------------------------

def cmd_genkey():
    if os.path.exists(PRIVATE_FILE):
        print("%s already exists; refusing to overwrite it." % PRIVATE_FILE)
        print("If you replace the key, apps built with the old public key "
              "will reject every new config.")
        return 1
    d = secrets.randbelow(N - 1) + 1
    with open(PRIVATE_FILE, "w", encoding="utf-8") as f:
        json.dump({"curve": "P-256", "d": "%064x" % d}, f)
    pub = base64.b64encode(public_der(d)).decode()
    with open(PUBLIC_FILE, "w", encoding="utf-8") as f:
        f.write(pub + "\n")
    print("private key:", PRIVATE_FILE, "(keep it secret and back it up)")
    print("public key :", PUBLIC_FILE)
    print(pub)
    return 0


def cmd_sign(path):
    with open(PRIVATE_FILE, encoding="utf-8") as f:
        d = int(json.load(f)["d"], 16)
    with open(path, encoding="utf-8") as f:
        cfg = normalise(json.load(f))
    errors = check_config(cfg)
    if errors:
        print("config has problems, nothing signed:")
        for e in errors:
            print(" -", e)
        return 1
    payload = json.dumps(cfg, ensure_ascii=False, separators=(",", ":")).encode()
    sig = sign(d, payload)
    assert verify(public_der(d), payload, sig)
    envelope = {"payload": base64.b64encode(payload).decode(),
                "sig": base64.b64encode(sig).decode()}
    with open(SIGNED_FILE, "w", encoding="utf-8") as f:
        json.dump(envelope, f)
    print("signed version %d -> %s" % (cfg["version"], SIGNED_FILE))
    return 0


def cmd_verify(path):
    with open(PUBLIC_FILE, encoding="utf-8") as f:
        pub = base64.b64decode(f.read().strip())
    with open(path, encoding="utf-8") as f:
        env = json.load(f)
    payload = base64.b64decode(env["payload"])
    ok = verify(pub, payload, base64.b64decode(env["sig"]))
    print("signature:", "OK" if ok else "INVALID")
    if ok:
        print(json.dumps(json.loads(payload), ensure_ascii=False, indent=2))
    return 0 if ok else 1


def cmd_app(apk_path, version_code, version_name=None, notes="", config_path="config.json"):
    import shutil
    with open(config_path, encoding="utf-8") as f:
        cfg = json.load(f)
    with open(apk_path, "rb") as f:
        data = f.read()
    if data[:2] != b"PK":
        print("%s does not look like an APK" % apk_path)
        return 1
    urls = [u.replace("/v1/config", "/v1/app.apk") for u in cfg.get("config_urls", [])
            if u.endswith("/v1/config")]
    if not urls:
        print("no config_urls ending in /v1/config; add app_update.urls by hand")
        return 1
    old = cfg.get("app_update", {}).get("version_code", 0)
    if version_code <= old:
        print("versionCode %d is not higher than the published one (%d)" % (version_code, old))
        return 1
    cfg["app_update"] = {
        "version_code": version_code,
        "version_name": version_name or str(version_code),
        "urls": urls,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "notes": notes,
    }
    cfg["version"] = int(cfg.get("version", 0)) + 1
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
        f.write("\n")
    if os.path.abspath(apk_path) != os.path.abspath("app.apk"):
        shutil.copyfile(apk_path, "app.apk")
    print("app %s (versionCode %d), %.1f MB, sha256 %s"
          % (cfg["app_update"]["version_name"], version_code, len(data) / 1e6,
             cfg["app_update"]["sha256"][:16] + "..."))
    rc = cmd_sign(config_path)
    if rc == 0:
        print("upload to the router's umstatus folder: app.apk and %s" % SIGNED_FILE)
    return rc


def main(argv):
    if len(argv) == 2 and argv[1] == "genkey":
        return cmd_genkey()
    if len(argv) == 3 and argv[1] == "sign":
        return cmd_sign(argv[2])
    if len(argv) == 3 and argv[1] == "verify":
        return cmd_verify(argv[2])
    if 4 <= len(argv) <= 6 and argv[1] == "app":
        return cmd_app(argv[2], int(argv[3]),
                       argv[4] if len(argv) > 4 else None,
                       argv[5] if len(argv) > 5 else "")
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
