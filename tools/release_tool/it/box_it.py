"""Integration test of «Xray روی میکروتیک»: a container on a RouterOS CHR (C)
runs Xray and pv-agent, User Manager 2 (B, left by linux_it.py) holds the
users. Real clients on this runner connect with each protocol through the
CHR's dst-nat (QEMU forwards the ports).

Run after linux_it.py, with CHR C booted (ports in BOX_PORTS forwarded).
"""

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "server", "linux"))
import chr as base          # noqa: E402
import linux_it as lit      # noqa: E402

base.VM.update({"C": {"ssh": 2224}})
BOX_PORTS = {"vision_port": 30443, "xhttp_port": 30444, "hy2_port": 30445, "ss_port": 30446, "status_port": 30447}
# the box reaches UM2 through QEMU's host address
REACH = {"B": {"host": base.SLIRP_HOST, "rest_port": 29443, "auth_port": 2812, "acct_port": 2813}}


def main():
    import mtxray
    import provision as pv
    import services as sv

    lit.step("C: container package and device-mode")
    connect = base.connector("C")
    r = connect()
    r = pv.install_packages(r, connect, ["container"], log=print)
    if not sv.device_mode_container(r):
        pv.request_container_mode(r)
        r.close()
        time.sleep(5)
        base.power_cycle("C")
        r = base.wait_ssh("C")
    assert sv.device_mode_container(r), "device-mode container still off"
    r.close()

    before = lit.um_usage("B", lit.USER).count("started")
    lit.step("setup: Xray in a container on C, users from UM2 (B)")
    params, entry = mtxray.setup_box(connect, [(base.connector("B"), "B")], "box1", "127.0.0.1",
                                     params=dict(BOX_PORTS, interval=10), log=print,
                                     router_addresses=REACH, seen_ip=base.SLIRP_HOST)
    print(json.dumps(entry, indent=1))
    problems = []
    for k, v in BOX_PORTS.items():
        if params[k] != v:
            problems.append("%s moved to %s" % (k, params[k]))
    if any(p["type"] == "amneziawg" for p in entry["protocols"]):
        problems.append("the box entry offers AmneziaWG")

    lit.step("clients with the right password")
    res = {}
    for _ in range(12):          # pv-agent's first round lets the users in
        time.sleep(10)
        res = lit.run_clients(entry, lit.USER, lit.PASS, bulk=True)
        if all(c == "204" for c in res.values()):
            break
    with connect() as r:
        print(mtxray.box_log(r))
    if not res or any(c != "204" for c in res.values()):
        problems.append("box clients: %s" % res)

    lit.step("a wrong password must fail")
    bad = lit.run_clients(entry, lit.USER, "wrong-pw", only=["vision", "ss"])
    if any(c == "204" for c in bad.values()):
        problems.append("wrong password let in: %s" % bad)

    lit.step("accounting reached User Manager 2")
    time.sleep(40)
    if lit.um_usage("B", lit.USER).count("started") <= before:
        problems.append("no accounting from the box on UM2")

    lit.step("set up again (re-run keeps keys and ports)")
    params2, entry2 = mtxray.setup_box(connect, [(base.connector("B"), "B")], "box1", "127.0.0.1",
                                       params=params, log=print, router_addresses=REACH, seen_ip=base.SLIRP_HOST)
    if params2["reality_public"] != params["reality_public"] or params2["hy2_pin"] != params["hy2_pin"]:
        problems.append("keys changed on re-run")
    time.sleep(20)
    res = lit.run_clients(entry2, lit.USER, lit.PASS, only=["vision"])
    if res.get("vision") != "204":
        problems.append("after re-run: %s" % res)

    lit.step("remove")
    with connect() as r:
        mtxray.remove(r, log=print)
        if sv.count(r, "/ip firewall nat", 'comment="pv-xray"'):
            problems.append("nat rules left")

    if problems:
        raise SystemExit("PROBLEMS:\n  " + "\n  ".join(problems))
    print("\nBOX ALL OK")


if __name__ == "__main__":
    main()
