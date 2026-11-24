#!/usr/bin/env python3
"""E1b DNP3 transport worker (process A): deliver ONE load-multiplier setpoint
over a real DNP3 session and read it back off the live outstation.

Runs in its OWN process with ~/dnp3_310/bin/python. Imports dnp3_python / pydnp3
ONLY -- it must never import opendssdirect, because the opendnp3 C++/asio runtime
and the OpenDSS native library segfault when co-resident in one interpreter. The
OpenDSS physics is done by e1b_run.py in a separate process; this worker's sole
job is to make the setpoint travel over a genuine DNP3 master->outstation link and
report the value the outstation actually latched.

A real opendnp3 outstation (MyOutStation) and master (MyMaster) open a real TCP
session on 127.0.0.1:21007. The master issues an AnalogOutputFloat32 DirectOperate
to group 41 / index 0 (the load multiplier); the outstation reflects it in its
group-40 AO status; control_common.read_outstation_status reads that status back
off the live outstation object. The delivered value is written to --out as JSON
for the orchestrator to consume.
"""
import argparse
import json
import sys
import time
from pathlib import Path

PILOT = Path.home() / "data/dnp3_pilot"
sys.path.insert(0, str(PILOT))
import control_common as cc                                   # noqa: E402
from dnp3_python.dnp3station.master import MyMaster           # noqa: E402
from dnp3_python.dnp3station.outstation import MyOutStation   # noqa: E402
from pydnp3 import opendnp3                                   # noqa: E402

HOST = "127.0.0.1"


def is_conn(m):
    s = getattr(m, "is_connected", None)
    try:
        s = s() if callable(s) else s
    except Exception:  # noqa: BLE001
        return False
    return bool(s)


def deliver(load_mult, connect_timeout, readback_timeout):
    log = {"requested_load_mult": load_mult}
    out = MyOutStation(port=cc.PORT, outstation_id=cc.STATION_ID, master_id=1)
    out.start()
    time.sleep(1.0)
    _sup0, base_status, method = cc.read_outstation_status(out)
    log["readback_method"] = method
    log["outstation_baseline_status"] = base_status
    mas = MyMaster(outstation_ip=HOST, port=cc.PORT, master_id=1, outstation_id=cc.STATION_ID)
    mas.start()
    t0 = time.monotonic()
    while time.monotonic() - t0 < connect_timeout and not is_conn(mas):
        time.sleep(0.25)
    log["dnp3_connected"] = is_conn(mas)
    observed = None
    if log["dnp3_connected"]:
        cmd = opendnp3.AnalogOutputFloat32(float(load_mult))
        mas.send_direct_operate_command(cmd, index=cc.INDEX, callback=lambda r: None)
        t0 = time.monotonic()
        while time.monotonic() - t0 < readback_timeout:
            _sup, val, _ = cc.read_outstation_status(out)
            if val is not None and (abs(val - load_mult) < 1e-4
                                    or base_status is None or abs(val - base_status) > 1e-6):
                observed = val
                break
            time.sleep(0.2)
        log["roundtrip_s"] = round(time.monotonic() - t0, 3)
    for obj in (mas, out):
        try:
            obj.shutdown()
        except Exception:  # noqa: BLE001
            pass
    log["dnp3_status_readback"] = observed
    log["dnp3_delivered"] = observed is not None
    return log


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--load-mult", type=float, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--connect-timeout", type=float, default=20.0)
    ap.add_argument("--readback-timeout", type=float, default=12.0)
    a = ap.parse_args()
    log = deliver(a.load_mult, a.connect_timeout, a.readback_timeout)
    Path(a.out).write_text(json.dumps(log))
    print(json.dumps(log), flush=True)


if __name__ == "__main__":
    main()
