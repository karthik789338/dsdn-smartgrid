#!/usr/bin/env python3
"""E1b: real DNP3 command -> OpenDSS physical change, end to end, in one process.

Uses the opendss_safety_engine pilot's own pieces unchanged:
  - a REAL opendnp3 outstation (MyOutStation) and master (MyMaster) over a real
    TCP session on 127.0.0.1:21007,
  - the master issues a real AnalogOutputFloat32 DirectOperate to group 41 / index 0
    (the load multiplier); the outstation reflects it in its group-40 AO status,
  - control_common.read_outstation_status reads that status back off the live
    outstation object (the real delivered value, not a file),
  - control_common.validate_load_mult / validate_command gate the command,
  - opendss_safety_engine.capture / check_applied_safety compute the OpenDSS consequence and
    the safety verdict, with rollback.

This is the cyber path made real: the value applied to OpenDSS is the one that
arrived over DNP3, not a number passed in code. Runs with ~/dnp3_310/bin/python
(has dnp3_python AND opendssdirect). No Mininet/ONOS yet; switch traversal is the
E1b->E2 step. Requires no root.
"""
import argparse, json, sys, time, uuid
from pathlib import Path

PILOT = Path.home() / "data/dnp3_pilot"
sys.path.insert(0, str(PILOT))
import control_common as cc           # noqa: E402
import opendss_safety_engine as E               # noqa: E402
from opendssdirect import dss         # noqa: E402
from dnp3_python.dnp3station.master import MyMaster        # noqa: E402
from dnp3_python.dnp3station.outstation import MyOutStation  # noqa: E402
from pydnp3 import opendnp3           # noqa: E402

HOST = "127.0.0.1"
FEEDERS = {
    "IEEE13": "13Bus/IEEE13Nodeckt.dss",
    "IEEE34": "34Bus/ieee34Mod1.dss",
    "IEEE123": "123Bus/IEEE123Master.dss",
}
BASE = Path.home() / "data/feeders/electricdss-tst/Version8/Distrib/IEEETestCases"

ap = argparse.ArgumentParser()
ap.add_argument("--out", default=str(Path("results") / "dnp3_opendss_endtoend"))
ap.add_argument("--connect-timeout", type=float, default=20.0)
ap.add_argument("--readback-timeout", type=float, default=12.0)
args = ap.parse_args()
OUT = Path(args.out).resolve(); OUT.mkdir(parents=True, exist_ok=True)


def compile_capture(model, label):
    dss.Command("Clear")
    dss.Command(f'Compile "{Path(model).resolve()}"')
    return E.capture(dss, label)


def is_conn(m):
    s = getattr(m, "is_connected", None)
    try:
        s = s() if callable(s) else s
    except Exception:  # noqa: BLE001
        return False
    return bool(s)


def deliver_over_dnp3(load_mult, log):
    """Start a real outstation+master, send one AO command, read the status back."""
    out = MyOutStation(port=cc.PORT, outstation_id=cc.STATION_ID, master_id=1)
    out.start(); time.sleep(1.0)
    sup0, base_status, method = cc.read_outstation_status(out)
    log["readback_method"] = method
    log["outstation_baseline_status"] = base_status
    mas = MyMaster(outstation_ip=HOST, port=cc.PORT, master_id=1, outstation_id=cc.STATION_ID)
    mas.start()
    t0 = time.monotonic()
    while time.monotonic() - t0 < args.connect_timeout and not is_conn(mas):
        time.sleep(0.25)
    log["dnp3_connected"] = is_conn(mas)
    observed = None
    if log["dnp3_connected"]:
        cmd = opendnp3.AnalogOutputFloat32(float(load_mult))
        mas.send_direct_operate_command(cmd, index=cc.INDEX, callback=lambda r: None)
        t0 = time.monotonic()
        while time.monotonic() - t0 < args.readback_timeout:
            sup, val, _ = cc.read_outstation_status(out)
            if val is not None and (abs(val - load_mult) < 1e-4
                                    or base_status is None or abs(val - base_status) > 1e-6):
                observed = val; break
            time.sleep(0.2)
    try:
        mas.shutdown()
    except Exception:  # noqa: BLE001
        pass
    try:
        out.shutdown()
    except Exception:  # noqa: BLE001
        pass
    return observed, base_status


def one_run(feeder, load_mult, mode, stale=False):
    model = BASE / FEEDERS[feeder]
    run_id = f"e1b-{uuid.uuid4().hex[:10]}"
    r = {"run_id": run_id, "feeder": feeder, "mode": mode,
         "requested_load_mult": load_mult, "nodes": None}
    try:
        cc.validate_load_mult(load_mult); r["command_authorized"] = True; r["auth_reason"] = ""
    except Exception as e:  # noqa: BLE001
        r["command_authorized"] = False; r["auth_reason"] = str(e)

    baseline = compile_capture(model, "baseline")
    r["nodes"] = baseline["node_count"]
    r["baseline_v_min"] = round(baseline["voltage_pu_min"], 5)
    r["baseline_v_max"] = round(baseline["voltage_pu_max"], 5)

    observed, base_status = deliver_over_dnp3(load_mult, r)
    r["dnp3_status_readback"] = observed
    r["dnp3_delivered"] = observed is not None
    if observed is None:
        r["outcome"] = "dnp3_not_delivered"; return r

    # command-envelope validation (identity + freshness); stale => reject, no action
    env = cc.command_record(run_id, observed, base_status)
    if stale:
        env["received_utc"] = "2000-01-01T00:00:00+00:00"
    try:
        applied_mult = cc.validate_command(env, run_id)
    except Exception as e:  # noqa: BLE001
        r["outcome"] = "command_rejected_no_physical_action"; r["reason"] = str(e); return r

    if not r["command_authorized"]:
        r["outcome"] = "refused_pre_application"; return r

    dss.Solution.LoadMult(applied_mult)
    applied = E.capture(dss, "applied")
    r["applied_v_min"] = round(applied["voltage_pu_min"], 5)
    r["applied_v_max"] = round(applied["voltage_pu_max"], 5)
    r["max_node_dv_pu"] = round(E.voltage_delta(baseline, applied), 6)
    r["loss_change_kw"] = round(applied["losses_kw"] - baseline["losses_kw"], 4)
    r["physical_change_observed"] = r["max_node_dv_pu"] > 1e-6
    safe_ok, issues = E.check_applied_safety(baseline, applied)
    r["applied_safety_ok"] = safe_ok
    r["safety_issues"] = "; ".join(issues)

    dss.Solution.LoadMult(baseline["load_multiplier"])
    restored = E.capture(dss, "restored")
    r["rollback_max_dv_pu"] = round(E.voltage_delta(baseline, restored), 8)
    r["outcome"] = "applied_safe_rolled_back" if safe_ok else "physics_rejected_rolled_back"
    return r


PLAN = [
    ("IEEE13", 1.02, "authorized_safe_expected"),
    ("IEEE34", 1.02, "authorized_physics_reject_expected"),
    ("IEEE123", 1.02, "authorized_safe_expected"),
    ("IEEE13", 1.10, "over_range_refused_expected"),       # command-layer gate
]


def main():
    rows = []
    for feeder, lm, mode in PLAN:
        print(f"RUN {feeder} lm={lm} ({mode})", flush=True)
        r = one_run(feeder, lm, mode, stale=False)
        rows.append(r)
        print(f"  -> delivered={r.get('dnp3_delivered')} outcome={r.get('outcome')} "
              f"dv={r.get('max_node_dv_pu')} safe={r.get('applied_safety_ok')}", flush=True)
    # explicit stale-command negative control (fresh DNP3 delivery, stale envelope)
    print("RUN IEEE13 lm=1.02 (stale_envelope_reject_expected)", flush=True)
    r = one_run("IEEE13", 1.02, "stale_envelope_reject_expected", stale=True)
    rows.append(r)
    print(f"  -> delivered={r.get('dnp3_delivered')} outcome={r.get('outcome')}", flush=True)

    with open(OUT / "per_run.jsonl", "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    summary = {"runs": len(rows),
               "results": [{k: r.get(k) for k in
                            ("feeder", "mode", "requested_load_mult", "command_authorized",
                             "dnp3_delivered", "dnp3_status_readback", "max_node_dv_pu",
                             "applied_safety_ok", "rollback_max_dv_pu", "outcome")} for r in rows]}
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
