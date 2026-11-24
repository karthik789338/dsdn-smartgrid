#!/usr/bin/env python3
"""E1b orchestrator (process B): real DNP3 command -> OpenDSS physical change.

Runs with ~/dnp3_310/bin/python. Imports opendssdirect ONLY (plus pure-stdlib
control_common / opendss_safety_engine) -- it must never import pydnp3, which would re-create
the native-runtime segfault. For each plan row it:

  1. compiles the feeder in OpenDSS and captures the baseline (this process),
  2. spawns e1b_transport.py as a SEPARATE process to carry the load-multiplier
     setpoint over a genuine DNP3 master->outstation session and read it back,
  3. reads the delivered value from the worker's JSON,
  4. gates it with control_common.validate_load_mult (command-layer authorization)
     and control_common.validate_command (envelope identity + freshness),
  5. applies the DELIVERED value to OpenDSS, captures the consequence, runs
     opendss_safety_engine.check_applied_safety (the physics / applied-safety gate), then
     rolls back.

The value applied to OpenDSS is the one that arrived over DNP3, not a number
passed in code -- the cyber path and the physical outcome are joined end to end,
with the two gates (command-authorized + applied-safety) kept distinct. No
Mininet/ONOS switch traversal yet; that is the E1b->E2 step. Needs no root.
"""
import argparse
import json
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

PILOT = Path.home() / "data/dnp3_pilot"
sys.path.insert(0, str(PILOT))
import control_common as cc    # noqa: E402  (stdlib-only)
import opendss_safety_engine as E        # noqa: E402  (stdlib-only; dss passed in)
from opendssdirect import dss  # noqa: E402

HOST_PY = str(Path.home() / "dnp3_310/bin/python")
TRANSPORT = str(Path(__file__).resolve().parent / "e1b_transport.py")
FEEDERS = {
    "IEEE13": "13Bus/IEEE13Nodeckt.dss",
    "IEEE34": "34Bus/ieee34Mod1.dss",
    "IEEE123": "123Bus/IEEE123Master.dss",
}
BASE = Path.home() / "data/feeders/electricdss-tst/Version8/Distrib/IEEETestCases"


def compile_capture(model, label):
    dss.Command("Clear")
    dss.Command(f'Compile "{Path(model).resolve()}"')
    return E.capture(dss, label)


def deliver_over_dnp3(load_mult):
    """Spawn the DNP3 transport worker (separate process) and return its log."""
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        out_path = tf.name
    proc = subprocess.run(
        [HOST_PY, TRANSPORT, "--load-mult", repr(float(load_mult)), "--out", out_path],
        capture_output=True, text=True, timeout=90,
    )
    try:
        log = json.loads(Path(out_path).read_text())
    except Exception:  # noqa: BLE001
        log = {"dnp3_delivered": False, "dnp3_status_readback": None,
               "worker_rc": proc.returncode, "worker_stderr": proc.stderr[-500:]}
    finally:
        Path(out_path).unlink(missing_ok=True)
    log["worker_rc"] = proc.returncode
    return log


def one_run(feeder, load_mult, mode, stale=False):
    model = BASE / FEEDERS[feeder]
    run_id = f"e1b-{uuid.uuid4().hex[:10]}"
    r = {"run_id": run_id, "feeder": feeder, "mode": mode,
         "requested_load_mult": load_mult, "nodes": None}
    try:
        cc.validate_load_mult(load_mult)
        r["command_authorized"] = True
        r["auth_reason"] = ""
    except Exception as e:  # noqa: BLE001
        r["command_authorized"] = False
        r["auth_reason"] = str(e)

    baseline = compile_capture(model, "baseline")
    r["nodes"] = baseline["node_count"]
    r["baseline_v_min"] = round(baseline["voltage_pu_min"], 5)
    r["baseline_v_max"] = round(baseline["voltage_pu_max"], 5)

    log = deliver_over_dnp3(load_mult)
    observed = log.get("dnp3_status_readback")
    r["dnp3_connected"] = log.get("dnp3_connected")
    r["readback_method"] = log.get("readback_method")
    r["dnp3_status_readback"] = observed
    r["dnp3_delivered"] = bool(log.get("dnp3_delivered"))
    r["worker_rc"] = log.get("worker_rc")
    base_status = log.get("outstation_baseline_status")
    if observed is None:
        r["outcome"] = "dnp3_not_delivered"
        return r

    # command-envelope validation (identity + freshness); stale => reject, no action
    env = cc.command_record(run_id, observed, base_status)
    if stale:
        env["received_utc"] = "2000-01-01T00:00:00+00:00"
    try:
        applied_mult = cc.validate_command(env, run_id)
    except Exception as e:  # noqa: BLE001
        r["outcome"] = "command_rejected_no_physical_action"
        r["reason"] = str(e)
        return r

    if not r["command_authorized"]:
        r["outcome"] = "refused_pre_application"
        return r

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
    ("IEEE13", 1.10, "over_range_refused_expected"),   # command-layer gate
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path("results") / "E1b_realdnp3"))
    a = ap.parse_args()
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    rows = []
    for feeder, lm, mode in PLAN:
        print(f"RUN {feeder} lm={lm} ({mode})", flush=True)
        r = one_run(feeder, lm, mode, stale=False)
        rows.append(r)
        print(f"  -> connected={r.get('dnp3_connected')} delivered={r.get('dnp3_delivered')} "
              f"outcome={r.get('outcome')} dv={r.get('max_node_dv_pu')} "
              f"safe={r.get('applied_safety_ok')}", flush=True)
    print("RUN IEEE13 lm=1.02 (stale_envelope_reject_expected)", flush=True)
    r = one_run("IEEE13", 1.02, "stale_envelope_reject_expected", stale=True)
    rows.append(r)
    print(f"  -> delivered={r.get('dnp3_delivered')} outcome={r.get('outcome')}", flush=True)

    with open(out / "per_run.jsonl", "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    summary = {"runs": len(rows),
               "results": [{k: r.get(k) for k in
                            ("feeder", "mode", "requested_load_mult", "command_authorized",
                             "dnp3_connected", "dnp3_delivered", "dnp3_status_readback",
                             "max_node_dv_pu", "applied_safety_ok", "rollback_max_dv_pu",
                             "outcome")} for r in rows]}
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
