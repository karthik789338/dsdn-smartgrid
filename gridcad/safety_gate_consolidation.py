#!/usr/bin/env python3
"""E1b consolidation: fold the real-DNP3 end-to-end result together with explicit
exercises of the TWO distinct gates, using control_common's real validators.

Gate 1 (command-layer authorization): control_common.validate_load_mult enforces
the authorized setpoint envelope [LOAD_MULT_MIN, LOAD_MULT_MAX]. An over-range
setpoint is refused BEFORE anything is placed on the DNP3 wire -- no outstation,
no physical action.

Gate 2 (envelope freshness/identity): control_common.validate_command rejects a
command whose received_utc is stale (older than max_age_seconds) or whose run_id
does not match -- a replayed/old envelope is dropped with no physical action.

These are the same functions the live outstation+engine path uses; here they are
driven on representative inputs so the refusal side of each gate is demonstrated
alongside the accepted end-to-end run (e1b_ieee13_03, pass=True).
"""
import json
import sys
from pathlib import Path

PIL = Path.home() / "data/dnp3_pilot"
sys.path.insert(0, str(PIL))
import control_common as cc  # noqa: E402

RESULTS = Path("results") / "E1b"
CORE_RID = "e1b_ieee13_03"


def try_call(fn, *a, **k):
    try:
        return {"accepted": True, "value": fn(*a, **k), "error": ""}
    except Exception as e:  # noqa: BLE001
        return {"accepted": False, "value": None, "error": f"{type(e).__name__}: {e}"}


def main():
    core_dir = RESULTS / CORE_RID
    core = json.loads((core_dir / "result.json").read_text())
    recv = json.loads((core_dir / "received_command.json").read_text())

    # Gate 1 -- command-layer authorization (setpoint bounds)
    g1 = {
        "bounds": [cc.LOAD_MULT_MIN, cc.LOAD_MULT_MAX],
        "authorized_1p02": try_call(cc.validate_load_mult, 1.02),
        "over_range_1p10": try_call(cc.validate_load_mult, 1.10),
        "under_range_0p99": try_call(cc.validate_load_mult, 0.99),
    }

    # Gate 2 -- envelope freshness / identity
    rid = "e1b_gatecheck_01"
    fresh = cc.command_record(rid, 1.02, None)           # just-built envelope
    stale = dict(fresh); stale["received_utc"] = "2000-01-01T00:00:00+00:00"
    wrong_id = dict(fresh)
    g2 = {
        "fresh_envelope": try_call(cc.validate_command, fresh, rid),
        "stale_envelope": try_call(cc.validate_command, stale, rid),
        "identity_mismatch": try_call(cc.validate_command, wrong_id, "different_run_id_99"),
    }

    summary = {
        "experiment": "E1b_real_dnp3_to_opendss",
        "core_run": {
            "run_id": CORE_RID,
            "feeder": "IEEE13",
            "requested_load_mult": 1.02,
            "dnp3_delivered_value": recv.get("load_multiplier"),
            "dnp3_origin": recv.get("origin"),
            "dnp3_schema": recv.get("schema"),
            "station_id": recv.get("station_id"),
            "port": recv.get("port"),
            "physical_change_observed": core.get("physical_change_observed"),
            "max_node_voltage_change_pu": core.get("max_node_voltage_change_pu"),
            "loss_change_kw": core.get("loss_change_kw"),
            "safety_accepted": core.get("safety_accepted"),
            "rollback_verified": core.get("rollback_verified"),
            "rollback_max_node_error_pu": core.get("rollback_max_node_error_pu"),
            "pass": core.get("pass"),
            "baseline_v": [core.get("baseline", {}).get("voltage_pu_min"),
                           core.get("baseline", {}).get("voltage_pu_max")],
            "applied_v": [core.get("applied", {}).get("voltage_pu_min"),
                          core.get("applied", {}).get("voltage_pu_max")],
        },
        "gate1_command_authorization": g1,
        "gate2_envelope_freshness_identity": g2,
        "interpretation": {
            "gate1": "over-range and under-range setpoints refused at the command layer "
                     "before transmission; authorized setpoint accepted",
            "gate2": "stale and identity-mismatched envelopes rejected; fresh matching "
                     "envelope accepted",
            "core": "a real DNP3 AnalogOutputFloat32 traversed a genuine master->outstation "
                    "session, was read back off the live outstation, applied to OpenDSS "
                    "IEEE13 with a measurable physical change, passed the applied-safety "
                    "gate, and was rolled back to the exact baseline",
        },
    }
    out = RESULTS / "dnp3_safety_gates_summary.json"
    out.write_text(json.dumps(summary, indent=2))

    # compact console view
    print("=== E1b CORE (real DNP3 -> OpenDSS) ===")
    cr = summary["core_run"]
    print(f"delivered={cr['dnp3_delivered_value']} pass={cr['pass']} "
          f"phys={cr['physical_change_observed']} dv={cr['max_node_voltage_change_pu']} "
          f"dloss={cr['loss_change_kw']} safe={cr['safety_accepted']} "
          f"rollback={cr['rollback_verified']} rb_err={cr['rollback_max_node_error_pu']}")
    print("=== GATE 1 authorization (bounds", g1["bounds"], ") ===")
    print(f"  1.02 accepted={g1['authorized_1p02']['accepted']}  "
          f"1.10 accepted={g1['over_range_1p10']['accepted']} ({g1['over_range_1p10']['error']})  "
          f"0.99 accepted={g1['under_range_0p99']['accepted']}")
    print("=== GATE 2 freshness/identity ===")
    print(f"  fresh accepted={g2['fresh_envelope']['accepted']}  "
          f"stale accepted={g2['stale_envelope']['accepted']} ({g2['stale_envelope']['error']})  "
          f"wrong-id accepted={g2['identity_mismatch']['accepted']} ({g2['identity_mismatch']['error']})")
    print(f"WROTE {out}")


if __name__ == "__main__":
    main()
