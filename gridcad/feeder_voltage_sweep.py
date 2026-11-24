#!/usr/bin/env python3
"""E1 physical-outcome sweep (reuses the opendss_safety_engine pilot engine).

For a load-altering DNP3 control command (AO group 41 / index 0 -> global load
multiplier), map the physical consequence across the action space and record,
per action, the two independent gate verdicts the pilot already enforces:

  command_authorized : control_common.validate_load_mult bounds+schema check
                       (an out-of-band attacker command is refused PRE-application,
                        so no physical action occurs)
  applied_safety_ok  : opendss_safety_engine.check_applied_safety(baseline, applied)
                       (a command inside bounds whose physical effect worsens a
                        voltage deviation is caught POST-solve, before commit)

Deterministic physical oracle for E3 (load-command action dimension): for any
requested load multiplier the exact feeder outcome and the correct verdict are
known. Physics + gate only; no DNP3 transport, no ONOS. Runs in e1_venv.

v2: recompile per point (stateless, order-independent, matches the pilot);
    tolerate non-convergence at high load on long feeders (34/123);
    None-safe summary.
"""
import argparse, csv, importlib, json, sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--pilot", default=str(Path.home() / "data/dnp3_pilot"))
ap.add_argument("--model", default=str(Path.home() / "data/feeders/electricdss-tst/"
                "Version8/Distrib/IEEETestCases/13Bus/IEEE13Nodeckt.dss"))
ap.add_argument("--feeder", default="IEEE13")
ap.add_argument("--lo", type=float, default=0.80)
ap.add_argument("--hi", type=float, default=1.30)
ap.add_argument("--step", type=float, default=0.01)
ap.add_argument("--out", default=str(Path("results") / "E1_phys"))
args = ap.parse_args()

sys.path.insert(0, args.pilot)
E = importlib.import_module("opendss_safety_engine")
cc = importlib.import_module("control_common")
import opendssdirect  # noqa: E402
from opendssdirect import dss  # noqa: E402

model = Path(args.model)
assert model.is_file(), f"missing model {model}"
outdir = Path(args.out); outdir.mkdir(parents=True, exist_ok=True)

FIELDS = ["feeder", "load_mult", "command_authorized", "authorized_reason",
          "voltage_pu_min", "voltage_pu_max", "undervoltage_nodes", "overvoltage_nodes",
          "max_node_dv_pu", "loss_change_kw", "losses_kw", "applied_safety_ok",
          "safety_issues", "pilot_deployed_outcome"]


def frange(lo, hi, step):
    n = round((hi - lo) / step)
    vals = [round(lo + i * step, 6) for i in range(n + 1)]
    for v in (cc.LOAD_MULT_MIN, cc.LOAD_MULT_MAX, 1.0, 1.02):
        if not any(abs(v - x) < 1e-9 for x in vals):
            vals.append(round(v, 6))
    return sorted(set(vals))


def authorized(lm):
    try:
        cc.validate_load_mult(lm); return True, ""
    except Exception as e:  # noqa: BLE001
        return False, str(e)


def solve_compile():
    dss.Command("Clear")
    dss.Command(f'Compile "{model.resolve()}"')


def row(**kw):
    r = {k: None for k in FIELDS}; r.update(kw); return r


def main():
    solve_compile()
    baseline = E.capture(dss, "baseline")
    base_lm = baseline["load_multiplier"]
    rows = []
    for lm in frange(args.lo, args.hi, args.step):
        auth, auth_reason = authorized(lm)
        try:
            solve_compile()
            dss.Solution.LoadMult(lm)
            applied = E.capture(dss, f"lm_{lm}")
        except RuntimeError as e:
            rows.append(row(feeder=args.feeder, load_mult=lm, command_authorized=auth,
                            authorized_reason=auth_reason, safety_issues=str(e),
                            pilot_deployed_outcome="non_convergent"))
            continue
        delta = E.voltage_delta(baseline, applied)
        loss_delta = applied["losses_kw"] - baseline["losses_kw"]
        safe_ok, issues = E.check_applied_safety(baseline, applied)
        if auth:
            outcome = "applied_safe" if safe_ok else "applied_rejected_by_physics_gate"
        else:
            outcome = "refused_pre_application"
        rows.append(row(
            feeder=args.feeder, load_mult=lm, command_authorized=auth, authorized_reason=auth_reason,
            voltage_pu_min=round(applied["voltage_pu_min"], 5),
            voltage_pu_max=round(applied["voltage_pu_max"], 5),
            undervoltage_nodes=applied["undervoltage_nodes"], overvoltage_nodes=applied["overvoltage_nodes"],
            max_node_dv_pu=round(delta, 6), loss_change_kw=round(loss_delta, 4),
            losses_kw=round(applied["losses_kw"], 4), applied_safety_ok=safe_ok,
            safety_issues="; ".join(issues), pilot_deployed_outcome=outcome))

    solve_compile(); dss.Solution.LoadMult(base_lm)
    try:
        restored = E.capture(dss, "restored"); rollback_dv = E.voltage_delta(baseline, restored)
    except RuntimeError:
        rollback_dv = None

    with open(outdir / "per_load_mult.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(rows)

    def onset(key):
        hits = [r["load_mult"] for r in rows if isinstance(r[key], int) and r[key] > 0]
        return min(hits) if hits else None
    auth_band = [r["load_mult"] for r in rows if r["command_authorized"]]
    phys_reject = [r["load_mult"] for r in rows
                   if r["command_authorized"] and r["applied_safety_ok"] is False]
    nonconv = [r["load_mult"] for r in rows if r["pilot_deployed_outcome"] == "non_convergent"]
    summary = {
        "feeder": args.feeder, "model_path": str(model),
        "model_sha256": E.hashlib.sha256(model.read_bytes()).hexdigest(),
        "opendss": getattr(opendssdirect, "__version__", "unknown"),
        "baseline": {k: baseline[k] for k in
                     ("load_multiplier", "voltage_pu_min", "voltage_pu_max",
                      "undervoltage_nodes", "overvoltage_nodes", "losses_kw", "node_count")},
        "sweep": {"lo": args.lo, "hi": args.hi, "step": args.step, "points": len(rows)},
        "command_auth_band": [min(auth_band), max(auth_band)] if auth_band else None,
        "pilot_safe_band_const": [cc.LOAD_MULT_MIN, cc.LOAD_MULT_MAX],
        "undervoltage_onset_lm": onset("undervoltage_nodes"),
        "overvoltage_onset_lm": onset("overvoltage_nodes"),
        "authorized_but_physics_rejected_lm": phys_reject,
        "non_convergent_lm": nonconv,
        "rollback_max_dv_pu": None if rollback_dv is None else round(rollback_dv, 8),
        "rollback_clean": None if rollback_dv is None else (rollback_dv < 1e-6),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    print(f"\nwrote {outdir/'per_load_mult.csv'} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
