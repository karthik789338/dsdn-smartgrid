#!/usr/bin/env python3
"""E3 (consequence-aware authorization vs baselines) -- physics side.

Scores competing authorization methods against the OpenDSS physical-outcome
ORACLE from E1, not against templates. The decision task: given a proposed DNP3
load-setpoint command on a feeder, ALLOW or BLOCK it.

ORACLE (ground truth): apply the setpoint in OpenDSS and run the pilot's
opendss_safety_engine.check_applied_safety -- ALLOW iff the resulting operating point is
physically safe, else BLOCK. This is exactly the E1 physics gate, used here as
the label.

Methods decided in this (OpenDSS) process, each FROZEN before scoring:
  command_bound_rule : ALLOW iff setpoint in the pilot's fixed band [1.005,1.030]
                       (no feeder/physics awareness) -- the pre-registered rule
                       baseline.
  retrieval_knn      : seeded ONLY with IEEE13 (setpoint -> safe?) labels; for a
                       query, copy the nearest IEEE13 setpoint's label (no feeder
                       awareness) -- the retrieval-only baseline.
  physics_verifier   : run OpenDSS on the actual feeder -> equals the oracle (the
                       consequence-aware gate; shows safety comes from the verifier).

The LLM method (phi4-mini reasoning from grid state, no solver) is scored in a
separate process (e3_llm.py, ollama env) over the scenario list written here, so
the two native runtimes never co-reside. e3_consolidate.py merges and reports
per-method accuracy, unsafe-allowed and over-block rates, overall and per feeder.

Baseline provenance: command_bound_rule is the pilot's own published band;
retrieval_knn is seeded only on IEEE13 and frozen before any IEEE34/123 scenario
is scored; neither sees the oracle. Run with the dnp3_310 interpreter.
"""
import argparse
import json
import os
import sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--pilot", default=os.path.expanduser("~/data/dnp3_pilot"))
ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "E3"))
args = ap.parse_args()

sys.path.insert(0, args.pilot)
import opendss_safety_engine as E       # noqa: E402
from opendssdirect import dss  # noqa: E402

BASE = Path.home() / "data/feeders/electricdss-tst/Version8/Distrib/IEEETestCases"
FEEDERS = {
    "IEEE13": "13Bus/IEEE13Nodeckt.dss",
    "IEEE34": "34Bus/ieee34Mod1.dss",
    "IEEE123": "123Bus/IEEE123Master.dss",
}
# proposed load-setpoint commands (DNP3 AO group 41 / load multiplier)
MULTS = [0.99, 1.00, 1.005, 1.01, 1.015, 1.02, 1.025, 1.03, 1.04, 1.05]

# --- frozen baselines (defined before any scoring; neither sees the oracle) ---
PILOT_BAND = (1.005, 1.030)


def command_bound_rule(feeder, mult):
    return "ALLOW" if PILOT_BAND[0] <= mult <= PILOT_BAND[1] else "BLOCK"


def build_ieee13_seed(oracle_by_feeder_mult):
    # retrieval memory: ONLY IEEE13 (mult -> ALLOW/BLOCK) from the oracle labels
    return {m: oracle_by_feeder_mult[("IEEE13", m)] for m in MULTS}


def retrieval_knn(seed, mult):
    nearest = min(seed.keys(), key=lambda s: abs(s - mult))
    return seed[nearest]


def oracle_for(feeder, mult):
    model = (BASE / FEEDERS[feeder]).resolve()
    dss.Command("Clear")
    dss.Command(f'Compile {model}')
    baseline = E.capture(dss, "baseline")
    dss.Solution.LoadMult(mult)
    applied = E.capture(dss, "applied")
    safe_ok, issues = E.check_applied_safety(baseline, applied)
    # recompile-based rollback leaves state clean for the next scenario
    dss.Command("Clear"); dss.Command(f'Compile {model}')
    return ("ALLOW" if safe_ok else "BLOCK"), {
        "baseline_vmin": round(baseline["voltage_pu_min"], 4),
        "baseline_vmax": round(baseline["voltage_pu_max"], 4),
        "applied_vmin": round(applied["voltage_pu_min"], 4),
        "applied_vmax": round(applied["voltage_pu_max"], 4),
        "nodes": baseline["node_count"],
        "safety_issues": "; ".join(issues),
    }


def main():
    os.makedirs(args.out, exist_ok=True)
    # 1) oracle labels for every scenario
    oracle = {}
    context = {}
    for feeder in FEEDERS:
        for m in MULTS:
            label, ctx = oracle_for(feeder, m)
            oracle[(feeder, m)] = label
            context[(feeder, m)] = ctx
            print(f"ORACLE {feeder:8s} mult={m:<6} -> {label}  "
                  f"(base {ctx['baseline_vmin']}-{ctx['baseline_vmax']} -> "
                  f"appl {ctx['applied_vmin']}-{ctx['applied_vmax']})", flush=True)

    # 2) frozen baselines (retrieval seeded on IEEE13 only)
    seed = build_ieee13_seed(oracle)

    rows = []
    scen_list = []
    for feeder in FEEDERS:
        for m in MULTS:
            o = oracle[(feeder, m)]
            ctx = context[(feeder, m)]
            rows.append({
                "feeder": feeder, "mult": m, "nodes": ctx["nodes"],
                "oracle": o,
                "command_bound_rule": command_bound_rule(feeder, m),
                "retrieval_knn": retrieval_knn(seed, m),
                "physics_verifier": o,   # runs OpenDSS on the real feeder = oracle
                **ctx,
            })
            # minimal context for the LLM (grid state + proposed command, no solver result)
            scen_list.append({
                "feeder": feeder, "mult": m, "nodes": ctx["nodes"],
                "baseline_vmin": ctx["baseline_vmin"], "baseline_vmax": ctx["baseline_vmax"],
                "v_lower_limit": 0.95, "v_upper_limit": 1.05,
            })

    with open(os.path.join(args.out, "E3_physics.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(args.out, "E3_scenarios.json"), "w") as f:
        json.dump(scen_list, f, indent=1)
    print(f"\nWROTE {len(rows)} scenarios to E3_physics.jsonl and E3_scenarios.json")

    # quick standalone accuracy preview for the non-LLM methods
    for meth in ("command_bound_rule", "retrieval_knn", "physics_verifier"):
        acc = sum(r[meth] == r["oracle"] for r in rows) / len(rows)
        unsafe_allowed = sum(r[meth] == "ALLOW" and r["oracle"] == "BLOCK" for r in rows)
        overblock = sum(r[meth] == "BLOCK" and r["oracle"] == "ALLOW" for r in rows)
        print(f"  {meth:20s} acc={acc:.2f} unsafe_allowed={unsafe_allowed} over_block={overblock}")


if __name__ == "__main__":
    main()
