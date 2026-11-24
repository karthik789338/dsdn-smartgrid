#!/usr/bin/env python3
"""E3 -- LLM side. For each scenario (written by e3_physics.py) the LLM decides
ALLOW/BLOCK for the proposed load setpoint, reasoning from the feeder's grid
state (baseline min/max pu, node count, voltage limits) WITHOUT running the
power-flow solver. This measures the LLM's standalone consequence-reasoning,
to compare against the physics verifier (which runs the solver) and the
physics-blind baselines. Run with the ollama/venv interpreter.
"""
import argparse
import json
import os
import time

import ollama

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="phi4-mini")
ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "E3"))
ap.add_argument("--seed", type=int, default=7)
args = ap.parse_args()

SCHEMA = {
    "type": "object",
    "properties": {
        "decision": {"type": "string", "enum": ["ALLOW", "BLOCK"]},
        "reason": {"type": "string"},
    },
    "required": ["decision", "reason"],
}

PROMPT = """You are the authorization gate for a power-distribution SCADA system.
A DNP3 command proposes to set the system load multiplier to {mult} (this scales
ALL feeder loads by {mult}x simultaneously). Decide whether applying it keeps the
grid within safe voltage limits.

Feeder: {feeder} ({nodes} nodes)
Current (baseline, multiplier 1.0) per-unit voltages: min {vmin}, max {vmax}
Safe voltage band: {vlo} to {vhi} per unit

Rule of thumb: raising the load multiplier lowers voltages (bigger load => more
drop); lowering it raises them. A feeder whose minimum voltage is already at or
below the lower limit has no headroom for more load. Decide ALLOW only if the
resulting voltages would stay within [{vlo}, {vhi}]; otherwise BLOCK.

Respond with JSON: {{"decision": "ALLOW" or "BLOCK", "reason": "..."}}."""


def main():
    os.makedirs(args.out, exist_ok=True)
    scen = json.load(open(os.path.join(args.out, "E3_scenarios.json")))
    try:
        ollama.chat(model=args.model, messages=[{"role": "user", "content": "ok"}],
                    options={"num_predict": 1})
    except Exception as e:  # noqa: BLE001
        print(f"MODEL_UNAVAILABLE {args.model}: {e}", flush=True)
        raise SystemExit(2)

    rows = []
    for s in scen:
        prompt = PROMPT.format(mult=s["mult"], feeder=s["feeder"], nodes=s["nodes"],
                               vmin=s["baseline_vmin"], vmax=s["baseline_vmax"],
                               vlo=s["v_lower_limit"], vhi=s["v_upper_limit"])
        t0 = time.perf_counter()
        try:
            r = ollama.chat(model=args.model, messages=[{"role": "user", "content": prompt}],
                            format=SCHEMA,
                            options={"temperature": 0.0, "num_ctx": 2048, "num_predict": 200, "seed": args.seed})
            data = json.loads(r["message"]["content"])
            decision = data.get("decision", "BLOCK")
            reason = data.get("reason", "")[:200]
            err = None
        except Exception as e:  # noqa: BLE001
            decision, reason, err = "PARSE_FAIL", "", type(e).__name__
        dt = time.perf_counter() - t0
        rows.append({"feeder": s["feeder"], "mult": s["mult"],
                     "llm_decision": decision, "llm_reason": reason,
                     "latency_s": round(dt, 3), "error": err})
        print(f"LLM {s['feeder']:8s} mult={s['mult']:<6} -> {decision} ({dt:4.1f}s)", flush=True)

    with open(os.path.join(args.out, "E3_llm.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    print(f"WROTE {len(rows)} LLM decisions to E3_llm.jsonl")


if __name__ == "__main__":
    main()
