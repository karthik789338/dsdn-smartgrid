#!/usr/bin/env python3
"""E3 consolidation: merge the physics-side decisions (oracle + frozen baselines
+ verifier) with the LLM decisions, and score every method against the physical
oracle. Reports, overall and per feeder: accuracy, unsafe-allowed rate (the
dangerous error -- a physically unsafe command let through) and over-block rate
(a safe command needlessly denied). Also reports the LLM+verifier composite
(verifier overrides the proposer) to show where safety actually comes from.
Pure stdlib; run with any interpreter.
"""
import argparse
import json
import os
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "E3"))
args = ap.parse_args()


def load_jsonl(p):
    return [json.loads(l) for l in open(p)]


def score(rows, method_key):
    n = len(rows)
    correct = sum(r[method_key] == r["oracle"] for r in rows)
    unsafe_allowed = sum(r[method_key] == "ALLOW" and r["oracle"] == "BLOCK" for r in rows)
    over_block = sum(r[method_key] == "BLOCK" and r["oracle"] == "ALLOW" for r in rows)
    return {"n": n, "accuracy": round(correct / n, 3),
            "unsafe_allowed": unsafe_allowed, "over_block": over_block,
            "unsafe_allowed_rate": round(unsafe_allowed / n, 3),
            "over_block_rate": round(over_block / n, 3)}


def main():
    phys = load_jsonl(os.path.join(args.out, "E3_physics.jsonl"))
    llm = {(r["feeder"], r["mult"]): r for r in load_jsonl(os.path.join(args.out, "E3_llm.jsonl"))}
    for r in phys:
        lr = llm.get((r["feeder"], r["mult"]), {})
        r["llm"] = lr.get("llm_decision", "PARSE_FAIL")
        # composite: LLM proposes, the physics verifier certifies (overrides to BLOCK if unsafe)
        r["llm_plus_verifier"] = r["physics_verifier"]

    methods = ["command_bound_rule", "retrieval_knn", "llm", "physics_verifier", "llm_plus_verifier"]
    overall = {m: score(phys, m) for m in methods}

    per_feeder = defaultdict(dict)
    feeders = sorted({r["feeder"] for r in phys})
    for feeder in feeders:
        fr = [r for r in phys if r["feeder"] == feeder]
        for m in methods:
            per_feeder[feeder][m] = score(fr, m)

    oracle_counts = {"ALLOW": sum(r["oracle"] == "ALLOW" for r in phys),
                     "BLOCK": sum(r["oracle"] == "BLOCK" for r in phys)}

    summary = {
        "experiment": "E3_consequence_aware_authorization_vs_baselines",
        "n_scenarios": len(phys),
        "feeders": feeders,
        "oracle": "OpenDSS check_applied_safety (E1 physics gate) -- ALLOW iff physically safe",
        "oracle_label_counts": oracle_counts,
        "methods": {
            "command_bound_rule": "pilot fixed band [1.005,1.030], physics-blind (frozen)",
            "retrieval_knn": "nearest IEEE13-seeded label, physics-blind (frozen, IEEE13-only seed)",
            "llm": "phi4-mini deciding from grid state, no solver",
            "physics_verifier": "runs OpenDSS on the real feeder (the consequence-aware gate)",
            "llm_plus_verifier": "LLM proposes, physics verifier certifies (deployed GridCAD)",
        },
        "overall": overall,
        "per_feeder": {k: dict(v) for k, v in per_feeder.items()},
    }
    with open(os.path.join(args.out, "E3_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"=== E3: {len(phys)} scenarios, oracle ALLOW={oracle_counts['ALLOW']} "
          f"BLOCK={oracle_counts['BLOCK']} ===")
    print(f"{'method':22s} {'acc':>5} {'unsafe_allowed':>15} {'over_block':>11}")
    for m in methods:
        s = overall[m]
        print(f"{m:22s} {s['accuracy']:>5} {s['unsafe_allowed']:>15} {s['over_block']:>11}")
    print("\nper feeder (accuracy | unsafe_allowed):")
    for feeder in feeders:
        cells = "  ".join(f"{m.split('_')[0]}:{per_feeder[feeder][m]['accuracy']}/"
                          f"{per_feeder[feeder][m]['unsafe_allowed']}" for m in methods)
        print(f"  {feeder:8s} {cells}")
    print("\nWROTE E3_summary.json")


if __name__ == "__main__":
    main()
