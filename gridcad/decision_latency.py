#!/usr/bin/env python3
"""E2 (decision-path latency): decompose the per-command latency of GridCAD's
mitigation-synthesis path into its stages, so the paper's latency claims are
honest about where the time goes.

Reuses the repo's own pieces unchanged (same as E0): RAGEngine.retrieve_context,
LLMPolicyEngine.build_policy_prompt, the ollama call with the published options,
_extract_json/_normalize_blueprint, and SafetyValidator.validate. For each of N
scenarios it times, separately:

  rag_retrieve   ChromaDB context retrieval
  prompt_build   assembling the policy prompt
  llm_synthesis  the phi4-mini generation (the dominant term)
  parse          JSON extract + normalize into a blueprint
  validate       SafetyValidator (the consequence/authorization check)
  llm_path_total rag+prompt+llm+parse+validate (the full LLM decision)
  rule_path_total the deterministic rule-table baseline + validate (zero-LLM ref)

Reports p50/p95/p99 per stage. The rule path is the same one E0 showed ties the
best LLM on accuracy; here it is the latency floor the LLM path is measured
against. Run with the repo/ollama interpreter (same env E0 used).
"""
import argparse
import json
import os
import random
import re
import statistics
import sys
import time
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--repo", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "DSDN_SmartGridLab"))
ap.add_argument("--model", default="phi4-mini")
ap.add_argument("--n", type=int, default=25)
ap.add_argument("--warmup", type=int, default=2)
ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "E2_latency"))
ap.add_argument("--seed", type=int, default=7)
args = ap.parse_args()

sys.path.insert(0, args.repo)
import attack_det_mit as g  # noqa: E402
import ollama  # noqa: E402

E = g.LLMPolicyEngine
BAR = "═" * 60


def host_port(i):
    return "1" if i % 2 == 1 else "2"


def make_scenarios(seed, n):
    rng = random.Random(seed)
    spec = [("IP_SPOOFED", {13: 15, 14: 15, 18: 10, 21: 10}),
            ("FC_INJECTION", {13: 10, 14: 10, 18: 15, 21: 15})]
    victims = [15, 16, 17, 18, 19]
    pairs = [(a, v) for v in victims for a in range(2, 25) if a != v]
    rng.shuffle(pairs)
    used, out = set(), []
    for vector, fcs in spec:
        fc_list = [fc for fc, k in fcs.items() for _ in range(k)]
        rng.shuffle(fc_list)
        for fc in fc_list:
            per_v = defaultdict(int, {v: sum(1 for s in out if s["victim"] == v) for v in victims})
            a, v = next(p for p in pairs if p not in used and per_v[p[1]] < 20)
            used.add((a, v))
            att_ip = f"10.0.0.{a}"
            sw = g.HOST_SWITCH[att_ip]
            confirmed = rng.random() < 0.5
            alert = {
                "alert_id": f"E2-{len(out)+1:03d}",
                "type": "MASTER_IMPERSONATION_ATTACK" if vector == "IP_SPOOFED" else "UNAUTHORIZED_FC_INJECTION",
                "attack_vector": vector,
                "confidence": 1.0 if vector == "IP_SPOOFED" else 0.95,
                "attack_summary": {
                    "attacker_ip": g.MASTER_IP if vector == "IP_SPOOFED" else att_ip,
                    "attacker_station": a, "victim_ip": f"10.0.0.{v}", "victim_station": v,
                    "success_indicators": confirmed},
                "attack_command": {"function_code": fc, "target_port": 20000 + v},
                "topology_violation": ({"ingress_location": [g.SWITCH_TO_DEVICE[sw], host_port(a)]}
                                       if vector == "IP_SPOOFED" else {}),
                "victim_responses": [{"fc": 129}] if confirmed else [],
            }
            intel = E.extract_intelligence(None, alert)
            if vector == "IP_SPOOFED":
                intel["attacker_switch"] = sw
            out.append({"alert": alert, "intel": intel, "victim": v, "attacker": a})
            if len(out) >= n:
                return out
    return out


def rule_blueprint(intel):
    v, sev = intel["attack_vector"], intel["fc_severity"]
    dev = g.SWITCH_TO_DEVICE.get(intel["attacker_switch"], "")
    if v == "IP_SPOOFED":
        d = dict(policy_type="PORT_BLOCK_SPOOF", target_device=intel["ingress_location"][0],
                 selector_type="IN_PORT", selector_value=intel["ingress_location"][1], priority=65000, timeout=1800)
    elif sev == "CRITICAL":
        d = dict(policy_type="COMPLETE_IP_BLOCK", target_device=dev, selector_type="IPV4_SRC",
                 selector_value=intel["attacker_ip"] + "/32", priority=45000, timeout=1800)
    else:
        d = dict(policy_type="DNP3_PORT_BLOCK", target_device=dev, selector_type="IPV4_SRC",
                 selector_value=intel["attacker_ip"] + "/32", priority=40000, timeout=600)
    return g.LLMPolicyBlueprint(threat_level=sev, confidence_score=intel["confidence"],
                                explanation_summary="deterministic rule baseline", reason="rule table lookup", **d)


def validate(intel, bp, rag_meta):
    try:
        d, _, _ = g.SafetyValidator().validate(intel, bp, rag_meta)
        return d.value
    except g.SafetyViolation:
        return "REJECTED"


def pct(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    i = min(len(xs) - 1, int(q * len(xs)))
    return xs[i]


def summarize(name, xs, unit="ms"):
    mult = 1000.0 if unit == "ms" else 1.0
    xs = [x * mult for x in xs]
    return {"stage": name, "unit": unit, "n": len(xs),
            "p50": round(statistics.median(xs), 3) if xs else None,
            "p95": round(pct(xs, 0.95), 3) if xs else None,
            "p99": round(pct(xs, 0.99), 3) if xs else None,
            "mean": round(statistics.mean(xs), 3) if xs else None,
            "min": round(min(xs), 3) if xs else None,
            "max": round(max(xs), 3) if xs else None}


def main():
    os.makedirs(args.out, exist_ok=True)
    scen = make_scenarios(args.seed, args.n)
    rag = g.RAGEngine(persist_dir=os.path.join(args.out, "chroma_seed"), rag_mode="seed_only")

    # warm up the model + RAG so cold-start doesn't skew p50
    try:
        ollama.chat(model=args.model, messages=[{"role": "user", "content": "ok"}],
                    options={"num_predict": 1})
    except Exception as e:  # noqa: BLE001
        print(f"MODEL_UNAVAILABLE {args.model}: {e}", flush=True)
        sys.exit(2)

    t = defaultdict(list)
    per_trial = []
    for k, s in enumerate(scen):
        intel, aid = s["intel"], s["alert"]["alert_id"]

        t0 = time.perf_counter(); rag_ctx, rag_meta = rag.retrieve_context(intel); d_rag = time.perf_counter() - t0
        t0 = time.perf_counter(); prompt = E.build_policy_prompt(None, intel, rag_ctx); d_prompt = time.perf_counter() - t0
        t0 = time.perf_counter()
        r = ollama.chat(model=args.model, messages=[{"role": "user", "content": prompt}],
                        format=g.LLMPolicyBlueprint.model_json_schema(),
                        options={"temperature": 0.0, "num_ctx": 6144, "num_predict": 512, "seed": args.seed})
        d_llm = time.perf_counter() - t0
        raw = r["message"]["content"]
        t0 = time.perf_counter()
        try:
            data = json.loads(E._extract_json(raw)); data = E._normalize_blueprint(data, intel)
            bp = g.LLMPolicyBlueprint(**data); parse_ok = True
        except Exception:  # noqa: BLE001
            bp = None; parse_ok = False
        d_parse = time.perf_counter() - t0
        d_val = 0.0; verdict = "PARSE_FAIL"
        if bp is not None:
            t0 = time.perf_counter(); verdict = validate(intel, bp, rag_meta); d_val = time.perf_counter() - t0

        # rule path on the same scenario
        t0 = time.perf_counter(); rbp = rule_blueprint(intel); d_rule = time.perf_counter() - t0
        t0 = time.perf_counter(); rverdict = validate(intel, rbp, rag_meta); d_rval = time.perf_counter() - t0

        if k >= args.warmup:
            t["rag_retrieve"].append(d_rag)
            t["prompt_build"].append(d_prompt)
            t["llm_synthesis"].append(d_llm)
            t["parse"].append(d_parse)
            t["validate"].append(d_val)
            t["llm_path_total"].append(d_rag + d_prompt + d_llm + d_parse + d_val)
            t["rule_build"].append(d_rule)
            t["rule_path_total"].append(d_rule + d_rval)
        per_trial.append(dict(alert_id=aid, vector=intel["attack_vector"], warmup=k < args.warmup,
                              rag_s=d_rag, prompt_s=d_prompt, llm_s=d_llm, parse_s=d_parse, val_s=d_val,
                              llm_total_s=d_rag + d_prompt + d_llm + d_parse + d_val, parse_ok=parse_ok,
                              verdict=verdict, rule_total_s=d_rule + d_rval, rule_verdict=rverdict))
        print(f"{aid} llm={d_llm:5.2f}s total={per_trial[-1]['llm_total_s']:5.2f}s "
              f"rule={per_trial[-1]['rule_total_s']*1000:6.3f}ms verdict={verdict}", flush=True)

    ms_stages = ["rag_retrieve", "prompt_build", "parse", "validate", "rule_build", "rule_path_total"]
    s_stages = ["llm_synthesis", "llm_path_total"]
    stages = [summarize(n, t[n], "ms") for n in ms_stages] + [summarize(n, t[n], "s") for n in s_stages]
    summary = {
        "experiment": "E2_decision_path_latency",
        "model": args.model,
        "n_timed": len(t["llm_synthesis"]),
        "warmup_dropped": args.warmup,
        "stages": stages,
        "headline": {
            "llm_synthesis_p50_s": summarize("llm_synthesis", t["llm_synthesis"], "s")["p50"],
            "llm_synthesis_p95_s": summarize("llm_synthesis", t["llm_synthesis"], "s")["p95"],
            "llm_path_total_p50_s": summarize("llm_path_total", t["llm_path_total"], "s")["p50"],
            "rule_path_total_p50_ms": summarize("rule_path_total", t["rule_path_total"], "ms")["p50"],
            "speedup_rule_vs_llm_x": (round(statistics.median(t["llm_path_total"]) /
                                            statistics.median(t["rule_path_total"]), 1)
                                      if t["rule_path_total"] and statistics.median(t["rule_path_total"]) > 0 else None),
        },
        "interpretation": "LLM synthesis dominates the decision path; RAG, prompt, parse and "
                          "validation are each sub-10ms; the deterministic rule path is sub-millisecond. "
                          "Any end-to-end latency claim must carry the LLM term, not just the fast stages.",
    }
    with open(os.path.join(args.out, "per_trial.jsonl"), "w") as f:
        for r in per_trial:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(args.out, "E2_decision_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print("\n=== E2 decision-path latency (p50 / p95 / p99) ===")
    for st in stages:
        print(f"  {st['stage']:16s} {st['p50']:>9} / {st['p95']:>9} / {st['p99']:>9} {st['unit']}")
    h = summary["headline"]
    print(f"\nLLM path p50 = {h['llm_path_total_p50_s']} s  |  rule path p50 = {h['rule_path_total_p50_ms']} ms  "
          f"|  rule is ~{h['speedup_rule_vs_llm_x']}x faster")


if __name__ == "__main__":
    main()
