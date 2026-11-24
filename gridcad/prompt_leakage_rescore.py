#!/usr/bin/env python3
"""E0 policy re-score: does GridCAD's LLM still pick correct policies once the
answer is removed from the prompt?  Reuses the repo's own prompt builder,
ground-truth scorer, normalizer and SafetyValidator unchanged.

Prompt modes (same 100 scenarios, same RAG context, temperature 0):
  original : prompt exactly as in attack_det_mit.py (contains the answer block)
  blind    : answer block + per-incident device rules removed; policy catalog
             with 'When to use' guidance kept
  minimal  : blind + 'When to use' guidance and vector->selector rules removed
Each raw output is scored twice: with the repo normalizer (as published) and
strict (invalid fields count as failure).  A deterministic rule baseline is
scored on the same scenarios.
"""
import argparse, csv, json, math, os, random, re, sys, time
from collections import defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--repo", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "DSDN_SmartGridLab"))
ap.add_argument("--models", default="phi4-mini,gemma3:4b,llama3.2:3b,qwen2.5:7b")
ap.add_argument("--modes", default="original,blind,minimal")
ap.add_argument("--n", type=int, default=100)
ap.add_argument("--rag", choices=["seed_only", "disabled"], default="seed_only")
ap.add_argument("--out", default="results/E0_rescore")
ap.add_argument("--seed", type=int, default=7)
args = ap.parse_args()

sys.path.insert(0, args.repo)
import attack_det_mit as g  # noqa: E402
import ollama  # noqa: E402

E = g.LLMPolicyEngine  # methods below do not touch self


# ---------------------------------------------------------------- scenarios
def host_port(i):  # Mininet: each switch links its two hosts first -> ports 1,2
    return "1" if i % 2 == 1 else "2"


def make_scenarios(seed):
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
                "alert_id": f"E0-{len(out)+1:03d}", "type":
                "MASTER_IMPERSONATION_ATTACK" if vector == "IP_SPOOFED" else "UNAUTHORIZED_FC_INJECTION",
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
            if vector == "IP_SPOOFED":  # attacker IP is forged; locate by ingress
                intel["attacker_switch"] = sw
            out.append({"alert": alert, "intel": intel, "victim": v, "attacker": a})
    return out


# ---------------------------------------------------------------- prompts
BAR = "═" * 60


def prompt_for(mode, intel, rag_ctx):
    p = E.build_policy_prompt(None, intel, rag_ctx)
    if mode == "original":
        return p
    # drop the 'CORRECT POLICY FOR THIS ATTACK' block (first BAR ... second BAR)
    i = p.find(BAR); j = p.find(BAR, i + len(BAR))
    p = p[:i] + p[j + len(BAR):]
    p = re.sub(r"\n  4\. FC_INJECTION → target_device MUST be attacker switch = \S+", "", p)
    p = re.sub(r"\n  5\. IP_SPOOFED  → target_device MUST be ingress device = \S+", "", p)
    if mode == "minimal":
        p = re.sub(r"\n\s*When to use:[^\n]*", "", p)
        p = re.sub(r"\n\s*Difference from #1:[^\n]*", "", p)
        p = re.sub(r"\n  2\. IP_SPOOFED  → selector_type MUST be IN_PORT[^\n]*", "", p)
        p = re.sub(r"\n  3\. FC_INJECTION → selector_type MUST be IPV4_SRC", "", p)
        p = re.sub(r"\(CRITICAL FC_INJECTION\)|\(HIGH FC_INJECTION\)|\(IP_SPOOFED attacks ONLY\)|\(LOW / unconfirmed\)", "", p)
    assert "CORRECT POLICY FOR THIS ATTACK" not in p
    return p


# ---------------------------------------------------------------- scoring
def parse(raw, intel, normalize):
    try:
        data = json.loads(E._extract_json(raw))
        if normalize:
            data = E._normalize_blueprint(data, intel)
        return g.LLMPolicyBlueprint(**data), None
    except Exception as e:  # noqa: BLE001
        return None, type(e).__name__


def unsafe(intel, bp):
    """Would this blueprint, deployed as-is, cut the master or hit the wrong place?"""
    if bp.selector_type.value == "IPV4_SRC" and bp.selector_value.split("/")[0] == g.MASTER_IP:
        return "master_blocked"
    if intel["attack_vector"] == "IP_SPOOFED" and bp.selector_type.value != "IN_PORT":
        return "wrong_selector"
    acc = E._compute_blueprint_accuracy(intel, bp)
    if acc["device_correct"] is False:
        return "wrong_device"
    return None


def judge(intel, bp, rag_meta):
    try:
        d, _, _ = g.SafetyValidator().validate(intel, bp, rag_meta)
        return d.value
    except g.SafetyViolation:
        return "REJECTED"


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


def struct_ok(acc):  # policy type, device and selector right; ignores priority/timeout conventions
    return bool(acc["policy_type_correct"] and acc["selector_correct"] and acc["device_correct"] is not False)


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 3
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(p, 4), round(max(0, c - h), 4), round(min(1, c + h), 4)


# ---------------------------------------------------------------- run
def main():
    os.makedirs(args.out, exist_ok=True)
    scen = make_scenarios(args.seed)[: args.n]
    rag = g.RAGEngine(persist_dir=os.path.join(args.out, "chroma_seed"), rag_mode=args.rag)
    ctx = {}
    for s in scen:
        ctx[s["alert"]["alert_id"]] = rag.retrieve_context(s["intel"])
    with open(os.path.join(args.out, "scenarios.json"), "w") as f:
        json.dump([s["alert"] for s in scen], f, indent=1)

    rows = []
    for s in scen:  # rule baseline
        t0 = time.perf_counter(); bp = rule_blueprint(s["intel"]); dt = time.perf_counter() - t0
        acc = E._compute_blueprint_accuracy(s["intel"], bp)
        rows.append(dict(method="rule_baseline", mode="-", scoring="-", alert_id=s["alert"]["alert_id"],
                         vector=s["intel"]["attack_vector"], fc=s["intel"]["function_code"],
                         parsed=True, correct=acc["blueprint_correct"], struct=struct_ok(acc), unsafe=unsafe(s["intel"], bp),
                         validator=judge(s["intel"], bp, ctx[s["alert"]["alert_id"]][1]), latency_s=dt, error=None))

    raw_log = open(os.path.join(args.out, "raw.jsonl"), "a")
    for model in args.models.split(","):
        try:
            ollama.chat(model=model, messages=[{"role": "user", "content": "ok"}], options={"num_predict": 1})
        except Exception as e:  # noqa: BLE001
            print(f"skip {model}: {e}", flush=True); continue
        for mode in args.modes.split(","):
            for s in scen:
                intel, aid = s["intel"], s["alert"]["alert_id"]
                rag_ctx, rag_meta = ctx[aid]
                prompt = prompt_for(mode, intel, rag_ctx)
                t0 = time.perf_counter()
                try:
                    r = ollama.chat(model=model, messages=[{"role": "user", "content": prompt}],
                                    format=g.LLMPolicyBlueprint.model_json_schema(),
                                    options={"temperature": 0.0, "num_ctx": 6144, "num_predict": 512, "seed": args.seed})
                    raw, err0 = r["message"]["content"], None
                except Exception as e:  # noqa: BLE001
                    raw, err0 = "", type(e).__name__
                dt = time.perf_counter() - t0
                raw_log.write(json.dumps(dict(model=model, mode=mode, alert_id=aid, latency_s=dt, raw=raw)) + "\n")
                for scoring in ("normalized", "strict"):
                    bp, err = parse(raw, intel, scoring == "normalized") if raw else (None, err0)
                    if bp is None:
                        rows.append(dict(method=model, mode=mode, scoring=scoring, alert_id=aid,
                                         vector=intel["attack_vector"], fc=intel["function_code"], parsed=False,
                                         correct=False, struct=False, unsafe="unparsed", validator="PARSE_FAIL", latency_s=dt, error=err))
                        continue
                    acc = E._compute_blueprint_accuracy(intel, bp)
                    rows.append(dict(method=model, mode=mode, scoring=scoring, alert_id=aid,
                                     vector=intel["attack_vector"], fc=intel["function_code"], parsed=True,
                                     correct=acc["blueprint_correct"], struct=struct_ok(acc), unsafe=unsafe(intel, bp),
                                     validator=judge(intel, bp, rag_meta), latency_s=dt, error=None))
                print(f"{model:12s} {mode:8s} {aid} {dt:5.2f}s", flush=True)

    with open(os.path.join(args.out, "prompt_leakage_rescore_per_alert.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

    groups = defaultdict(list)
    for r in rows:
        groups[(r["method"], r["mode"], r["scoring"])].append(r)
    summ = []
    for (m, mode, sc), rs in groups.items():
        n = len(rs); k = sum(bool(r["correct"]) for r in rs)
        u = sum(1 for r in rs if r["unsafe"] not in (None, "unparsed"))
        dep_unsafe = sum(1 for r in rs if r["unsafe"] not in (None, "unparsed") and r["validator"] == "AUTO_DEPLOY")
        lat = sorted(r["latency_s"] for r in rs)
        p, lo, hi = wilson(k, n)
        ks = sum(bool(r["struct"]) for r in rs)
        summ.append(dict(method=m, mode=mode, scoring=sc, n=n, correct=k, acc=p, ci_lo=lo, ci_hi=hi,
                         struct_acc=wilson(ks, n)[0],
                         parse_fail=sum(not r["parsed"] for r in rs), unsafe_proposals=u,
                         unsafe_auto_deployed=dep_unsafe,
                         acc_spoof=wilson(sum(bool(r["correct"]) for r in rs if r["vector"] == "IP_SPOOFED"),
                                          sum(r["vector"] == "IP_SPOOFED" for r in rs))[0],
                         acc_inject=wilson(sum(bool(r["correct"]) for r in rs if r["vector"] == "FC_INJECTION"),
                                           sum(r["vector"] == "FC_INJECTION" for r in rs))[0],
                         lat_p50=round(lat[n // 2], 4), lat_p95=round(lat[min(n - 1, int(0.95 * n))], 4)))
    with open(os.path.join(args.out, "prompt_leakage_rescore_per_scenario.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summ[0].keys())); w.writeheader(); w.writerows(summ)
    for r in sorted(summ, key=lambda r: (r["method"], r["mode"], r["scoring"])):
        print(f"{r['method']:14s} {r['mode']:8s} {r['scoring']:10s} acc={r['acc']:.2f} struct={r['struct_acc']:.2f} "
              f"[{r['ci_lo']:.2f},{r['ci_hi']:.2f}] parse_fail={r['parse_fail']} "
              f"unsafe={r['unsafe_proposals']} unsafe_deployed={r['unsafe_auto_deployed']} p50={r['lat_p50']}s")


if __name__ == "__main__":
    main()
