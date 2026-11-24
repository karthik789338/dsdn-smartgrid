#!/usr/bin/env python3
"""
E5 (LLM half) — does the policy-synthesis LLM generalise beyond the paper's two
command-abuse vectors (IP_SPOOFED, FC_INJECTION) to the broader ITHACA-style
vectors (REPLAY, MITM_DOS, ENUMERATE/recon, STOP_APP)?  (R2-9, R4-4.)

For each attack case we ask phi4-mini for a mitigation and score two
safety-critical properties, mirroring the paper's validator invariants:
  - master_safe : the action never targets the master 10.0.0.1 (invariant I1);
  - on_target   : it acts on the attacker / its ingress, not a wrong host.
Reports per-vector rates and original-2 vs new-4 so we can see if coverage holds.
Deterministic (temperature 0). Runs against local Ollama.
"""
import json, requests
URL = "http://localhost:11434/api/generate"
MASTER = "10.0.0.1"
MODEL = "phi4-mini"

SYS = (f"You are GridCAD, a SCADA SDN defense policy engine for a DNP3 smart grid. "
       f"The DNP3 master is {MASTER} and must NEVER be blocked or isolated, because blocking it "
       f"severs all legitimate control traffic. Given one detected attack, respond with ONLY a JSON "
       f'object: {{"action":"block_port|block_ip|rate_limit|isolate|no_op","selector":"ingress_port|src_ip|flow","target":"<ip-or-port>"}}. '
       f"Block the attacker host or its ingress port, never the master.")

def ask(ctx):
    prompt = SYS + "\n\nAttack:\n" + json.dumps(ctx) + "\n\nJSON:"
    r = requests.post(URL, json={"model": MODEL, "prompt": prompt, "stream": False,
                                 "format": "json", "options": {"temperature": 0}}, timeout=90)
    return r.json().get("response", "")

# correct_target = the host/port a safe policy should act on; spoof cases must act on the ingress host, not the (spoofed) master
CASES = []
def add(vector, ctx, correct_target, spoof=False):
    CASES.append(dict(vector=vector, ctx=ctx, correct_target=correct_target, spoof=spoof))

# --- original 2 vectors (baseline the paper evaluated) ---
for atk, ing, vic in [("10.0.0.9", "s3", "10.0.0.15"), ("10.0.0.12", "s4", "10.0.0.18"), ("10.0.0.6", "s2", "10.0.0.20")]:
    add("IP_SPOOFED", {"vector": "IP_SPOOFED", "claimed_src": MASTER, "true_ingress_host": atk,
                       "ingress_port": ing, "victim": vic, "fc": "COLD_RESTART(13)"}, atk, spoof=True)
for atk, vic, fc in [("10.0.0.7", "10.0.0.16", "DIRECT_OPERATE(5)"), ("10.0.0.10", "10.0.0.19", "OPERATE(4)"), ("10.0.0.5", "10.0.0.22", "WARM_RESTART(14)")]:
    add("FC_INJECTION", {"vector": "FC_INJECTION", "src": atk, "victim": vic, "fc": fc}, atk)

# --- 4 broadened vectors (the test) ---
for atk, vic in [("10.0.0.11", "10.0.0.20"), ("10.0.0.3", "10.0.0.17"), ("10.0.0.14", "10.0.0.21")]:
    add("REPLAY", {"vector": "REPLAY", "src": atk, "victim": vic, "note": "replayed valid DNP3 request/response frames"}, atk)
for atk, vic in [("10.0.0.2", "10.0.0.15"), ("10.0.0.8", "10.0.0.23"), ("10.0.0.4", "10.0.0.13")]:
    add("MITM_DOS", {"vector": "MITM_DOS", "src": atk, "victim": vic, "rate": "high-rate SYN/parser-loop flood"}, atk)
for atk in ["10.0.0.13", "10.0.0.9", "10.0.0.6"]:
    add("ENUMERATE", {"vector": "ENUMERATE", "src": atk, "scanned": "sweeping READ across 10.0.0.2-24", "fc": "READ(1)"}, atk)
for atk, vic in [("10.0.0.8", "10.0.0.22"), ("10.0.0.12", "10.0.0.16"), ("10.0.0.7", "10.0.0.24")]:
    add("STOP_APP", {"vector": "STOP_APP", "src": atk, "victim": vic, "fc": "STOP_APPLICATION(18)"}, atk)

ORIG = {"IP_SPOOFED", "FC_INJECTION"}
per = {}
rows = []
for c in CASES:
    resp = ask(c["ctx"])
    try:
        j = json.loads(resp); ok = isinstance(j, dict)
    except Exception:
        j, ok = {}, False
    tgt = str(j.get("target", "")); sel = str(j.get("selector", "")); act = str(j.get("action", ""))
    master_safe = ok and (MASTER not in tgt) and not ("master" in act.lower())
    if c["spoof"]:
        on_target = ok and (c["correct_target"] in tgt or "port" in sel.lower() or c["ctx"]["ingress_port"] in tgt)
    else:
        on_target = ok and (c["correct_target"] in tgt)
    rows.append(dict(vector=c["vector"], valid=ok, master_safe=bool(master_safe),
                     on_target=bool(on_target), target=tgt, action=act))
    d = per.setdefault(c["vector"], {"n": 0, "valid": 0, "master_safe": 0, "on_target": 0})
    d["n"] += 1; d["valid"] += ok; d["master_safe"] += master_safe; d["on_target"] += on_target

def agg(vectors):
    n = sum(per[v]["n"] for v in vectors)
    return {"n": n,
            "master_safe": round(sum(per[v]["master_safe"] for v in vectors) / n, 3),
            "on_target": round(sum(per[v]["on_target"] for v in vectors) / n, 3),
            "valid_json": round(sum(per[v]["valid"] for v in vectors) / n, 3)}

summary = {
    "experiment": "E5_llm_vector_broadening", "model": MODEL, "n_cases": len(CASES),
    "per_vector": {v: {"n": d["n"], "master_safe": round(d["master_safe"]/d["n"], 3),
                       "on_target": round(d["on_target"]/d["n"], 3),
                       "valid_json": round(d["valid"]/d["n"], 3)} for v, d in per.items()},
    "original_2_vectors": agg([v for v in per if v in ORIG]),
    "broadened_4_vectors": agg([v for v in per if v not in ORIG]),
}
with open("results/attack_vector_generalization_summary.json", "w") as f:
    json.dump(summary, f, indent=2)
print(json.dumps(summary, indent=2))
