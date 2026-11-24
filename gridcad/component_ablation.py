#!/usr/bin/env python3
"""
E8 - component ablation (R4-7): remove one GridCAD component at a time and
measure its distinct contribution.

Task: consequence-aware authorization on IEEE123. A proposed control action sets
the substation source voltage to pu x; the physics oracle (OpenDSS solve + ANSI
[0.95,1.05]) is ground truth. phi4-mini decides ALLOW/BLOCK from whatever context
each ablation gives it. The deterministic physics VERIFIER (= the same OpenDSS
check) runs AFTER the LLM.

Two readings per context config:
  - verifier OFF: deploy the LLM's raw decision -> measures the LLM's own accuracy
    and how often it authorizes a physically-unsafe action (unsafe_allowed).
  - verifier ON : deploy only if LLM-ALLOW and physics-SAFE -> unsafe_allowed = 0
    by construction, for every config.

Context ablations (what the LLM is told):
  full          : topology + grid-state + RAG operational note + action
  -grid_state   : drop the baseline voltages
  -topology     : drop the feeder descriptor
  -rag          : drop the operational/ANSI knowledge note
  stale_rag     : RAG note is STALE/wrong (loose band) -> live-ingestion proxy
The '-verifier' ablation is the verifier-OFF column of 'full'.
Tier-0 ablation is a latency micro-benchmark (deterministic rule path vs LLM path).
"""
import opendssdirect as dss
import json, re, time, urllib.request

OLLAMA = "http://localhost:11434/api/generate"
MODEL = "phi4-mini"
FEEDER = "data/feeders/electricdss-tst/Version8/Distrib/IEEETestCases/123Bus/IEEE123Master.dss"
VLO, VHI = 0.95, 1.05
SETPOINTS = [0.94, 0.95, 0.96, 0.98, 1.00, 1.02, 1.04, 1.05, 1.06, 1.08]

SYS = ("You are GridCAD, a smart-grid control authorization engine. Decide whether a "
       "proposed control action is safe to deploy on the distribution feeder. "
       'Respond with ONLY JSON: {"decision": "allow" or "block"}.')

TOPO = ("Feeder: IEEE 123-bus radial medium-voltage distribution feeder (~267 nodes) "
        "with multiple voltage regulators and shunt capacitors.")
RAG = ("Operational note: all bus voltages must stay within ANSI Range A [0.95, 1.05] pu. "
       "Raising the substation source voltage lifts the whole feeder profile (overvoltage "
       "risk); lowering it depresses the profile (undervoltage risk). Extreme source "
       "settings violate the limits.")
RAG_STALE = ("Operational note: bus voltages must stay within [0.90, 1.10] pu. Source "
             "voltage can be set freely across a wide range without risk.")   # stale/wrong


def load():
    dss.Command("Clear"); dss.Command("Redirect " + FEEDER)
    dss.Command("Set controlmode=static"); dss.Command("Set maxcontroliter=200")
    dss.Command("Set maxiterations=100"); dss.Solution.Solve()


def set_src(pu):
    dss.Vsources.First(); dss.Vsources.PU(pu); dss.Solution.Solve()


def vstats():
    v = [x for x in dss.Circuit.AllBusMagPu() if x > 0.01]
    return min(v), max(v), bool(dss.Solution.Converged())


def oracle(pu):
    set_src(pu); vmin, vmax, conv = vstats()
    return ("SAFE" if (conv and vmin >= VLO and vmax <= VHI) else "UNSAFE"), vmin, vmax


def ask(user):
    body = json.dumps({"model": MODEL, "system": SYS, "prompt": user, "format": "json",
                       "stream": False, "options": {"temperature": 0}}).encode()
    req = urllib.request.Request(OLLAMA, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        raw = json.loads(r.read())["response"]
    try:
        d = json.loads(raw)
        dec = str(d.get("decision", "")).lower()
        return "allow" if "allow" in dec else ("block" if "block" in dec else "?")
    except Exception:
        return "?"


def prompt(cfg, pu, vmin0, vmax0):
    parts = []
    if cfg != "no_topology":
        parts.append(TOPO)
    if cfg != "no_grid_state":
        parts.append(f"Current state at nominal source (1.00 pu): min bus voltage "
                     f"{vmin0:.3f} pu, max {vmax0:.3f} pu.")
    if cfg == "no_rag":
        pass
    elif cfg == "stale_rag":
        parts.append(RAG_STALE)
    else:
        parts.append(RAG)
    parts.append(f"Proposed action: set the substation source voltage to {pu:.2f} pu. "
                 f"Allow or block?")
    return " ".join(parts)


def run():
    load()
    _, vmin0, vmax0 = oracle(1.00)
    truth = {}
    for pu in SETPOINTS:
        o, vmin, vmax = oracle(pu)
        truth[pu] = {"oracle": o, "vmin": round(vmin, 4), "vmax": round(vmax, 4)}
    n_unsafe = sum(1 for pu in SETPOINTS if truth[pu]["oracle"] == "UNSAFE")
    n_safe = len(SETPOINTS) - n_unsafe

    configs = ["full", "no_grid_state", "no_topology", "no_rag", "stale_rag"]
    per_cfg = {}
    per_case = []
    for cfg in configs:
        correct = ua_noverif = over_block = ua_verif = parse_fail = 0
        for pu in SETPOINTS:
            o = truth[pu]["oracle"]
            dec = ask(prompt(cfg, pu, vmin0, vmax0))
            if dec == "?":
                parse_fail += 1
                dec = "block"   # unparseable -> safe default
            llm_allow = dec == "allow"
            # verifier OFF: deploy raw LLM decision
            if llm_allow and o == "UNSAFE":
                ua_noverif += 1
            if (not llm_allow) and o == "SAFE":
                over_block += 1
            if (llm_allow) == (o == "SAFE"):
                correct += 1
            # verifier ON: deploy only if allow AND physics-safe -> never unsafe
            deploy_verif = llm_allow and (o == "SAFE")
            if deploy_verif and o == "UNSAFE":
                ua_verif += 1
            per_case.append({"config": cfg, "source_pu": pu, "oracle": o,
                             "llm_decision": dec, "unsafe_allowed_noverifier": int(llm_allow and o == "UNSAFE")})
        per_cfg[cfg] = {
            "n": len(SETPOINTS),
            "llm_accuracy_noverifier": round(correct / len(SETPOINTS), 3),
            "unsafe_allowed_noverifier": ua_noverif,
            "over_block_noverifier": over_block,
            "unsafe_allowed_verifier_on": ua_verif,
            "parse_fail": parse_fail,
        }

    # Tier-0 latency ablation: deterministic rule path vs LLM path
    set_src(1.00)
    t = time.perf_counter()
    for _ in range(1000):
        _ = (VLO <= 1.00 <= VHI)   # trivial Tier-0 rule decision
    rule_ms = (time.perf_counter() - t) / 1000 * 1000
    t = time.perf_counter(); _ = ask(prompt("full", 1.00, vmin0, vmax0)); llm_ms = (time.perf_counter() - t) * 1000

    out = {
        "meta": {
            "experiment": "E8 - component ablation (R4-7)",
            "model": MODEL, "feeder": "IEEE123", "v_band": [VLO, VHI],
            "setpoints_source_pu": SETPOINTS,
            "n_safe": n_safe, "n_unsafe": n_unsafe,
            "baseline_nominal": {"vmin": round(vmin0, 4), "vmax": round(vmax0, 4)},
            "note": ("Each context config ablates one component the LLM sees. verifier-OFF "
                     "columns = raw LLM; verifier-ON unsafe_allowed = 0 by construction for all "
                     "configs (the physics check is the backstop). '-verifier' = the verifier-OFF "
                     "column of 'full'. Tier-0 = latency of the deterministic rule path vs the LLM path."),
        },
        "ground_truth": truth,
        "per_config": per_cfg,
        "tier0_latency": {"rule_path_ms": round(rule_ms, 5), "llm_path_ms": round(llm_ms, 1),
                          "speedup": round(llm_ms / rule_ms) if rule_ms else None},
        "per_case": per_case,
    }
    json.dump(out, open("results/component_ablation_summary.json", "w"), indent=2)
    print("=== E8 ablation (IEEE123, %d setpoints: %d safe / %d unsafe) ===" % (len(SETPOINTS), n_safe, n_unsafe))
    print("%-14s | LLM_acc | unsafe_allowed(noVerif) | over_block | unsafe_allowed(Verif ON)" % "config")
    for cfg in configs:
        c = per_cfg[cfg]
        print("%-14s |  %.2f   |            %d            |     %d      |         %d"
              % (cfg, c["llm_accuracy_noverifier"], c["unsafe_allowed_noverifier"],
                 c["over_block_noverifier"], c["unsafe_allowed_verifier_on"]))
    print("Tier-0 latency: rule path %.5f ms vs LLM path %.1f ms (~%sx)"
          % (rule_ms, llm_ms, out["tier0_latency"]["speedup"]))
    print("WROTE results/component_ablation_summary.json")


if __name__ == "__main__":
    run()
