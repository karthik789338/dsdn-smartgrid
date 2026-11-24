#!/usr/bin/env python3
"""
E6 - Verifier cost + necessity at scale.
Ladder: IEEE13 -> IEEE34 -> IEEE123 -> IEEE8500 (8531 nodes).

The controllable command is the substation source voltage setpoint (a real SCADA/LTC
control point an attacker or operator can command). Sweeping it moves the whole feeder
voltage profile across the ANSI band, so each feeder has a genuine safe window with
unsafe setpoints on either side (too low -> undervoltage, too high -> overvoltage).

Part A (verifier cost scaling): per-decision verification = apply a *changed* setpoint,
  solve with control iterations, read voltages. Timed under real setpoint changes
  (controls re-settle), reported p50/p95/p99 across feeder sizes.
Part B (necessity at scale): oracle = OpenDSS solve + ANSI [0.95,1.05] (ground truth);
  a fixed command-bound rule (authorize source pu in [1.00,1.05], physics-blind) vs the
  consequence-aware verifier (authorize iff oracle SAFE). unsafe_allowed = ALLOW on an
  oracle-BLOCK state; over_block = BLOCK on an oracle-SAFE state.
Conventions match E1a/E3: v_band [0.95,1.05], oracle = solve + voltage check.
"""
import opendssdirect as dss
import time, json, statistics as st

VEND = "data/feeders/electricdss-tst/Version8/Distrib/IEEETestCases"
MINE = "data/feeders/electricdss-tst/Version8/Distrib/IEEETestCases"
FEEDERS = {
    "IEEE13":   VEND + "/13Bus/IEEE13Nodeckt.dss",
    "IEEE34":   VEND + "/34Bus/ieee34Mod1.dss",
    "IEEE123":  VEND + "/123Bus/IEEE123Master.dss",
    "IEEE8500": MINE + "/8500-Node/Master.dss",
}
VLO, VHI = 0.95, 1.05               # ANSI Range A safety band (oracle ground truth)
RULE_LO, RULE_HI = 1.00, 1.05       # fixed command-bound authorization band (physics-blind)
SRC = [round(0.94 + 0.01 * i, 2) for i in range(17)]   # source pu 0.94 .. 1.10
PERTURB = [0.98, 1.00, 1.02, 1.04, 1.06]               # Part A: cycle to force re-solve


def load(path):
    dss.Command("Clear")
    t = time.perf_counter()
    dss.Command("Redirect " + path)
    comp = (time.perf_counter() - t) * 1000.0
    dss.Command("Set controlmode=static")
    dss.Command("Set maxcontroliter=200")
    dss.Command("Set maxiterations=100")
    dss.Solution.Solve()
    return comp


def set_src(pu):
    dss.Vsources.First()
    dss.Vsources.PU(pu)


def vstats():
    v = [x for x in dss.Circuit.AllBusMagPu() if x > 0.01]
    return min(v), max(v), bool(dss.Solution.Converged())


def safe():
    vmin, vmax, conv = vstats()
    return (conv and vmin >= VLO and vmax <= VHI), vmin, vmax


def pct(xs):
    xs = sorted(xs)
    n = len(xs)
    q = lambda p: xs[min(n - 1, int(p * n))]
    return {"n": n, "mean": round(st.mean(xs), 3), "p50": round(st.median(xs), 3),
            "p95": round(q(0.95), 3), "p99": round(q(0.99), 3),
            "min": round(xs[0], 3), "max": round(xs[-1], 3)}


out = {
    "meta": {
        "experiment": "E6 - verifier cost + necessity at scale",
        "opendssdirect": getattr(dss, "__version__", "0.9.4"),
        "command": "substation source voltage setpoint (pu)",
        "v_band": [VLO, VHI], "rule_band_source_pu": [RULE_LO, RULE_HI],
        "source_pu_sweep": SRC,
        "note": ("Part A: per-decision verify latency (apply changed source setpoint -> solve "
                 "with control iterations -> read) vs feeder size. Part B: oracle (ANSI A) vs "
                 "physics-blind fixed rule vs consequence-aware verifier over the setpoint sweep. "
                 "unsafe_allowed = ALLOW on oracle-BLOCK; over_block = BLOCK on oracle-SAFE."),
    },
    "feeders": {},
}

for name, path in FEEDERS.items():
    comp = load(path)
    nodes = dss.Circuit.NumNodes()
    # Part A: per-decision verify cost under a real setpoint change (controls re-settle)
    N = 40 if nodes < 2000 else 25
    cyc = []
    for i in range(N):
        set_src(PERTURB[i % len(PERTURB)])
        t = time.perf_counter()
        dss.Solution.Solve()
        _ = vstats()
        cyc.append((time.perf_counter() - t) * 1000.0)
    # Part B: source-setpoint sweep - oracle vs fixed rule vs verifier
    rows = []
    n_safe = n_unsafe = ua = ob = 0
    for pu in SRC:
        set_src(pu)
        dss.Solution.Solve()
        ok, vmin, vmax = safe()
        oracle = "SAFE" if ok else "UNSAFE"
        rule = "ALLOW" if (RULE_LO <= pu <= RULE_HI) else "BLOCK"
        verifier = "ALLOW" if ok else "BLOCK"
        if ok:
            n_safe += 1
            if rule == "BLOCK":
                ob += 1
        else:
            n_unsafe += 1
            if rule == "ALLOW":
                ua += 1
        rows.append({"source_pu": pu, "vmin": round(vmin, 4), "vmax": round(vmax, 4),
                     "oracle": oracle, "rule": rule, "verifier": verifier})
    win = [pu for pu, r in zip(SRC, rows) if r["oracle"] == "SAFE"]
    out["feeders"][name] = {
        "nodes": nodes, "compile_ms": round(comp, 1),
        "verify_cycle_ms": pct(cyc),
        "n_scenarios": len(SRC), "n_safe": n_safe, "n_unsafe": n_unsafe,
        "safe_source_pu_window": [min(win), max(win)] if win else None,
        "unsafe_allowed_rule": ua, "over_block_rule": ob,
        "unsafe_allowed_verifier": 0, "over_block_verifier": 0,
        "rows": rows,
    }
    f = out["feeders"][name]
    print("%-9s nodes=%-5d compile=%-6.1f verify_p50=%-6.2f verify_p95=%-6.2f verify_max=%-6.2f "
          "safe=%d/%d win=%s rule_unsafe_allowed=%d rule_over_block=%d verifier_errors=0"
          % (name, nodes, comp, f["verify_cycle_ms"]["p50"], f["verify_cycle_ms"]["p95"],
             f["verify_cycle_ms"]["max"], n_safe, len(SRC),
             f["safe_source_pu_window"], ua, ob))

json.dump(out, open("results/E6_scale_summary.json", "w"), indent=2)
print("WROTE results/E6_scale_summary.json")
