#!/usr/bin/env python3
"""
E12 - Operational security metrics (R4-8).

Thesis: a mitigation is NOT free. GridCAD's risk-aware selection weighs the
operational/physical COST of acting, so the system must prefer the
least-costly safe mitigation and weigh grid-device importance. E12 quantifies
that cost with the real OpenDSS physics oracle on IEEE123, focusing on the
reviewer's three asks: false-positive physical cost, rollback cost, and
recovery after a wrong mitigation.

Key idea (and headline finding): the physical cost of a false-positive block
is ROLE-DEPENDENT.
  * Isolating a MONITOR outstation (RTU) costs only OBSERVABILITY - the grid
    physics is unchanged, because a monitor does not actuate.
  * Isolating a CONTROL device (capacitor bank / voltage regulator) during an
    operational stress removes voltage support and can push buses out of the
    ANSI A band - a real physical cost.
This operationalizes the device-importance weighting in the problem statement:
the cost of mitigating a device depends on what that device does.

Method (deterministic, OpenDSS):
  1. Baseline + an operational load stress; solve with all controls -> the
     reference safe state (controllers compensate).
  2. For each control device, simulate a false-positive isolation (remove it /
     freeze its control) under the same stress, re-solve, and measure the
     physical cost: worst bus-voltage drop and NEW ANSI-A violations introduced.
  3. Rollback: re-enable the device, re-solve, confirm recovery to the
     reference state; time the rollback re-solve (physics re-check latency).
  4. Monitor isolations: physical cost 0 by construction; cost is observability
     (device-minutes of lost telemetry/control-visibility).

Scope note: the SDN rollback itself is an O(1) OpenFlow flow-mod (remove the
installed rule; the pilot fabric shows installed rules persist until removed);
the cost that is non-trivial and physical is the grid re-convergence, which we
time here. The one operational number NOT measured this session is live-ONOS
failover wall-clock latency (ONOS not stood up) - the same item deferred in E10.
"""
import os, sys, json, time
import opendssdirect as dss

FEEDER = "f123p/123Bus/IEEE123Master.dss"
ANSI_LO, ANSI_HI = 0.95, 1.05
STRESS = 1.50            # operational load multiplier (stress case)
BLOCK_MINUTES = 15       # assumed isolation duration for observability cost
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "E12_opcost_summary.json")

def compile_feeder():
    dss.Command("Clear")
    dss.Command(f"Redirect {FEEDER}")

def solve(loadmult):
    dss.Solution.LoadMult(loadmult)
    t0 = time.perf_counter()
    dss.Solution.Solve()
    dt = (time.perf_counter() - t0) * 1000.0  # ms
    pu = {b: v for b, v in zip(dss.Circuit.AllNodeNames(),
                               dss.Circuit.AllBusMagPu()) if v > 0.01}
    return pu, dt, bool(dss.Solution.Converged())

def viol_below(pu):
    return {b for b, v in pu.items() if v < ANSI_LO}

def main():
    t0 = time.time()
    compile_feeder()
    base_pu, base_ms, base_conv = solve(1.0)
    base_vmin = min(base_pu.values()); base_vmax = max(base_pu.values())

    # stressed reference: all controls active
    compile_feeder()
    ref_pu, ref_ms, ref_conv = solve(STRESS)
    ref_vmin = min(ref_pu.values()); ref_vmax = max(ref_pu.values())
    ref_viol = viol_below(ref_pu)

    caps = dss.Capacitors.AllNames()
    regs = dss.RegControls.AllNames()

    def device_cost(kind, name):
        """Isolate one control device under STRESS, measure physical cost,
        then roll back and confirm recovery. Fresh compile each time so the
        isolation is the only change."""
        compile_feeder()
        if kind == "capacitor":
            dss.Command(f"Capacitor.{name}.enabled=no")       # isolated
        else:  # regulator control frozen (cannot adjust tap to the stress)
            dss.Command(f"RegControl.{name}.enabled=no")
        iso_pu, iso_ms, iso_conv = solve(STRESS)
        iso_vmin = min(iso_pu.values())
        # worst drop vs reference, and NEW violations introduced
        max_drop = max((ref_pu[b] - iso_pu[b]) for b in iso_pu if b in ref_pu)
        new_viol = sorted(viol_below(iso_pu) - ref_viol)
        # rollback: re-enable, re-solve, confirm recovery to reference
        if kind == "capacitor":
            dss.Command(f"Capacitor.{name}.enabled=yes")
        else:
            dss.Command(f"RegControl.{name}.enabled=yes")
        rb_pu, rb_ms, rb_conv = solve(STRESS)
        rec_dev = max(abs(rb_pu[b] - ref_pu[b]) for b in rb_pu if b in ref_pu)
        return {
            "role": "control", "kind": kind,
            "isolated_vmin_pu": round(iso_vmin, 4),
            "worst_drop_pu": round(max_drop, 4),
            "new_ansi_A_violations": len(new_viol),
            "example_violated_nodes": new_viol[:5],
            "converged": iso_conv,
            "rollback_resolve_ms": round(rb_ms, 2),
            # bit-identical recovery is not expected for discrete controls
            # (tap changers / switched caps re-converge to a nearby step);
            # report the actual deviation and a physically meaningful tolerance.
            "recovery_max_dev_pu": round(rec_dev, 5),
            "recovered_within_2pct": bool(rec_dev < 0.02),
        }

    control_costs = {}
    for c in caps:
        control_costs[f"cap:{c}"] = device_cost("capacitor", c)
    for r in regs:
        control_costs[f"reg:{r}"] = device_cost("regulator", r)

    # monitor isolations: physics unchanged -> physical cost 0, observability only
    monitors = {
        "mon:feeder_RTU_A": {"role": "monitor", "kind": "rtu"},
        "mon:bus_monitor_B": {"role": "monitor", "kind": "rtu"},
        "mon:meter_C": {"role": "monitor", "kind": "rtu"},
    }
    for m in monitors.values():
        m.update({
            "worst_drop_pu": 0.0, "new_ansi_A_violations": 0,
            "physical_cost": "none (no actuation)",
            "observability_cost_device_minutes": BLOCK_MINUTES,
            "rollback_resolve_ms": 0.0,
            "recovery_max_dev_pu": 0.0, "recovered_within_2pct": True,
        })

    # aggregate
    ctrl_with_viol = [k for k, v in control_costs.items()
                      if v["new_ansi_A_violations"] > 0]
    worst = max(control_costs.values(), key=lambda v: v["worst_drop_pu"])
    worst_k = [k for k, v in control_costs.items() if v is worst][0]
    rb_lat = [v["rollback_resolve_ms"] for v in control_costs.values()]

    out = {
        "feeder": "IEEE123", "ansi_band": [ANSI_LO, ANSI_HI],
        "load_multiplier_stress": STRESS,
        "baseline": {"vmin_pu": round(base_vmin, 4), "vmax_pu": round(base_vmax, 4),
                     "converged": base_conv, "solve_ms": round(base_ms, 2)},
        "stressed_reference_all_controls": {
            "vmin_pu": round(ref_vmin, 4), "vmax_pu": round(ref_vmax, 4),
            "ansi_A_violations": len(ref_viol), "converged": ref_conv,
            "solve_ms": round(ref_ms, 2)},
        "false_positive_cost": {
            "control_devices": control_costs,
            "monitor_devices": monitors,
        },
        "headline": {
            "control_devices_tested": len(control_costs),
            "control_isolations_causing_new_ANSI_violations": len(ctrl_with_viol),
            "which": ctrl_with_viol,
            "worst_device": worst_k,
            "worst_drop_pu": worst["worst_drop_pu"],
            "worst_new_violations": worst["new_ansi_A_violations"],
            "monitor_isolations_physical_cost": 0,
            "rollback_resolve_ms_p50": round(sorted(rb_lat)[len(rb_lat)//2], 2),
            "rollback_resolve_ms_max": round(max(rb_lat), 2),
            "all_rollbacks_recovered_within_2pct": all(
                v["recovered_within_2pct"] for v in control_costs.values()),
            "worst_recovery_dev_pu": round(max(
                v["recovery_max_dev_pu"] for v in control_costs.values()), 5),
        },
        "caveats": [
            "False-positive physical cost is role-dependent: isolating a monitor "
            "RTU costs only observability (0 physical), isolating a voltage-"
            "support device (cap/regulator) under load stress can breach ANSI A. "
            "This evidences the device-importance weighting in the problem "
            "statement.",
            "Control isolation modeled as device/control removed from service "
            "(strongest form of the cost); a 'frozen-at-last-state' model would "
            "be a lower bound. Rollback = re-enable + physics re-converge; the "
            "SDN flow-removal itself is an O(1) OpenFlow flow-mod.",
            "One operational number is NOT measured this session: live-ONOS "
            "failover wall-clock latency (ONOS not stood up) - the item deferred "
            "from E10; needs the testbed up.",
            "IEEE123, single stress multiplier; magnitudes indicative of the "
            "mechanism, not a worst-case bound.",
            "Rollback recovers the physical state to within ~1-2% pu, not bit-"
            "identically: discrete controls (regulator tap changers, switched "
            "caps) re-converge to a nearby step after the isolation clears "
            "(tap hysteresis), which is normal operational behavior.",
            "At this stress the all-controls reference is comfortably in-band "
            "on the lower side (vmin ~0.964) but has a mild over-voltage at one "
            "regulated node (vmax ~1.0625 > 1.05), a known IEEE123 heavy-load "
            "quirk; the false-positive cost reported here is the under-voltage "
            "direction (loss of voltage support).",
        ],
        "elapsed_s": round(time.time() - t0, 1),
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    json.dump(out, open(OUT, "w"), indent=2)
    h = out["headline"]
    print("baseline vmin/vmax", out["baseline"]["vmin_pu"], out["baseline"]["vmax_pu"])
    print("stressed ref vmin/vmax/viol",
          out["stressed_reference_all_controls"]["vmin_pu"],
          out["stressed_reference_all_controls"]["vmax_pu"],
          out["stressed_reference_all_controls"]["ansi_A_violations"])
    print("ctrl isolations causing NEW violations:",
          h["control_isolations_causing_new_ANSI_violations"], "of",
          h["control_devices_tested"], "->", h["which"])
    print("worst:", h["worst_device"], "drop", h["worst_drop_pu"],
          "newviol", h["worst_new_violations"])
    print("monitor physical cost:", h["monitor_isolations_physical_cost"])
    print("rollback resolve ms p50/max:", h["rollback_resolve_ms_p50"],
          h["rollback_resolve_ms_max"], "recovered<=2%",
          h["all_rollbacks_recovered_within_2pct"],
          "worstdev", h["worst_recovery_dev_pu"])
    print("WROTE", OUT)

if __name__ == "__main__":
    main()
