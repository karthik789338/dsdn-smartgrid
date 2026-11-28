#!/usr/bin/env python3
"""Isolated OpenDSS plant: apply one DNP3-observed load command and restore.

Only operates on a standalone simulated IEEE13 circuit. No access to a live
power system, no writes to the working E1b telemetry physical_state.json.
"""

import argparse
import hashlib
import json
import logging
import math
import time
from pathlib import Path

from control_common import (
    VOLTAGE_MAX, VOLTAGE_MIN, atomic_json, utcnow,
    validate_command, validate_run_id,
)


def capture(dss, label: str) -> dict:
    dss.Solution.Solve()
    if not bool(dss.Solution.Converged()):
        raise RuntimeError(f"OpenDSS did not converge at stage {label}")
    nodes = list(dss.Circuit.AllNodeNames())
    values = [float(value) for value in dss.Circuit.AllBusMagPu()]
    if not nodes or len(nodes) != len(values):
        raise RuntimeError("Missing or inconsistent voltage node values")
    if any(not math.isfinite(value) or value <= 0 for value in values):
        raise RuntimeError("Non-finite/zero node voltage")
    voltage_map = dict(zip(nodes, values))
    losses = float(dss.Circuit.Losses()[0]) / 1000.0
    if not math.isfinite(losses) or losses < 0:
        raise RuntimeError("Invalid circuit active losses")
    return {
        "stage": label,
        "timestamp_utc": utcnow(),
        "converged": True,
        "load_multiplier": float(dss.Solution.LoadMult()),
        "node_voltages_pu": voltage_map,
        "node_count": len(nodes),
        "voltage_pu_min": min(values),
        "voltage_pu_max": max(values),
        "undervoltage_nodes": sum(value < VOLTAGE_MIN for value in values),
        "overvoltage_nodes": sum(value > VOLTAGE_MAX for value in values),
        "losses_kw": losses,
    }


def voltage_delta(a: dict, b: dict) -> float:
    va, vb = a["node_voltages_pu"], b["node_voltages_pu"]
    if va.keys() != vb.keys():
        raise RuntimeError("Node inventory changed between solves")
    return max(abs(va[name] - vb[name]) for name in va)


def check_applied_safety(before: dict, after: dict) -> tuple[bool, list[str]]:
    """Do not worsen pre-existing IEEE13 voltage deviations.

    The unmodified test feeder already has nodes above 1.05 p.u., so a
    simple 'zero violations' test would mistakenly reject its baseline.
    """
    issues = []
    if after["voltage_pu_min"] < VOLTAGE_MIN:
        issues.append("New operating point is below 0.95 p.u.")
    if after["undervoltage_nodes"] > before["undervoltage_nodes"]:
        issues.append("More undervoltage nodes than the baseline")
    if after["overvoltage_nodes"] > before["overvoltage_nodes"]:
        issues.append("More overvoltage nodes than the baseline")
    if after["voltage_pu_max"] > before["voltage_pu_max"] + 0.002:
        issues.append("Baseline maximum overvoltage worsened")
    if after["losses_kw"] > before["losses_kw"] * 1.15:
        issues.append("Losses exceed 115% of baseline")
    if voltage_delta(before, after) > 0.02:
        issues.append("Maximum node voltage shift exceeds 0.02 p.u.")
    return (len(issues) == 0, issues)


def run(args) -> dict:
    from opendssdirect import dss

    dss.Command("Clear")
    dss.Command(f'Compile "{args.model.resolve()}"')
    baseline = capture(dss, "before_control")
    original_multiplier = baseline["load_multiplier"]
    if not math.isclose(original_multiplier, 1.0, abs_tol=0.0001):
        raise RuntimeError(f"Unexpected IEEE13 baseline multiplier: {original_multiplier}")

    result = {
        "experiment": "GridCAD_E1b3_DNP3_physical_control",
        "run_id": args.run_id,
        "model_sha256": hashlib.sha256(args.model.read_bytes()).hexdigest(),
        "scope": "One DNP3 AO -> isolated OpenDSS IEEE13 load multiplier -> automatic rollback",
        "baseline": baseline,
        "applied": None,
        "restored": None,
        "command": None,
        "physical_change_observed": False,
        "safety_accepted": False,
        "rollback_verified": False,
        "pass": False,
        "reasons": [],
    }
    atomic_json(args.out_dir / "engine_ready.json", {
        "run_id": args.run_id, "timestamp_utc": utcnow(),
        "baseline_load_multiplier": original_multiplier,
    })
    logging.info("ENGINE_ARMED baseline_losses=%.6f baseline_min=%.6f baseline_max=%.6f",
                 baseline["losses_kw"], baseline["voltage_pu_min"], baseline["voltage_pu_max"])
    request_file = args.out_dir / "received_command.json"
    deadline = time.monotonic() + args.max_wait_seconds
    while not request_file.is_file() and time.monotonic() < deadline:
        time.sleep(0.2)
    if not request_file.is_file():
        result["reasons"].append("No real DNP3 outstation receipt before deadline")
        return result

    try:
        document = json.loads(request_file.read_text(encoding="utf-8"))
        load_mult = validate_command(document, args.run_id)
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        result["reasons"].append(f"Command rejected without plant action: {exc}")
        return result

    result["command"] = document
    try:
        dss.Solution.LoadMult(load_mult)
        applied = capture(dss, "while_control_active")
        result["applied"] = applied
        delta = voltage_delta(baseline, applied)
        loss_delta = abs(applied["losses_kw"] - baseline["losses_kw"])
        result["max_node_voltage_change_pu"] = delta
        result["loss_change_kw"] = applied["losses_kw"] - baseline["losses_kw"]
        result["physical_change_observed"] = (delta > 1e-6 and loss_delta > 1e-4)
        if not result["physical_change_observed"]:
            result["reasons"].append("Command did not produce measurable OpenDSS electrical change")
        result["safety_accepted"], issues = check_applied_safety(baseline, applied)
        result["reasons"].extend(issues)
        logging.info("APPLIED loadmult=%.7f max_voltage_delta=%.8f loss_delta_kw=%.6f",
                     load_mult, delta, result["loss_change_kw"])
    except Exception as exc:
        result["reasons"].append(f"Apply/solve failed: {type(exc).__name__}: {exc}")
    finally:
        # A successful pilot also rolls back intentionally to demonstrate a
        # verifiable return to the original electrical operating point.
        try:
            dss.Command('Clear'); dss.Command(f'Compile {args.model.resolve()}'); dss.Solution.LoadMult(original_multiplier)
            restored = capture(dss, "after_automatic_rollback")
            result["restored"] = restored
            delta_restored = voltage_delta(baseline, restored)
            loss_restored = abs(baseline["losses_kw"] - restored["losses_kw"])
            result["rollback_max_node_error_pu"] = delta_restored
            result["rollback_loss_error_kw"] = loss_restored
            result["rollback_verified"] = (
                abs(restored["load_multiplier"] - original_multiplier) < 1e-6
                and delta_restored < 1e-4
                and loss_restored < 0.1
            )
            if not result["rollback_verified"]:
                result["reasons"].append("Rollback did not reproduce the baseline within tolerance")
            logging.info("ROLLED_BACK verified=%s max_voltage_error=%.8f",
                         result["rollback_verified"], delta_restored)
        except Exception as exc:
            result["reasons"].append(f"CRITICAL: rollback failed: {type(exc).__name__}: {exc}")
    result["pass"] = (result["physical_change_observed"]
                      and result["safety_accepted"] and result["rollback_verified"])
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--max-wait-seconds", type=float, default=90)
    args = parser.parse_args()
    validate_run_id(args.run_id)
    if not args.model.is_file() or args.max_wait_seconds <= 0:
        parser.error("existing OpenDSS model and positive timeout required")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if (args.out_dir / "engine_ready.json").exists() or (args.out_dir / "result.json").exists():
        raise RuntimeError("Engine evidence already exists; use a fresh run directory")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = run(args)
    except Exception as exc:
        logging.exception("Engine failure")
        result = {"experiment": "GridCAD_E1b3_DNP3_physical_control",
                  "run_id": args.run_id, "pass": False,
                  "reasons": [f"Engine failed: {type(exc).__name__}: {exc}"]}
    atomic_json(args.out_dir / "result.json", result)
    print(json.dumps({key: value for key, value in result.items() if key not in ("baseline", "applied", "restored", "command")},
                     indent=2, allow_nan=False))
    if not result["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
