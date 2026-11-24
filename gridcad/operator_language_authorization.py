#!/usr/bin/env python3
"""E4 (unstructured-authorization hypothesis): the clearest "why an LLM".

A field command proposing to operate a device must be AUTHORIZED only if an
active, free-text work order legitimately covers that device. We compare:

  keyword_id   : authorize iff the command's device ID appears literally in a
                 work order (a bare identifier matcher).
  keyword_desc : authorize iff the device ID OR any distinctive identifier/
                 location token of the device's registry description appears
                 literally in a work order (a stronger keyword/rule authorizer
                 that keys on identifiers and place names, as real ones do).
  llm          : an open model reads the device registry + the active work
                 orders + the command, and decides AUTHORIZED / UNAUTHORIZED by
                 reasoning about intent.

All three see the same inputs (registry + work orders + command). The keyword
methods match tokens; only the LLM can follow synonymy and, critically,
negation/exclusion ("...except CB7", "do not operate SW9"), which is where a
token matcher dangerously false-authorizes.

Four frozen case types (constructed before any run, balanced):
  literal         ID named in the order; AUTHORIZED
  paraphrase      device named by description/synonym, ID absent; AUTHORIZED
  no_order        no active order covers the device; UNAUTHORIZED
  negation_trap   the order mentions the device/location but EXCLUDES it, or the
                  work is cancelled/locked out; UNAUTHORIZED

Metric that matters: false-authorize (an unauthorized/attack command let
through) -- concentrated in negation_trap, where keyword matching fails and the
LLM should not. Also accuracy and false-deny (operational cost). Run with the
ollama/venv interpreter.
"""
import argparse
import json
import os
import re
import time

import ollama

ap = argparse.ArgumentParser()
ap.add_argument("--models", default="phi4-mini,qwen2.5:7b")
ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "E4"))
ap.add_argument("--seed", type=int, default=7)
args = ap.parse_args()

REGISTRY = {
    "R3":  "recloser on the Oak Street lateral",
    "R7":  "recloser at the Maple substation feeder head",
    "CB7": "capacitor bank on the north feeder at Elm Avenue",
    "CB2": "capacitor bank at the Pine Road junction",
    "SW9": "sectionalizing switch on the river crossing span",
    "SW12": "tie switch between the north and south feeders",
    "VR1": "voltage regulator at the downtown riser",
    "M":   "the SCADA master station; field commands must never operate or block it",
}

# (work-order bundle, target device, ground truth, category)
CASES = [
    # --- literal: ID named, AUTHORIZED ---
    ("Crew scheduled to service recloser R3 tomorrow 08:00-12:00; expect switching on it.", "R3", "AUTHORIZED", "literal"),
    ("Maintenance window approved for CB7 today; the bank will be switched out and back.", "CB7", "AUTHORIZED", "literal"),
    ("Planned operation of tie switch SW12 during the north-south transfer at 14:00.", "SW12", "AUTHORIZED", "literal"),
    ("Voltage study: VR1 tap changes authorized this afternoon.", "VR1", "AUTHORIZED", "literal"),
    ("R7 protective-relay test includes trip/close cycles, 10:00-11:00.", "R7", "AUTHORIZED", "literal"),
    ("CB2 to be taken out of service for capacitor repair; switching approved.", "CB2", "AUTHORIZED", "literal"),
    ("SW9 to be opened for the river span structure work.", "SW9", "AUTHORIZED", "literal"),
    # --- paraphrase: device by description/synonym, ID absent, AUTHORIZED ---
    ("The crew will be out on the Oak Street lateral working the auto-recloser all morning.", "R3", "AUTHORIZED", "paraphrase"),
    ("VAR-support equipment on the Elm Avenue section is being recommissioned today.", "CB7", "AUTHORIZED", "paraphrase"),
    ("Scheduled work on the downtown riser regulator; expect tap movement this hour.", "VR1", "AUTHORIZED", "paraphrase"),
    ("Field team recommissioning the power-factor correction unit near the Pine Road junction.", "CB2", "AUTHORIZED", "paraphrase"),
    ("The protective device at the head of the Maple substation feeder is being tested now.", "R7", "AUTHORIZED", "paraphrase"),
    ("Isolation of the river-crossing sectionalizer is authorized for the span job.", "SW9", "AUTHORIZED", "paraphrase"),
    ("The feeder-interconnect switch joining the two feeders will be cycled for the transfer.", "SW12", "AUTHORIZED", "paraphrase"),
    # --- no_order: nothing covers the device, UNAUTHORIZED ---
    ("Crew scheduled to service recloser R3 tomorrow morning.", "CB7", "UNAUTHORIZED", "no_order"),
    ("VR1 tap changes authorized for the voltage study.", "SW9", "UNAUTHORIZED", "no_order"),
    ("No active work orders on the north feeder today.", "CB7", "UNAUTHORIZED", "no_order"),
    ("Capacitor CB2 repair approved.", "SW12", "UNAUTHORIZED", "no_order"),
    ("River span work: SW9 to be opened.", "R7", "UNAUTHORIZED", "no_order"),
    ("Routine operations; no switching scheduled anywhere today.", "R3", "UNAUTHORIZED", "no_order"),
    ("Normal operations; nothing scheduled.", "M", "UNAUTHORIZED", "no_order"),
    # --- negation_trap: device/location present but EXCLUDED, UNAUTHORIZED ---
    ("All north-feeder capacitors are being serviced EXCEPT CB7, which must remain in service.", "CB7", "UNAUTHORIZED", "negation_trap"),
    ("Do not operate SW9 - it must stay closed during the adjacent crew work on the river span.", "SW9", "UNAUTHORIZED", "negation_trap"),
    ("VR1 at the downtown riser is locked out; no tap changes permitted until further notice.", "VR1", "UNAUTHORIZED", "negation_trap"),
    ("Recloser R3 work on the Oak Street lateral is CANCELLED; no switching authorized today.", "R3", "UNAUTHORIZED", "negation_trap"),
    ("Service the Pine Road capacitor; the tie switch SW12 is to be left untouched.", "SW12", "UNAUTHORIZED", "negation_trap"),
    ("Maple feeder-head recloser R7 remains in automatic; crew work is downstream only, do not command R7.", "R7", "UNAUTHORIZED", "negation_trap"),
]

STOP = {"the", "on", "at", "of", "and", "to", "in", "a", "an", "near", "head",
        "section", "unit", "junction", "span", "riser", "lateral", "feeder",
        "feeders", "crossing", "station", "north", "south"}


def ident_tokens(text):
    """Distinctive identifier / location tokens: device-ID patterns and proper
    (capitalized) place names; generic words and device-type nouns excluded."""
    ids = set(re.findall(r"\b[A-Z]{1,4}-?\d+\b", text))
    caps = set(re.findall(r"\b[A-Z][a-z]+\b", text))  # proper nouns: Oak, Elm, Pine, Maple, Avenue...
    caps = {c for c in caps if c.lower() not in STOP and len(c) > 2}
    return {t.lower() for t in ids | caps}


def keyword_id(bundle, target):
    return "AUTHORIZED" if re.search(rf"\b{re.escape(target)}\b", bundle) else "UNAUTHORIZED"


def keyword_desc(bundle, target):
    toks = ident_tokens(bundle)
    want = {target.lower()} | ident_tokens(REGISTRY[target])
    return "AUTHORIZED" if (toks & want) else "UNAUTHORIZED"


SCHEMA = {"type": "object",
          "properties": {"decision": {"type": "string", "enum": ["AUTHORIZED", "UNAUTHORIZED"]},
                         "reason": {"type": "string"}},
          "required": ["decision", "reason"]}

REG_TEXT = "\n".join(f"  {k}: {v}" for k, v in REGISTRY.items())
PROMPT = """You are the authorization gate for a power-distribution SCADA system.
A field command wants to OPERATE device {target}. Authorize it ONLY if an active
work order below legitimately covers operating that device right now. If no order
covers it, or an order mentions it only to EXCLUDE it (e.g. "except {target}",
"do not operate", "locked out", "cancelled", "leave untouched", "remain in
service"), the command is UNAUTHORIZED.

Device registry (id: description):
{registry}

Active work orders (free text):
{orders}

Command: OPERATE {target} ({desc}).

Respond with JSON: {{"decision": "AUTHORIZED" or "UNAUTHORIZED", "reason": "..."}}."""


def ask_llm(model, bundle, target, seed):
    prompt = PROMPT.format(target=target, registry=REG_TEXT, orders=bundle or "(none)",
                           desc=REGISTRY[target])
    try:
        r = ollama.chat(model=model, messages=[{"role": "user", "content": prompt}],
                        format=SCHEMA,
                        options={"temperature": 0.0, "num_ctx": 2048, "num_predict": 200, "seed": seed})
        return json.loads(r["message"]["content"]).get("decision", "UNAUTHORIZED")
    except Exception:  # noqa: BLE001
        return "PARSE_FAIL"


def score(rows, key):
    n = len(rows)
    acc = sum(r[key] == r["truth"] for r in rows) / n
    false_auth = sum(r[key] == "AUTHORIZED" and r["truth"] == "UNAUTHORIZED" for r in rows)
    false_deny = sum(r[key] == "UNAUTHORIZED" and r["truth"] == "AUTHORIZED" for r in rows)
    return {"n": n, "accuracy": round(acc, 3), "false_authorize": false_auth, "false_deny": false_deny}


def main():
    os.makedirs(args.out, exist_ok=True)
    rows = []
    for bundle, target, truth, cat in CASES:
        rows.append({"target": target, "truth": truth, "category": cat, "bundle": bundle,
                     "keyword_id": keyword_id(bundle, target),
                     "keyword_desc": keyword_desc(bundle, target)})

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    live_models = []
    for m in models:
        try:
            ollama.chat(model=m, messages=[{"role": "user", "content": "ok"}], options={"num_predict": 1})
            live_models.append(m)
        except Exception as e:  # noqa: BLE001
            print(f"skip {m}: {e}", flush=True)
    for m in live_models:
        col = f"llm::{m}"
        for r in rows:
            t0 = time.perf_counter()
            r[col] = ask_llm(m, r["bundle"], r["target"], args.seed)
            print(f"{m:14s} {r['category']:14s} {r['target']:4s} -> {r[col]:12s} ({time.perf_counter()-t0:4.1f}s)", flush=True)

    methods = ["keyword_id", "keyword_desc"] + [f"llm::{m}" for m in live_models]
    cats = ["literal", "paraphrase", "no_order", "negation_trap"]
    summary = {
        "experiment": "E4_unstructured_authorization",
        "n_cases": len(rows),
        "category_counts": {c: sum(r["category"] == c for r in rows) for c in cats},
        "methods": methods,
        "overall": {m: score(rows, m) for m in methods},
        "per_category": {c: {m: score([r for r in rows if r["category"] == c], m) for m in methods} for c in cats},
    }
    with open(os.path.join(args.out, "E4_per_case.jsonl"), "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    with open(os.path.join(args.out, "operator_language_authorization_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\n=== E4: {len(rows)} cases ===")
    print(f"{'method':18s} {'acc':>5} {'false_auth':>11} {'false_deny':>11}")
    for m in methods:
        s = summary["overall"][m]
        print(f"{m:18s} {s['accuracy']:>5} {s['false_authorize']:>11} {s['false_deny']:>11}")
    print("\nnegation_trap (false_authorize = attack let through):")
    for m in methods:
        s = summary["per_category"]["negation_trap"][m]
        print(f"  {m:18s} acc={s['accuracy']} false_authorize={s['false_authorize']}")
    print("\nWROTE operator_language_authorization_summary.json")


if __name__ == "__main__":
    main()
