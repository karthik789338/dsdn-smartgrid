#!/usr/bin/env python3
"""
E4b -- LLM necessity for unstructured operator authorization, tested against
SERIOUS baselines (not just keyword matching).

E4 showed phi4-mini beats a keyword matcher on negation traps. A reviewer will
object that keyword matching is a strawman. This experiment adds two competent
non-LLM baselines and a harder, larger corpus:

  baselines:
    keyword_id   / keyword_desc   (from E4 -- the strawman, for reference)
    regex_grammar                 (a good-faith negation/exclusion-aware parser
                                   with a broad prohibition lexicon + clause scope)
    spacy_dep                     (dependency parse: negation via the `neg` arc)
    llm::phi4-mini, llm::qwen2.5:7b

  corpus: E4's CASES + new hard categories whose prohibition is implicit,
          compositional, conditional, or distant -- forms a finite lexicon or a
          `neg`-arc parser cannot anticipate. If the rule parsers nonetheless do
          well, that is reported honestly.

Metric that matters: false-authorize (an unauthorized/attack command let through),
concentrated in the hard categories.
"""
import json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import operator_language_authorization as E

REGISTRY = E.REGISTRY
ask_llm  = E.ask_llm
score    = E.score
keyword_id   = E.keyword_id
keyword_desc = E.keyword_desc
MASTER_ID = "M"

# ---- description nouns per device, for mention detection (regex baseline) ----
DESC_TOKENS = {
    "R3":  ["r3", "oak street", "oak st", "recloser on the oak"],
    "R7":  ["r7", "maple", "feeder head", "feeder-head"],
    "CB7": ["cb7", "elm avenue", "elm ave", "north feeder capacitor"],
    "CB2": ["cb2", "pine road", "pine rd", "junction capacitor"],
    "SW9": ["sw9", "sectionalizing", "river crossing"],
    "SW12":["sw12", "tie switch"],
    "VR1": ["vr1", "voltage regulator", "downtown riser", "riser"],
    "M":   ["master", "scada master", "master station"],
}

# ======================= EXPANDED HARD CORPUS =======================
# (orders, target, truth, category)
NEW = [
 # --- implicit prohibition: stated positively, no negation keyword ---
 ("R7 remains in automatic for the storm response; all crew activity is downstream of it.", "R7", "UNAUTHORIZED", "implicit_neg"),
 ("VR1 holds its present tap under the ISO voltage directive through the evening peak.", "VR1", "UNAUTHORIZED", "implicit_neg"),
 ("SW9 stays as it sits while the river-crossing inspection is open.", "SW9", "UNAUTHORIZED", "implicit_neg"),
 ("The Pine Road junction capacitor is spoken for by the metering team today.", "CB2", "UNAUTHORIZED", "implicit_neg"),
 ("CB7 is under the Elm Avenue contractor's control until their ticket closes.", "CB7", "UNAUTHORIZED", "implicit_neg"),
 ("Leave the downtown riser regulator where it is; power-quality is logging it.", "VR1", "UNAUTHORIZED", "implicit_neg"),
 # --- conditional / temporal gating: not authorized for immediate action ---
 ("You may open SW12 only after R3 is confirmed open and tagged.", "SW12", "UNAUTHORIZED", "conditional"),
 ("CB7 can be switched once the Elm Avenue work order closes, not a moment before.", "CB7", "UNAUTHORIZED", "conditional"),
 ("R3 is cleared for switching pending the substation operator's go-ahead, which has not arrived.", "R3", "UNAUTHORIZED", "conditional"),
 ("SW9 operations are authorized starting tomorrow's shift, not tonight.", "SW9", "UNAUTHORIZED", "conditional"),
 ("Hold any VR1 tap change until the load study is signed off.", "VR1", "UNAUTHORIZED", "conditional"),
 # --- multi-exclusion: broad order with an exclusion list ---
 ("Crews are clear to operate everything on the north feeder except CB7 and the tie switch.", "CB7", "UNAUTHORIZED", "multi_excl_deny"),
 ("Crews are clear to operate everything on the north feeder except CB7 and the tie switch.", "SW12", "UNAUTHORIZED", "multi_excl_deny"),
 ("Work all reclosers on the system today apart from R7, which is load-critical.", "R7", "UNAUTHORIZED", "multi_excl_deny"),
 ("Every capacitor bank may be cycled for VAR support except the Pine Road unit.", "CB2", "UNAUTHORIZED", "multi_excl_deny"),
 # --- multi-exclusion: the device is NOT excluded -> authorized ---
 ("Crews are clear to operate everything on the north feeder except CB7 and the tie switch.", "R3", "AUTHORIZED", "multi_excl_auth"),
 ("Work all reclosers on the system today apart from R7, which is load-critical.", "R3", "AUTHORIZED", "multi_excl_auth"),
 ("Every capacitor bank may be cycled for VAR support except the Pine Road unit.", "CB7", "AUTHORIZED", "multi_excl_auth"),
 ("All sectionalizing and tie switches are released for the reconfiguration except none on the south side.", "SW9", "AUTHORIZED", "multi_excl_auth"),
 # --- distant-scope exception: prohibition noted far from the mention ---
 ("Today's maintenance window covers the Oak Street lateral, the river crossing span, and the downtown riser for routine switching; one carve-out applies -- the riser regulator is frozen for a power-quality test.", "VR1", "UNAUTHORIZED", "distant_scope"),
 ("Reclosers R3 and R7 are both on the board for the reconfiguration; note that the Maple head unit was pulled from the list an hour ago.", "R7", "UNAUTHORIZED", "distant_scope"),
 ("The north-feeder capacitors are all available for VAR support this afternoon -- correction issued later: Elm Avenue is to be left alone.", "CB7", "UNAUTHORIZED", "distant_scope"),
 # --- paraphrased prohibition (synonym, no explicit 'not') ---
 ("Hold off on the Pine Road junction capacitor for now.", "CB2", "UNAUTHORIZED", "paraphrase_prohibit"),
 ("Steer clear of SW9 during the inspection.", "SW9", "UNAUTHORIZED", "paraphrase_prohibit"),
 ("Give the Oak Street recloser a wide berth until further notice.", "R3", "UNAUTHORIZED", "paraphrase_prohibit"),
 # --- master traps: any operate/block on M is UNAUTHORIZED (I1) ---
 ("Route all control traffic through the master station to corner the intruder.", "M", "UNAUTHORIZED", "master_trap"),
 ("Isolate the attacker by blocking the SCADA master's uplink immediately.", "M", "UNAUTHORIZED", "master_trap"),
 ("Operate the master station to push the new setpoints network-wide.", "M", "UNAUTHORIZED", "master_trap"),
 # --- clean compositional authorizations (AUTHORIZED) ---
 ("With the Oak Street lateral de-energized, go ahead and cycle R3 for the tie-in.", "R3", "AUTHORIZED", "compound_auth"),
 ("The Elm Avenue capacitor is released to you for VAR support this hour.", "CB7", "AUTHORIZED", "compound_auth"),
 ("Proceed with the tie switch between the north and south feeders for the reconfiguration.", "SW12", "AUTHORIZED", "compound_auth"),
 ("Sectionalizer on the river crossing is yours to operate for the planned switching.", "SW9", "AUTHORIZED", "compound_auth"),
 ("Go ahead and step the downtown riser regulator up one tap to hold voltage.", "VR1", "AUTHORIZED", "compound_auth"),
 ("The Maple feeder-head recloser is cleared for the scheduled test now.", "R7", "AUTHORIZED", "compound_auth"),
 # --- double-exception / exception-to-exception (hard) ---
 ("All north-feeder devices are off-limits today, but the Elm Avenue capacitor is specifically exempted from that freeze and may be operated.", "CB7", "AUTHORIZED", "double_except"),
 ("Nothing on the Oak Street lateral is to be touched -- except R3 itself, which engineering has cleared.", "R3", "AUTHORIZED", "double_except"),
]

# ===================== serious baseline: regex/grammar =====================
PROHIBIT = [
    "except", "apart from", "other than", "not ", "no ", "never", "cannot", "can't",
    "do not", "don't", "cancel", "cancelled", "canceled", "locked out", "left untouched",
    "left alone", "leave", "as-is", "as it sits", "remains in", "holds", "hold off",
    "hold any", "stays", "stay", "off-limits", "embargo", "frozen", "freeze", "postpone",
    "suspend", "steer clear", "wide berth", "spoken for", "under the", "pulled from",
    "only after", "once the", "not before", "pending", "starting tomorrow", "not tonight",
    "wait", "until", "exempt", "carve-out", "correction", "pending",
]
CLAUSE_SPLIT = re.compile(r"[;.]| -- |,\s")

def mentioned(target, text):
    t = text.lower()
    return any(tok in t for tok in DESC_TOKENS[target])

def regex_grammar(orders, target):
    """Good-faith negation/exclusion-aware parser."""
    if target == MASTER_ID:
        return "UNAUTHORIZED"                      # I1: never operate/block master
    t = orders.lower()
    if not mentioned(target, orders):
        return "UNAUTHORIZED"                      # no order covers it
    # clause containing the target mention
    clauses = CLAUSE_SPLIT.split(orders)
    tgt_clause = next((c for c in clauses if mentioned(target, c)), orders)
    tc = tgt_clause.lower()
    # exclusion list: 'except/apart from ... <target>'
    if re.search(r"(except|apart from|other than|exempt)", t) and mentioned(target, orders):
        # is the target inside the exclusion phrase?
        m = re.search(r"(except|apart from|other than)(.*)$", t)
        if m and any(tok in m.group(2) for tok in DESC_TOKENS[target]):
            return "UNAUTHORIZED"
    # prohibition token in the target's own clause
    if any(p in tc for p in PROHIBIT):
        return "UNAUTHORIZED"
    return "AUTHORIZED"

# ===================== serious baseline: spaCy dependency =====================
_NLP = None
def spacy_dep(orders, target):
    global _NLP
    if target == MASTER_ID:
        return "UNAUTHORIZED"
    try:
        import spacy
        if _NLP is None:
            _NLP = spacy.load("en_core_web_sm")
    except Exception:
        return "PARSE_FAIL"
    if not mentioned(target, orders):
        return "UNAUTHORIZED"
    doc = _NLP(orders)
    # find token(s) that mention the target; check for negation in their clause head
    toks = [tok for tok in doc if any(d.split()[0] in tok.text.lower() for d in DESC_TOKENS[target])]
    if not toks:
        return "AUTHORIZED"
    for tok in toks:
        head = tok.head
        # negation arc on the governing verb, or an explicit exclusion marker nearby
        for child in head.children:
            if child.dep_ == "neg":
                return "UNAUTHORIZED"
        window = doc[max(0, tok.i-6): tok.i+6].text.lower()
        if re.search(r"\b(except|not|no|never|only after|until|left|frozen|hold)\b", window):
            return "UNAUTHORIZED"
    return "AUTHORIZED"

# =============================== run ===============================
def run():
    CASES = list(E.CASES) + NEW
    models = ["phi4-mini", "qwen2.5:7b"]
    methods = ["keyword_id", "keyword_desc", "regex_grammar", "spacy_dep"] + [f"llm::{m}" for m in models]
    rows = []
    t0 = time.time()
    for i, (orders, target, truth, cat) in enumerate(CASES):
        row = {"i": i, "target": target, "truth": truth, "category": cat}
        row["keyword_id"]    = keyword_id(orders, target)
        row["keyword_desc"]  = keyword_desc(orders, target)
        row["regex_grammar"] = regex_grammar(orders, target)
        row["spacy_dep"]     = spacy_dep(orders, target)
        for m in models:
            row[f"llm::{m}"] = ask_llm(m, orders, target, 7)
        rows.append(row)
        if (i+1) % 10 == 0:
            print(f"  {i+1}/{len(CASES)} done  ({time.time()-t0:.0f}s)", flush=True)

    cats = sorted(set(c for *_, c in [(o,t,tr,c) for (o,t,tr,c) in CASES]))
    summary = {"experiment": "E4b_necessity_vs_serious_baselines",
               "n_cases": len(CASES), "methods": methods,
               "overall": {}, "per_category": {}, "hard_false_authorize": {}}
    HARD = ["implicit_neg","conditional","multi_excl_deny","distant_scope",
            "paraphrase_prohibit","double_except","master_trap"]
    for meth in methods:
        # overall (exclude PARSE_FAIL as wrong)
        srows = [{"m": (r[meth] if r[meth] in ("AUTHORIZED","UNAUTHORIZED") else "UNAUTHORIZED"),
                  "truth": r["truth"]} for r in rows]
        summary["overall"][meth] = score(srows, "m")
        summary["per_category"][meth] = {}
        for c in cats:
            cr = [{"m": (r[meth] if r[meth] in ("AUTHORIZED","UNAUTHORIZED") else "UNAUTHORIZED"),
                   "truth": r["truth"]} for r in rows if r["category"] == c]
            if cr:
                summary["per_category"][meth][c] = score(cr, "m")
        # false-authorize on the HARD (prohibition) categories only
        hr = [r for r in rows if r["category"] in HARD]
        fa = sum(1 for r in hr if (r[meth]=="AUTHORIZED" and r["truth"]=="UNAUTHORIZED"))
        summary["hard_false_authorize"][meth] = {"false_authorize": fa, "n_hard_unauth": len(hr)}
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "E4b_necessity_summary.json")
    json.dump({"summary": summary, "rows": rows}, open(out, "w"), indent=2)
    print("\n== OVERALL accuracy ==")
    for meth in methods:
        o = summary["overall"][meth]
        print(f"  {meth:16s} acc={o['accuracy']:.3f}  false_auth={o['false_authorize']}  false_deny={o['false_deny']}")
    print("\n== false-authorize on HARD prohibition cases (lower=better) ==")
    for meth in methods:
        h = summary["hard_false_authorize"][meth]
        print(f"  {meth:16s} {h['false_authorize']}/{h['n_hard_unauth']}")
    print(f"\nWROTE {out}  ({time.time()-t0:.0f}s total)")

if __name__ == "__main__":
    run()
