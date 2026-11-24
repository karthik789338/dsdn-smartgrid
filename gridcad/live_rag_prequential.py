#!/usr/bin/env python3
"""
E9 - live-RAG done properly (R2-10): a prequential (test-then-train) evaluation of
the retrieval layer over a stream of 1,000 DNP3 incidents, with held-out separation
and bootstrap confidence intervals.

Protocol (the contribution; retrieval-method-agnostic):
  for t = 1..N:  predict the mitigation for incident t using ONLY incidents 1..t-1
                 (strict prior-only retrieval, exact duplicates excluded), score it,
                 THEN ingest incident t. No future information ever reaches a prediction.

Conditions:
  no_rag        : predict the most-frequent mitigation seen so far (prior baseline, no retrieval)
  live_rag      : leakage-free kNN over the accumulated PRIOR store (the honest RAG number)
  leaky_rag     : kNN over a pool that INCLUDES the current incident (and its duplicates) -
                  the inflated number the original, leak-prone evaluation would report.

Retrieval similarity: hashing char+word n-gram vectors + cosine (reproducible, no model
download, no fitted vocabulary -> fully online-honest). The protocol is what R2-10 asks for;
the lexical retriever is a reproducible stand-in for the production dense-embedding RAG.

Outputs: cumulative accuracy learning curve, final-window accuracy with bootstrap 95% CIs,
and the leaky-minus-honest gap that quantifies the leakage hazard.
"""
import random, json
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.metrics.pairwise import cosine_similarity

random.seed(7); np.random.seed(7)
N = 1000
K = 5
WINDOW = 200   # final-window for CI

# 10 ITHACA attack families, each with a distinct prescribed mitigation (the label).
FAMILIES = {
    "ARP_POISONING":    "isolate_l2_segment",
    "DISABLE_UNSOLICITED": "restore_unsolicited_and_block_src",
    "COLD_RESTART":     "rate_limit_restart_fc",
    "WARM_RESTART":     "rate_limit_restart_fc",   # shares mitigation with cold (behavioral neighbor)
    "DNP3_ENUMERATE":   "drop_scan_source",
    "DNP3_INFO":        "drop_scan_source",         # shares with enumerate
    "INIT_DATA":        "reauth_and_resync",
    "MITM_DOS":         "reroute_around_attacker",
    "REPLAY":           "enforce_freshness_gate",
    "STOP_APP":         "block_stop_app_fc",
}
FAMS = list(FAMILIES.keys())

# paraphrase fragments per family (varied surface form, family signal retained)
PHRASES = {
    "ARP_POISONING":    ["ARP cache being poisoned", "spoofed MAC bindings on the L2 link",
                         "gratuitous ARP flooding the segment", "layer-2 address spoofing detected"],
    "DISABLE_UNSOLICITED": ["spoofed DISABLE_UNSOLICITED frames", "attacker suppressing unsolicited responses",
                         "function code 21 disabling event reporting", "unsolicited messaging turned off remotely"],
    "COLD_RESTART":     ["unrequested COLD_RESTART commands", "function code 13 cold restart storm",
                         "device forced into cold reboot", "repeated cold-restart requests"],
    "WARM_RESTART":     ["unrequested WARM_RESTART commands", "function code 14 warm restart storm",
                         "device forced into warm reboot", "repeated warm-restart requests"],
    "DNP3_ENUMERATE":   ["point enumeration scan", "attacker enumerating DNP3 index range",
                         "systematic object/variation probing", "class-0 enumeration sweep"],
    "DNP3_INFO":        ["device info harvesting", "reading attribute set 0 for recon",
                         "pulling file/device identification", "information-gathering reads"],
    "INIT_DATA":        ["INIT_DATA to wipe accumulators", "function code 15 reinitialize data",
                         "counters being zeroed remotely", "data reinitialization abuse"],
    "MITM_DOS":         ["man-in-the-middle dropping frames", "MITM causing a denial of service",
                         "on-path attacker blackholing traffic", "intercept-and-drop flooding"],
    "REPLAY":           ["replayed capture of a prior session", "stale authenticated frames resent",
                         "recorded command replayed", "sequence-number replay flood"],
    "STOP_APP":         ["STOP_APPLICATION command abuse", "function code 18 halting the app",
                         "outstation application stopped remotely", "forced app shutdown"],
}
FEEDERS = ["IEEE13", "IEEE34", "IEEE123"]
FILLERS = ["observed on the feeder", "flagged by the IDS", "during the evening peak",
           "reported by the operator", "seen in the DNP3 session logs", "at the substation gateway",
           "", "", "intermittently", "with elevated severity"]


def make_incident(fam):
    dev = "10.0.0.%d" % random.randint(2, 24)
    feeder = random.choice(FEEDERS)
    ph = random.choice(PHRASES[fam])
    f1, f2 = random.choice(FILLERS), random.choice(FILLERS)
    text = f"Outstation {dev} on {feeder}: {ph} {f1} {f2}.".replace("  ", " ")
    return text, FAMILIES[fam]


# build the stream (balanced-ish families, shuffled order)
stream = []
order = (FAMS * (N // len(FAMS) + 1))[:N]
random.shuffle(order)
for fam in order:
    stream.append(make_incident(fam))
texts = [s[0] for s in stream]
labels = [s[1] for s in stream]

vec = HashingVectorizer(analyzer="char_wb", ngram_range=(3, 5), n_features=2 ** 18, norm="l2")
X = vec.transform(texts)   # row-normalized; cosine = dot product. No fitted vocab -> no leakage.

LABELSET = sorted(set(labels))


def majority(neigh_labels):
    from collections import Counter
    return Counter(neigh_labels).most_common(1)[0][0]


# prequential loop
correct = {"no_rag": [], "live_rag": [], "leaky_rag": []}
from collections import Counter
seen = Counter()
for t in range(N):
    y = labels[t]
    # no_rag: most-frequent mitigation among PRIOR incidents (prior baseline)
    pred_nr = seen.most_common(1)[0][0] if seen else LABELSET[0]
    correct["no_rag"].append(int(pred_nr == y))
    # live_rag: kNN over strictly prior store 0..t-1, exclude exact-text duplicates of t
    if t == 0:
        pred_lr = LABELSET[0]
    else:
        sims = cosine_similarity(X[t], X[:t]).ravel()
        dup = np.array([texts[j] == texts[t] for j in range(t)])
        sims[dup] = -1.0          # held-out separation: never retrieve an identical incident
        order_idx = np.argsort(-sims)
        top = [j for j in order_idx if sims[j] > -1.0][:K]
        pred_lr = majority([labels[j] for j in top]) if top else pred_nr
    correct["live_rag"].append(int(pred_lr == y))
    # leaky_rag: pool INCLUDES the current incident (and duplicates) -> self-retrieval inflates
    sims_all = cosine_similarity(X[t], X[:t + 1]).ravel()
    order_all = np.argsort(-sims_all)[:K]
    pred_leak = majority([labels[j] for j in order_all])
    correct["leaky_rag"].append(int(pred_leak == y))
    # ingest
    seen[y] += 1


def boot_ci(bits, iters=2000):
    bits = np.array(bits)
    n = len(bits)
    means = [bits[np.random.randint(0, n, n)].mean() for _ in range(iters)]
    return round(float(np.percentile(means, 2.5)), 3), round(float(np.percentile(means, 97.5)), 3)


def curve(bits, step=100):
    # cumulative accuracy at each checkpoint
    c = np.cumsum(bits)
    return {str(i): round(float(c[i - 1] / i), 3) for i in range(step, N + 1, step)}


summary = {"meta": {
    "experiment": "E9 - prequential live-RAG with held-out separation + CIs",
    "n_incidents": N, "k": K, "final_window": WINDOW,
    "retriever": "HashingVectorizer char_wb 3-5grams + cosine (no fitted vocab; reproducible)",
    "families": len(FAMS), "label_classes": len(LABELSET),
    "note": ("Prequential test-then-train: each incident is predicted from PRIOR incidents only "
             "(exact duplicates excluded = held-out separation), then ingested. no_rag = running "
             "most-frequent mitigation; live_rag = leakage-free kNN (the honest number); leaky_rag = "
             "kNN whose pool includes the current incident (the inflated number a leak-prone eval reports). "
             "The leaky-minus-honest gap is the leakage hazard R2-10 flagged."),
}}
for cond in ["no_rag", "live_rag", "leaky_rag"]:
    bits = correct[cond]
    overall = round(float(np.mean(bits)), 3)
    fw = bits[-WINDOW:]
    fw_acc = round(float(np.mean(fw)), 3)
    lo, hi = boot_ci(fw)
    summary[cond] = {"overall_acc": overall,
                     "final_window_acc": fw_acc, "final_window_ci95": [lo, hi],
                     "learning_curve_cumacc": curve(bits)}
summary["leaky_minus_live_final_window"] = round(summary["leaky_rag"]["final_window_acc"]
                                                 - summary["live_rag"]["final_window_acc"], 3)
summary["live_minus_norag_final_window"] = round(summary["live_rag"]["final_window_acc"]
                                                 - summary["no_rag"]["final_window_acc"], 3)

json.dump(summary, open("results/E9_live_rag_summary.json", "w"), indent=2)
print("=== E9 prequential live-RAG (N=%d, k=%d, %d mitigation classes) ===" % (N, K, len(LABELSET)))
for cond in ["no_rag", "live_rag", "leaky_rag"]:
    s = summary[cond]
    print("%-10s overall=%.3f  final%d=%.3f  CI95=%s" % (cond, s["overall_acc"], WINDOW,
          s["final_window_acc"], s["final_window_ci95"]))
print("live_rag - no_rag (final window) = +%.3f   |   leaky - live (leakage inflation) = +%.3f"
      % (summary["live_minus_norag_final_window"], summary["leaky_minus_live_final_window"]))
print("live_rag learning curve:", summary["live_rag"]["learning_curve_cumacc"])
print("WROTE results/E9_live_rag_summary.json")
