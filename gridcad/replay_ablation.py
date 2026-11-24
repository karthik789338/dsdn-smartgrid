#!/usr/bin/env python3
"""
E_detector (replay + model augmentation) -- builds on protocol_detector.py
(the leakage-free protocol-feature detector on the REAL pilot DNP3 capture).

Adds two things the base summary did not isolate:
  1. REPLAY ablation: per-class recall of the HONEST (behavioral-only,
     campaign-blocked) detector WITH vs WITHOUT the dup_recent freshness
     feature. Replayed frames are statistically identical to benign traffic,
     so flow-statistics detectors miss them (the E5/ITHACA 0.27 failure);
     dup_recent is a protocol-freshness signal that should recover them.
  2. XGBoost on the honest behavioral features (campaign-blocked), vs RF,
     to confirm a leakage-free protocol detector needs no deep MLP.
"""
import json, os, sys
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import protocol_detector as D
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import recall_score, f1_score, accuracy_score

# rebuild the exact dataset main() uses (SEED-fixed)
benign = D.parse_pcap()
tmax = max(r["t"] for r in benign)
recs = benign + D.make_attacks(tmax)
Xb, Xf, y, t, camp, labels = D.build(recs)
y = np.asarray(y)
c_tr, c_te = D.split_campaign(camp)

# honest behavioral matrix WITHOUT dup_recent
BEH_no = [k for k in D.BEH if k != "dup_recent"]
Xb_no = np.array([[r[k] for k in BEH_no] for r in recs], float)

def rf():
    return RandomForestClassifier(n_estimators=300, max_depth=None,
                                  random_state=0, n_jobs=-1)

def per_class_recall(X):
    m = rf().fit(X[c_tr], y[c_tr])
    p = m.predict(X[c_te])
    yt = y[c_te]
    rec = {}
    for i, lab in enumerate(labels):
        mask = yt == i
        rec[lab] = round(float(recall_score(yt == i, p == i, zero_division=0)), 4) if mask.sum() else None
    return rec, round(float(f1_score(yt, p, average="macro")), 4), round(float(accuracy_score(yt, p)), 4)

rec_with, f1_with, acc_with = per_class_recall(Xb)      # with dup_recent
rec_no,   f1_no,   acc_no   = per_class_recall(Xb_no)   # without dup_recent

# XGBoost vs RF on honest behavioral features (campaign-blocked)
model_cmp = {}
try:
    from xgboost import XGBClassifier
    xgb = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.3,
                        tree_method="hist", n_jobs=4, verbosity=0)
    xgb.fit(Xb[c_tr], y[c_tr]); px = xgb.predict(Xb[c_te])
    model_cmp["xgboost_honest"] = {"acc": round(float(accuracy_score(y[c_te], px)), 4),
                                   "macro_f1": round(float(f1_score(y[c_te], px, average="macro")), 4)}
except Exception as e:
    model_cmp["xgboost_honest"] = {"error": str(e)}
model_cmp["rf_honest"] = {"acc": acc_with, "macro_f1": f1_with}

out = {
    "experiment": "E_detector_replay_and_model_augmentation",
    "base": "protocol_detector.py (protocol features, real pilot DNP3 pcap, campaign-blocked honest eval)",
    "replay_dup_recent_ablation": {
        "replay_recall_with_dup_recent": rec_with.get("replay"),
        "replay_recall_without_dup_recent": rec_no.get("replay"),
        "macro_f1_with": f1_with, "macro_f1_without": f1_no,
        "note": "dup_recent is a protocol-freshness signal; replayed frames are "
                "statistically benign so flow-only detectors (ITHACA E5: 0.27) miss them.",
    },
    "per_class_recall_with_dup_recent": rec_with,
    "per_class_recall_without_dup_recent": rec_no,
    "honest_model_comparison_campaign_blocked": model_cmp,
}
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "replay_ablation_summary.json"), "w"), indent=2)
print("== REPLAY recall (honest, campaign-blocked) ==")
print(f"  with dup_recent   : {rec_with.get('replay')}")
print(f"  without dup_recent: {rec_no.get('replay')}")
print(f"  macro-F1 with/without: {f1_with} / {f1_no}")
print("== honest model comparison (behavioral feats, campaign-blocked) ==")
for k, v in model_cmp.items():
    print(f"  {k:16s} {v}")
print("WROTE replay_ablation_summary.json")
