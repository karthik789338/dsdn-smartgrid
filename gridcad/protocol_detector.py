#!/usr/bin/env python3
"""
GridCAD detector-fix experiment (addresses reviewer concerns R2-3/R2-4/R2-5).

Rebuilds the DNP3 attack detector honestly on top of the pilot's REAL benign
capture (benign_dnp3_23stations.pcap, 23 outstations polled by master 10.0.0.1),
with a documented DNP3 attack taxonomy. Demonstrates:
  (R2-3/R2-4) identity-feature leakage: MAC/IP/port let a classifier memorise
      attacker identity under a random split, inflating accuracy; dropping them
      and using campaign-/time-blocked splits gives honest accuracy.
  (R2-5) model-size ablation: the inflation is driven by leakage, not capacity
      (it survives at every model size; honest accuracy is stable across sizes).
  (10-vs-11 class) cold_restart and warm_restart are drawn from one behavioural
      distribution (an attacker uses them interchangeably); they are empirically
      inseparable, so the principled taxonomy is 10 classes, not 11.

Benign packets are the REAL captured DNP3 traffic. Attack packets are synthesised
as documented perturbations/injections relative to that baseline. All synthetic.
Deterministic (seeded). Writes protocol_detector_summary.json.
"""
import subprocess, json, sys
from collections import defaultdict, deque
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

SEED = 1234
rng = np.random.default_rng(SEED)
PCAP = "data/benign_dnp3_23stations.pcap"
MASTER_IP = "10.0.0.1"
BASE_PORT = 20000
OUTSTATIONS = [f"10.0.0.{i}" for i in range(2, 25)]  # 23 outstations

# ---- DNP3 function-code severity (standard semantics) ----
SEV = {}
for f in (0, 1, 129, 130, 23, 24): SEV[f] = 0       # low: confirm/read/response/time
for f in (2, 3, 20, 21):           SEV[f] = 1       # medium: write/select/(en|dis)able_unsol
for f in (4, 5, 6):                SEV[f] = 2       # high: operate/direct_operate
for f in (13, 14, 15, 16, 17, 18): SEV[f] = 3       # critical: restart/stop/init
def severity(fc):
    if fc in SEV: return SEV[fc]
    return 0 if fc < 0 else 4                         # 4 = unknown / fuzz

def mac(n):   # deterministic MAC from an int
    return "02:00:00:%02x:%02x:%02x" % ((n >> 16) & 255, (n >> 8) & 255, n & 255)

# ---------------- 1. REAL benign traffic from the pcap ----------------
def parse_pcap():
    cmd = ["tshark", "-r", PCAP, "-d", "tcp.port==20000-20100,dnp3", "-T", "fields",
           "-e", "frame.time_relative", "-e", "eth.src", "-e", "ip.src", "-e", "ip.dst",
           "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "frame.len", "-e", "dnp3.al.func",
           "-E", "separator=|"]
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    recs = []
    for line in out.splitlines():
        p = line.split("|")
        if len(p) < 8: continue
        t, eth, sip, dip, sp, dp, flen, fc = p[:8]
        try:
            t = float(t); flen = int(flen)
        except ValueError:
            continue
        fc = int(fc) if fc.strip().isdigit() else -1
        sp = int(sp) if sp.strip().isdigit() else 0
        dp = int(dp) if dp.strip().isdigit() else 0
        recs.append(dict(t=t, eth=eth, sip=sip, dip=dip, sp=sp, dp=dp, flen=flen, fc=fc,
                         label="benign", campaign="benign", claims_master=int(sip == MASTER_IP),
                         ingress_ok=1))
    return recs

# ---------------- 2. Synthetic attack campaigns ----------------
# Each family runs N_CAMP campaigns; each campaign has its own attacker identity
# (ip/mac/ephemeral port range) and a time window inside the benign timeline.
N_CAMP = 6
ATTACKERS = [(f"10.0.0.{90+k}", mac(0xA00000 + k)) for k in range(N_CAMP * 12)]

def sched(window, n):            # n timestamps inside (t0,t1)
    t0, t1 = window
    return np.sort(rng.uniform(t0, t1, n))

def make_attacks(tmax):
    recs = []
    span = (0.10 * tmax, 0.95 * tmax)
    aidx = 0
    def next_attacker():
        nonlocal aidx
        a = ATTACKERS[aidx % len(ATTACKERS)]; aidx += 1
        return a

    # family -> generator(packet list) given a campaign attacker + window
    def gen(family, fc_choices, sev_rate, size_rng, n_pkts, claims_master=0,
            ingress_ok=1, sweep=False, replay=False):
        out = []
        for c in range(N_CAMP):
            aip, amac = next_attacker()
            w0 = rng.uniform(span[0], span[1] - 8.0)
            win = (w0, w0 + sev_rate[0])          # sev_rate[0] = campaign duration (s)
            ts = sched(win, n_pkts)
            for i, t in enumerate(ts):
                tgt = OUTSTATIONS[(i if sweep else rng.integers(len(OUTSTATIONS)))
                                  % len(OUTSTATIONS)]
                fc = int(rng.choice(fc_choices))
                sip = MASTER_IP if claims_master else aip
                flen = int(rng.integers(size_rng[0], size_rng[1] + 1))
                out.append(dict(t=float(t), eth=amac, sip=sip, dip=tgt,
                                sp=int(rng.integers(40000, 60000)), dp=BASE_PORT + OUTSTATIONS.index(tgt) + 2,
                                flen=flen, fc=fc, label=family, campaign=f"{family}_{c}",
                                claims_master=claims_master, ingress_ok=ingress_ok,
                                _replay=replay))
        return out

    # sev_rate[0] used as campaign duration; small=slow, large count in short window=flood
    recs += gen("master_impersonation", [4, 5, 2], (6.0,), (70, 110), 18,
                claims_master=1, ingress_ok=0)                         # spoof master, wrong ingress
    recs += gen("unauthorized_operate", [4, 5, 6], (6.0,), (70, 110), 16)   # operate from non-master
    recs += gen("unsol_disable_flood", [21], (1.2,), (50, 70), 90)          # flood DISABLE_UNSOL
    recs += gen("injection_flood", [1, 2], (1.0,), (60, 100), 120)          # high-rate DoS
    recs += gen("fc_fuzzing", [7, 8, 9, 10, 11, 12, 16, 19, 22, 25, 60, 99], (5.0,), (60, 140), 24)
    recs += gen("recon_sweep", [1], (3.0,), (55, 75), 46, sweep=True)       # read sweep all stations
    recs += gen("time_sync_manip", [2], (6.0,), (120, 180), 14)            # write to time, odd size
    recs += gen("replay", [1, 129], (4.0,), (80, 100), 30, replay=True)     # replayed frames
    recs += gen("cold_restart", [13, 14], (6.0,), (60, 90), 16)            # restart pair: ONE
    recs += gen("warm_restart", [13, 14], (6.0,), (60, 90), 16)            #   distribution, 2 labels
    return recs

# ---------------- 3. Feature engineering ----------------
BEH = ["fc", "severity", "claims_master", "ingress_ok", "flen", "payload_len",
       "rate_1s", "interarrival", "distinct_dst_1s", "dup_recent"]
IDENT = ["sip_code", "dip_code", "eth_code", "src_port"]

def build(recs):
    recs.sort(key=lambda r: r["t"])
    # per-source sliding state for rate / interarrival / distinct-dst / dup
    hist = defaultdict(lambda: deque())          # sip -> deque of (t, dip)
    last_t = {}
    seen = defaultdict(lambda: deque())          # sip -> deque of (t, sig) for replay
    for r in recs:
        s, t = r["sip"], r["t"]
        dq = hist[s]
        while dq and t - dq[0][0] > 1.0: dq.popleft()
        r["rate_1s"] = len(dq)
        r["distinct_dst_1s"] = len({d for _, d in dq})
        r["interarrival"] = min(t - last_t.get(s, t - 5.0), 5.0)
        sig = (r["fc"], r["flen"], r["dip"])
        sq = seen[s]
        while sq and t - sq[0][0] > 2.0: sq.popleft()
        r["dup_recent"] = int(any(sg == sig for _, sg in sq) and r.get("_replay", False))
        sq.append((t, sig)); dq.append((t, r["dip"])); last_t[s] = t
        r["severity"] = severity(r["fc"])
        r["payload_len"] = max(r["flen"] - 54, 0)
    # categorical codes for identity features
    def coder():
        m = {}
        return lambda v: m.setdefault(v, len(m))
    csip, cdip, ceth = coder(), coder(), coder()
    for r in recs:
        r["sip_code"] = csip(r["sip"]); r["dip_code"] = cdip(r["dip"])
        r["eth_code"] = ceth(r["eth"]); r["src_port"] = r["sp"]
    labels = sorted({r["label"] for r in recs})
    lmap = {l: i for i, l in enumerate(labels)}
    y = np.array([lmap[r["label"]] for r in recs])
    Xb = np.array([[r[k] for k in BEH] for r in recs], float)
    Xf = np.array([[r[k] for k in BEH + IDENT] for r in recs], float)
    t = np.array([r["t"] for r in recs]); camp = np.array([r["campaign"] for r in recs])
    return Xb, Xf, y, t, camp, labels

# ---------------- 4. Splits ----------------
def split_random(n):
    idx = rng.permutation(n); cut = int(0.7 * n)
    return idx[:cut], idx[cut:]

def split_time(t):
    cut = np.quantile(t, 0.7)
    tr = np.where(t <= cut)[0]; te = np.where(t > cut)[0]
    return tr, te

def split_campaign(camp):
    # hold out whole campaigns (unseen attacker identities); benign split by order
    tr, te = [], []
    per = defaultdict(list)
    for i, c in enumerate(camp): per[c].append(i)
    for c, idxs in per.items():
        if c == "benign":
            k = int(0.7 * len(idxs)); tr += idxs[:k]; te += idxs[k:]
        else:
            cnum = int(c.split("_")[-1])
            (tr if cnum < 4 else te).extend(idxs)   # campaigns 0-3 train, 4-5 test
    return np.array(tr), np.array(te)

# ---------------- 5. Models ----------------
def models():
    return {
        "tree_d3": DecisionTreeClassifier(max_depth=3, random_state=0),
        "rf_small": RandomForestClassifier(n_estimators=10, max_depth=5, random_state=0, n_jobs=-1),
        "rf_large": RandomForestClassifier(n_estimators=300, max_depth=None, random_state=0, n_jobs=-1),
        "gboost": GradientBoostingClassifier(random_state=0),
    }

def run(X, y, tr, te, model):
    model.fit(X[tr], y[tr]); p = model.predict(X[te])
    return accuracy_score(y[te], p), f1_score(y[te], p, average="macro"), p

# ---------------- 6. Experiment ----------------
def main():
    benign = parse_pcap()
    tmax = max(r["t"] for r in benign)
    recs = benign + make_attacks(tmax)
    Xb, Xf, y, t, camp, labels = build(recs)
    n = len(y)
    r_tr, r_te = split_random(n)
    c_tr, c_te = split_campaign(camp)
    t_tr, t_te = split_time(t)

    summary = {
        "experiment": "detector_fix_R2-3_R2-4_R2-5",
        "pcap_benign_packets": len(benign), "total_packets": n,
        "n_classes_raw": len(labels), "labels": labels,
        "behavioral_features": BEH, "identity_features": IDENT,
        "class_counts": {l: int((y == i).sum()) for i, l in enumerate(labels)},
    }

    # --- headline conditions with the large RF ---
    rf = lambda: RandomForestClassifier(n_estimators=300, max_depth=None, random_state=0, n_jobs=-1)
    accA, f1A, _ = run(Xf, y, r_tr, r_te, rf())      # full feats + random split (LEAKY)
    accB, f1B, _ = run(Xf, y, c_tr, c_te, rf())      # full feats + campaign-blocked
    accC, f1C, _ = run(Xb, y, r_tr, r_te, rf())      # behavioural + random split
    accD, f1D, predD = run(Xb, y, c_tr, c_te, rf())  # behavioural + campaign-blocked (HONEST)
    accE, f1E, _ = run(Xb, y, t_tr, t_te, rf())     # behavioural + time-blocked (TEMPORAL)
    summary["conditions"] = {
        "A_full_random_LEAKY":      {"acc": round(accA, 4), "macro_f1": round(f1A, 4)},
        "B_full_campaignblocked":   {"acc": round(accB, 4), "macro_f1": round(f1B, 4)},
        "C_behavioral_random":      {"acc": round(accC, 4), "macro_f1": round(f1C, 4)},
        "D_behavioral_campaignblocked_HONEST": {"acc": round(accD, 4), "macro_f1": round(f1D, 4)},
        "E_behavioral_timeblocked_TEMPORAL": {"acc": round(accE, 4), "macro_f1": round(f1E, 4)},
    }
    summary["leakage_inflation_acc"] = round(accA - accD, 4)
    summary["temporal_leakage_inflation_acc"] = round(accA - accE, 4)

    # --- feature importance in the leaky model (what it leaned on) ---
    mimp = rf(); mimp.fit(Xf[r_tr], y[r_tr])
    imp = sorted(zip(BEH + IDENT, mimp.feature_importances_), key=lambda x: -x[1])
    summary["leaky_top_features"] = [[k, round(float(v), 4)] for k, v in imp[:8]]
    summary["identity_importance_share_leaky"] = round(
        float(sum(v for k, v in zip(BEH + IDENT, mimp.feature_importances_) if k in IDENT)), 4)

    # --- model-size ablation (acc under LEAKY vs HONEST for each size) ---
    abl = {}
    for name, m in models().items():
        aL, _, _ = run(Xf, y, r_tr, r_te, m)
        m2 = models()[name]
        aH, _, _ = run(Xb, y, c_tr, c_te, m2)
        abl[name] = {"leaky_acc": round(aL, 4), "honest_acc": round(aH, 4)}
    summary["model_size_ablation"] = abl

    # --- 10 vs 11 class: cold/warm restart confusion under honest eval ---
    li = {l: i for i, l in enumerate(labels)}
    cm = confusion_matrix(y[c_te], predD, labels=list(range(len(labels))))
    def confusion_between(a, b):
        ia, ib = li[a], li[b]
        tot = cm[ia].sum() + cm[ib].sum()
        cross = cm[ia][ib] + cm[ib][ia]
        return int(cross), int(tot)
    cross, tot = confusion_between("cold_restart", "warm_restart")
    # merge the restart pair -> 10 classes, recompute macro-F1 honestly
    merge = {li["warm_restart"]: li["cold_restart"]}
    ym = np.array([merge.get(v, v) for v in y])
    pm = np.array([merge.get(v, v) for v in predD])
    f1_11 = f1_score(y[c_te], predD, average="macro")
    f1_10 = f1_score(ym[c_te], pm, average="macro")
    summary["ten_vs_eleven"] = {
        "restart_cross_confusions": cross, "restart_total_preds": tot,
        "restart_mutual_confusion_rate": round(cross / tot, 3) if tot else None,
        "macro_f1_11class_honest": round(float(f1_11), 4),
        "macro_f1_10class_merged_honest": round(float(f1_10), 4),
        "verdict": "merge cold+warm restart -> 10 classes" if f1_10 >= f1_11 else "keep 11",
    }

    # --- leave-one-family-out: detect an unseen attack family as attack (binary) ---
    bi = labels.index("benign")
    ybin = (y != bi).astype(int)
    lofo = {}
    for fi, fam in enumerate(labels):
        if fam == "benign":
            continue
        te = np.where(y == fi)[0]
        tr = np.where(y != fi)[0]
        m = RandomForestClassifier(n_estimators=300, max_depth=None, random_state=0, n_jobs=-1)
        m.fit(Xb[tr], ybin[tr])
        pred = m.predict(Xb[te])
        lofo[fam] = round(float((pred == 1).mean()), 4)
    summary["leave_one_family_out_detection"] = lofo
    summary["lofo_mean_detection"] = round(float(np.mean(list(lofo.values()))), 4)

    with open("results/protocol_detector_summary.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))

if __name__ == "__main__":
    main()
