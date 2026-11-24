#!/usr/bin/env python3
"""
E10b - Live ONOS controller-failover latency (the number deferred from E10/E12).

Measures CONTROL-plane mastership failover on the live 3-instance ONOS 2.2.1 +
3-node Atomix 3.1.5 cluster: time from SIGKILL of the master controller to a
surviving controller taking mastership of a MULTI-HOMED switch. The data plane
is unaffected (installed flow rules persist - OpenFlow fail-static, E10); this
times when new control decisions can be made again.

Each trial: find the current master of the device, `docker kill` it (abrupt
crash), poll REST device-mastership on a surviving node until mastership moves
to a live node, record the latency and whether the device stayed available
(it is still attached to the 2 surviving controllers). Then restart the killed
node and wait for a 3-node READY cluster before the next trial (quorum safety:
never kill 2 of 3 at once).
"""
import json, time, subprocess, urllib.request, base64, os

AUTH = base64.b64encode(b"onos:rocks").decode()
NODE = {"172.20.0.5": ("onos-1", 8181),
        "172.20.0.6": ("onos-2", 8182),
        "172.20.0.7": ("onos-3", 8183)}
D = "of:0000a2c10641aa48"           # the multi-homed ftest switch
TRIALS = 7
PROG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "e10b_prog.txt")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results", "E10b_failover_summary.json")

def g(port, path):
    r = urllib.request.Request("http://localhost:%d%s" % (port, path),
                               headers={"Authorization": "Basic " + AUTH})
    return json.loads(urllib.request.urlopen(r, timeout=5).read())

def master(port): return g(port, "/onos/v1/mastership/%s/master" % D).get("nodeId")
def avail(port):
    try: return g(port, "/onos/v1/devices/%s" % D).get("available")
    except Exception: return None
def ready(port):
    return sum(1 for n in g(port, "/onos/v1/cluster")["nodes"]
               if n.get("status") == "READY")
def sh(*a): subprocess.run(a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def up_ports():
    o = []
    for ip, (c, p) in NODE.items():
        try: g(p, "/onos/v1/cluster"); o.append((ip, p))
        except Exception: pass
    return o
def log(m):
    with open(PROG, "a") as f: f.write("%s\n" % m)

res = []
log("START trials=%d" % TRIALS)
for t in range(TRIALS):
    ups = up_ports()
    if len(ups) < 2:
        log("t%d cluster-degraded skip" % t); continue
    q0 = ups[0][1]
    mip = master(q0)
    if mip not in NODE:
        log("t%d nomaster(%s)" % (t, mip)); continue
    cont, mport = NODE[mip]
    qport = next(p for ip, p in ups if ip != mip)   # query a survivor
    stayed = True
    t0 = time.perf_counter()
    sh("sudo", "docker", "kill", cont)
    new = None
    while time.perf_counter() - t0 < 40:
        try:
            nm = master(qport)
            if nm and nm != mip and nm in NODE:
                new = nm; break
        except Exception: pass
        if avail(qport) is False: stayed = False
        time.sleep(0.03)
    t1 = time.perf_counter()
    fo = round(t1 - t0, 3) if new else None
    av = avail(qport)
    res.append({"trial": t, "killed": cont, "killed_ip": mip, "new_master": new,
                "failover_s": fo, "device_available_after": av,
                "device_stayed_available": stayed})
    log("t%d kill %s -> %s fo=%s avail_after=%s stayed=%s" %
        (t, cont, new, fo, av, stayed))
    sh("sudo", "docker", "start", cont)        # restore the node
    w = time.perf_counter()
    while time.perf_counter() - w < 150:
        try:
            if ready(qport) >= 3: break
        except Exception: pass
        time.sleep(0.5)
    time.sleep(5)                              # settle / rebalance

fos = [r["failover_s"] for r in res if r["failover_s"]]
stayed_all = all(r["device_stayed_available"] for r in res) if res else False
out = {
    "device": D,
    "config": "single OVS switch multi-homed to all 3 ONOS controllers "
              "(tcp:172.20.0.5/6/7:6653)",
    "n_trials": len(res), "trials": res,
    "failover_s": {
        "n": len(fos),
        "p50": round(sorted(fos)[len(fos)//2], 3) if fos else None,
        "mean": round(sum(fos)/len(fos), 3) if fos else None,
        "min": round(min(fos), 3) if fos else None,
        "max": round(max(fos), 3) if fos else None},
    "device_stayed_available_all_trials": stayed_all,
    "method": "docker kill (SIGKILL) the current ONOS master; poll REST device-"
              "mastership on a surviving node until mastership moves to a live "
              "node; restart killed node and wait for 3-node READY between trials",
    "cluster": "3x ONOS 2.2.1 + 3x Atomix 3.1.5 (live pilot cluster)",
    "caveats": [
        "CONTROL-plane mastership failover: time from SIGKILL of the master to a "
        "surviving controller taking mastership of a multi-homed switch; bounded "
        "by the Atomix failure-detection/term timeout.",
        "Requires the switch to be multi-homed (connected to all 3 controllers). "
        "The pilot fabric shards each switch to ONE controller, which gives NO "
        "OF-layer failover (killing that controller disconnects the switch); the "
        "resilient design multi-homes, which is what is measured here.",
        "Data-plane forwarding from already-installed flow rules persists through "
        "the window (OpenFlow fail-static, E10); device_stayed_available confirms "
        "the switch never lost connectivity (still attached to 2 survivors).",
        "Single switch, single EC2 host, container-local cluster; wall-clock "
        "indicative, not a datacenter-grade bound.",
    ],
}
json.dump(out, open(OUT, "w"), indent=2)
log("DONE %s stayed=%s" % (out["failover_s"], stayed_all))
print("DONE", out["failover_s"], "stayed", stayed_all)
print("WROTE", OUT)
