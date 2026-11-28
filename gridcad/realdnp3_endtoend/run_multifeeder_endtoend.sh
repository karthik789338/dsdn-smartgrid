#!/bin/bash
# Real DNP3 -> OpenDSS multi-feeder end-to-end runner (two-process master+outstation).
# A real dnp3_python/opendnp3 master issues AnalogOutputFloat32 load-multiplier
# commands to a real DNP3 outstation; authorized commands are applied to an
# isolated OpenDSS feeder, validated against ANSI Range A, and rolled back.
# Requirements: see README.md (Python 3.10 venv with dnp3_python + opendssdirect,
# and a loopback alias for the outstation IP 10.0.0.7).
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${DNP3_PY:-$HOME/dnp3_310/bin/python}"
FEED="$REPO/data/feeders/ieee_testcases"
export PYTHONPATH="$HERE"
OUT="${1:-$REPO/results/realdnp3_runs}"
rm -rf "$OUT"; mkdir -p "$OUT"
declare -A MODEL=( [IEEE13]=$FEED/13Bus/IEEE13Nodeckt.dss [IEEE34]=$FEED/34Bus/ieee34Mod1.dss [IEEE123]=$FEED/123Bus/IEEE123Master.dss )
run(){ local f=$1 lm=$2 tag=$3; local D=$OUT/$tag; mkdir -p $D; local RID=${tag}_run
  pkill -f dnp3_outstation 2>/dev/null; sleep 1
  $PY $HERE/dnp3_outstation.py --run-id $RID --out-dir $D --max-seconds 70 >$D/out.log 2>&1 &
  $PY $HERE/physics_rollback_engine.py --model ${MODEL[$f]} --run-id $RID --out-dir $D --max-wait-seconds 70 >$D/engine.log 2>&1 & local ep=$!
  sleep 7
  $PY $HERE/dnp3_master.py --run-id $RID --out-dir $D --load-mult $lm >$D/master.log 2>&1
  echo "$tag master_rc=$?"; wait $ep 2>/dev/null; pkill -f dnp3_outstation 2>/dev/null; sleep 2; }
run IEEE13 1.02 ieee13_safe
run IEEE34 1.02 ieee34_reject
run IEEE123 1.02 ieee123_safe
run IEEE13 1.10 ieee13_overrange
$PY $HERE/consolidate_summary.py "$OUT" "$REPO/results/dnp3_opendss_endtoend_summary.json"
echo ALL_DONE
