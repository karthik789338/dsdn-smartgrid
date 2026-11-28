# Real DNP3 -> OpenDSS end-to-end control safety

Runs the real-DNP3 control path end to end across multiple IEEE feeders. A real
`dnp3_python`/opendnp3 **master** issues an `AnalogOutputFloat32` load-multiplier
command over TCP to a real DNP3 **outstation**. Commands that pass the
command-authorization band are applied to an isolated OpenDSS feeder model,
checked against ANSI Range A (0.95-1.05 pu) by the physics oracle, and
automatically rolled back. The DNP3 master (10.0.0.1) is never blocked (I1).

## Components
- `dnp3_outstation.py` - real DNP3 outstation; records the received command.
- `dnp3_master.py` - real DNP3 master; DirectOperate AnalogOutputFloat32.
- `physics_rollback_engine.py` - OpenDSS apply / ANSI check / automatic rollback.
- `control_common.py` - command schema, authorization band, validation.
- `run_multifeeder_endtoend.sh` - orchestrates the three processes per feeder.
- `consolidate_summary.py` - writes results/dnp3_opendss_endtoend_summary.json.

## Requirements
- Python 3.10 virtualenv with `dnp3_python` (opendnp3) and `opendssdirect`.
  Set `DNP3_PY` to its interpreter (default `~/dnp3_310/bin/python`).
  dnp3_python has no wheels for Python 3.12; use 3.10.
- A loopback alias so the testbed outstation address resolves locally:
      sudo ip addr add 10.0.0.7/32 dev lo
- Feeder models under `data/feeders/ieee_testcases/` (13Bus, 34Bus, 123Bus).

## Run
    sudo ip addr add 10.0.0.7/32 dev lo    # once per boot
    DNP3_PY=~/dnp3_310/bin/python bash gridcad/realdnp3_endtoend/run_multifeeder_endtoend.sh

## What the runs demonstrate (defense in depth)
| Run | Feeder | load mult | Expected | Observed |
|-----|--------|-----------|----------|----------|
| ieee13_safe | IEEE13 | 1.02 | authorized + safe | delivered, applied, rolled back |
| ieee34_reject | IEEE34 | 1.02 | authorized but unsafe | delivered, undervoltage caught, rolled back |
| ieee123_safe | IEEE123 | 1.02 | authorized + safe | delivered, applied, rolled back |
| ieee13_overrange | IEEE13 | 1.10 | over-range | refused at command layer, never delivered |

All authorized commands are delivered over real DNP3. The physics oracle is the
hard backstop that catches an authorized-but-unsafe command (IEEE34); the
command-authorization band [1.005, 1.03] refuses the over-range command before
it reaches the wire. A single-station deep dive (over-range AnalogOutput
rejection with full rollback detail) is in `results/dnp3_safety_gates_summary.json`.
