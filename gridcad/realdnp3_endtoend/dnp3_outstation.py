#!/usr/bin/env python3
"""h7: observe a real DNP3 analog-output command, then emit one plant request."""

import argparse
import logging
import signal
import time
from pathlib import Path

from control_common import (
    PORT, STATION_ID, atomic_json, command_record, read_outstation_status,
    utcnow, validate_run_id,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--max-seconds", type=float, default=120)
    parser.add_argument("--interval", type=float, default=0.2)
    args = parser.parse_args()
    validate_run_id(args.run_id)
    if args.max_seconds < 5 or not 0.05 <= args.interval <= 2:
        parser.error("max-seconds >= 5; interval within 0.05..2 seconds")

    from dnp3_python.dnp3station.outstation import MyOutStation

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    output = args.out_dir / "received_command.json"
    ready = args.out_dir / "outstation_ready.json"
    if output.exists() or ready.exists():
        raise RuntimeError("Pilot artifacts already exist; use a new run-specific directory")
    args.out_dir.mkdir(parents=True, exist_ok=True)

    outstation = MyOutStation(port=PORT, outstation_id=STATION_ID, master_id=1)
    stopping = False

    def handle_stop(_signal, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)
    outstation.start()
    start = time.monotonic()
    try:
        supported, baseline, method = read_outstation_status(outstation)
        if not supported:
            raise RuntimeError(
                "Cannot read the outstation's local group-40 AO status. "
                "STOP: no control will be sent to OpenDSS. Inspect MyOutStation API."
            )
        atomic_json(ready, {
            "run_id": args.run_id, "station_id": STATION_ID,
            "port": PORT, "timestamp_utc": utcnow(),
            "readback_method": method, "initial_status": baseline,
        })
        logging.info("ARMED station=%d port=%d output_status_initial=%s via=%s",
                     STATION_ID, PORT, baseline, method)
        while not stopping and (time.monotonic() - start) < args.max_seconds:
            supported, value, _ = read_outstation_status(outstation)
            if not supported:
                raise RuntimeError("Lost output-status readback; stopping fail-closed")
            if value is not None and (baseline is None or abs(value - baseline) > 1e-5):
                # In particular, non-finite, out-of-range and unexpected values
                # cannot be translated into plant commands.
                try:
                    envelope = command_record(args.run_id, value, baseline)
                except ValueError as exc:
                    logging.error("REJECTED observed AO output status %s: %s", value, exc)
                    atomic_json(args.out_dir / "outstation_rejection.json", {
                        "run_id": args.run_id, "observed_status": value,
                        "reason": str(exc), "timestamp_utc": utcnow(),
                    })
                    raise
                atomic_json(output, envelope)
                logging.info("DNP3_RECEIVED station=%d group=40 index=0 loadmult=%.7f",
                             STATION_ID, value)
                return
            time.sleep(args.interval)
        raise TimeoutError("No changed DNP3 AO status observed before deadline")
    finally:
        outstation.shutdown()
        logging.info("Outstation h7 shutdown")


if __name__ == "__main__":
    main()
