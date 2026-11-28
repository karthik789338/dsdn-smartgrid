#!/usr/bin/env python3
"""h1: one bounded DNP3 direct-operate AO command to the isolated h7 endpoint."""

import argparse
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from control_common import (
    INDEX, PORT, STATION_ID, atomic_json, utcnow,
    validate_load_mult, validate_run_id,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--load-mult", type=float, default=1.02)
    parser.add_argument("--connect-timeout", type=float, default=20)
    parser.add_argument("--observe-timeout", type=float, default=15)
    args = parser.parse_args()
    validate_run_id(args.run_id)
    validate_load_mult(args.load_mult)
    if args.connect_timeout <= 0 or args.observe_timeout <= 0:
        parser.error("timeouts must be positive")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ready_path = args.out_dir / "outstation_ready.json"
    engine_path = args.out_dir / "engine_ready.json"
    outstation_event = args.out_dir / "received_command.json"
    sent_path = args.out_dir / "master_sent.json"
    if sent_path.exists() or outstation_event.exists() or (args.out_dir / "result.json").exists():
        raise RuntimeError("Existing master/control evidence: use a fresh run directory")
    ready = json.loads(ready_path.read_text(encoding="utf-8"))
    if ready.get("run_id") != args.run_id or ready.get("station_id") != STATION_ID:
        raise ValueError("Wrong h7 outstation run identity")
    ready_at = datetime.fromisoformat(ready["timestamp_utc"])
    if ready_at.tzinfo is None or not 0 <= (datetime.now(timezone.utc) - ready_at).total_seconds() <= 120:
        raise RuntimeError("Outstation ready marker stale or clock-skewed")
    engine = json.loads(engine_path.read_text(encoding="utf-8"))
    engine_at = datetime.fromisoformat(engine["timestamp_utc"])
    if (engine.get("run_id") != args.run_id or engine_at.tzinfo is None
            or not 0 <= (datetime.now(timezone.utc) - engine_at).total_seconds() <= 120):
        raise RuntimeError("Independent OpenDSS engine is not armed for this run")

    from dnp3_python.dnp3station.master import MyMaster
    from pydnp3 import opendnp3

    endpoint = MyMaster(outstation_ip=f"10.0.0.{STATION_ID}", port=PORT,
                        master_id=1, outstation_id=STATION_ID)
    callback_event = threading.Event()
    callback_result = {"called": False}

    def on_result(result):
        callback_result["called"] = True
        callback_result["summary"] = str(getattr(result, "summary", "unknown"))
        callback_result["raw_result_repr"] = repr(result)[:600]
        callback_event.set()
        logging.info("DNP3_TASK_CALLBACK summary=%s", callback_result["summary"])

    endpoint.start()
    try:
        start = time.monotonic()
        while time.monotonic() - start < args.connect_timeout:
            state = endpoint.is_connected
            if bool(state() if callable(state) else state):
                break
            time.sleep(0.25)
        else:
            raise TimeoutError(f"DNP3 h7 10.0.0.{STATION_ID}:{PORT} not connected")
        logging.info("CONNECTED h1 -> h7:%d", PORT)
        sent = {
            "run_id": args.run_id,
            "station_id": STATION_ID,
            "port": PORT,
            "command_group": 41,
            "command_type": "AnalogOutputFloat32_DirectOperate",
            "index": INDEX,
            "load_multiplier": float(args.load_mult),
            "sent_utc": utcnow(),
        }
        command = opendnp3.AnalogOutputFloat32(float(args.load_mult))
        endpoint.send_direct_operate_command(command, index=INDEX, callback=on_result)
        atomic_json(sent_path, sent)
        logging.info("DNP3_DIRECT_OPERATE_SENT group=41 index=0 value=%.7f", args.load_mult)

        callback_event.wait(timeout=min(5.0, args.observe_timeout))
        deadline = time.monotonic() + args.observe_timeout
        while time.monotonic() < deadline and not outstation_event.is_file():
            time.sleep(0.2)
        sent["callback"] = dict(callback_result)
        sent["outstation_receipt_file_seen"] = outstation_event.is_file()
        atomic_json(args.out_dir / "master_observation.json", sent)
        if not outstation_event.is_file():
            raise TimeoutError("No independent outstation AO receipt recorded")
        logging.info("OUTSTATION_RECEIPT_SEEN %s", outstation_event)
    finally:
        endpoint.shutdown()


if __name__ == "__main__":
    main()
