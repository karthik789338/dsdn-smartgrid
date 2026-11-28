"""Contracts for the isolated E1b.3 DNP3-to-OpenDSS control pilot.

The master never writes a plant command file. Only the outstation process
may publish a command after observing its DNP3 analog-output-status value.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "gridcad_e1b3_control_v1"
STATION_ID = 7
PORT = 21007
INDEX = 0
LOAD_MULT_MIN = 1.005
LOAD_MULT_MAX = 1.030
VOLTAGE_MIN = 0.95
VOLTAGE_MAX = 1.05


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_run_id(run_id: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{5,63}", run_id):
        raise ValueError("run-id must be 6-64 characters: letters, numbers, _ or -")
    return run_id


def atomic_json(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(record, stream, allow_nan=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def numeric(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return None
    result = float(value)
    return result if math.isfinite(result) else None


def validate_load_mult(value: object) -> float:
    number = numeric(value)
    if number is None or not LOAD_MULT_MIN <= number <= LOAD_MULT_MAX:
        raise ValueError(
            f"load multiplier must be finite and within [{LOAD_MULT_MIN}, {LOAD_MULT_MAX}]"
        )
    return number


def _index_zero(container: object) -> float | None:
    if not isinstance(container, Mapping):
        return None
    value = container.get(INDEX, container.get(str(INDEX)))
    if isinstance(value, Mapping):
        value = value.get("value", value.get("Value"))
    return numeric(value)


def analog_output_status(db: object, *, group_only: bool = False) -> float | None:
    """Get AO status index zero; never confuse it with an analog INPUT.

    When a public group-40 getter was used, group_only=True allows a map
    of indices directly. A full DB requires an explicit output-status key.
    """
    if not isinstance(db, Mapping):
        return None
    if group_only:
        direct = _index_zero(db)
        if direct is not None:
            return direct
    for key, value in db.items():
        normalized = str(key).lower().replace("_", "")
        if "analogoutputstatus" in normalized or "group40" in normalized:
            found = _index_zero(value)
            if found is not None:
                return found
    return None


def read_outstation_status(outstation: object) -> tuple[bool, float | None, str]:
    """Read the local outstation's actual AO status, if the API exposes it.

    Returns (supported, current_value, source). A valid unset value is None.
    Explicitly fail closed on an unsupported API, never synthesize receipt.
    """
    unset_but_supported = None
    for method_name in ("get_db_by_group_variation",):
        method = getattr(outstation, method_name, None)
        if callable(method):
            for group, variation in ((40, 4), (40, 2), (40, 1)):
                try:
                    database = method(group=group, variation=variation)
                    value = analog_output_status(database, group_only=True)
                    if value is not None:
                        return True, value, f"{method_name}({group},{variation})"
                    unset_but_supported = (True, None, f"{method_name}({group},{variation})")
                except (KeyError, TypeError, ValueError, AttributeError):
                    continue
    for method_name in ("get_db_by_group_variation_index", "get_val_by_group_variation_index"):
        method = getattr(outstation, method_name, None)
        if callable(method):
            for variation in (4, 2, 1):
                try:
                    point = method(group=40, variation=variation, index=INDEX)
                except (KeyError, TypeError, ValueError, AttributeError):
                    continue
                value = numeric(point)
                if value is None and isinstance(point, Mapping):
                    value = analog_output_status(point, group_only=True)
                if value is not None:
                    return True, value, f"{method_name}(40,{variation},0)"
                unset_but_supported = (True, None, f"{method_name}(40,{variation},0)")
    method = getattr(outstation, "get_db", None)
    if callable(method):
        try:
            database = method()
        except (TypeError, AttributeError):
            pass
        else:
            if isinstance(database, Mapping):
                value = analog_output_status(database)
                if value is not None:
                    return True, value, "get_db()"
                unset_but_supported = (True, None, "get_db()")
            if isinstance(getattr(database, "db", None), Mapping):
                value = analog_output_status(database.db)
                if value is not None:
                    return True, value, "get_db().db"
                unset_but_supported = (True, None, "get_db().db")
    for attribute in ("db_handler", "db", "database", "db_storage"):
        obj = getattr(outstation, attribute, None)
        candidates = (obj, getattr(obj, "db", None), getattr(obj, "db_storage", None))
        for candidate in candidates:
            if isinstance(candidate, Mapping):
                value = analog_output_status(candidate)
                if value is not None:
                    return True, value, attribute
                unset_but_supported = (True, None, attribute)
    return unset_but_supported or (False, None, "No readable outstation group-40/status database exposed")


def command_record(run_id: str, observed: float, baseline: float | None) -> dict:
    validate_run_id(run_id)
    value = validate_load_mult(observed)
    return {
        "schema": SCHEMA,
        "run_id": run_id,
        "origin": "outstation_local_dnp3_analog_output_status_change",
        "station_id": STATION_ID,
        "port": PORT,
        "group": 40,
        "index": INDEX,
        "load_multiplier": value,
        "previous_output_status": baseline,
        "received_utc": utcnow(),
    }


def validate_command(record: object, run_id: str, *, max_age_seconds: float = 15) -> float:
    if not isinstance(record, dict):
        raise ValueError("Command must be a JSON object")
    expected = {
        "schema": SCHEMA,
        "run_id": validate_run_id(run_id),
        "origin": "outstation_local_dnp3_analog_output_status_change",
        "station_id": STATION_ID,
        "port": PORT,
        "group": 40,
        "index": INDEX,
    }
    if any(record.get(field) != value for field, value in expected.items()):
        raise ValueError("Command envelope identity or point mapping differs")
    timestamp = datetime.fromisoformat(record["received_utc"])
    if timestamp.tzinfo is None:
        raise ValueError("Command timestamp must be timezone-aware")
    age = (datetime.now(timezone.utc) - timestamp).total_seconds()
    if not 0 <= age <= max_age_seconds:
        raise ValueError(f"Stale or future command: age={age:.2f}s")
    return validate_load_mult(record.get("load_multiplier"))
