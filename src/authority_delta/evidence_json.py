"""Serialize observed AWS evidence without changing canonical approval hashing."""
from datetime import date, datetime, timezone
import json


def aws_json_value(value):
    if isinstance(value, datetime):
        # AWS timestamps are aware. Keep a naive timestamp explicitly without a Z.
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    # Never stringify arbitrary objects (which might include credential material).
    raise TypeError(f"Unsupported evidence type: {type(value).__name__}")


def encode_evidence(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False,
        default=aws_json_value) + "\n").encode("utf-8")


def recover_serializable_report(report):
    """Keep good evidence sections while making unsupported evidence a clear failure."""
    safe = {}
    excluded = []
    for key, value in report.items():
        try:
            encode_evidence({key: value})
        except (TypeError, ValueError, OverflowError, RecursionError):
            excluded.append(key)
        else:
            safe[key] = value
    safe.update(result="FAIL", gate_0="NOT_PASSED", gate_a="NOT_RUN",
        evidence_serialization_error={"excluded_sections": excluded,
            "message": "Unsupported evidence was excluded; retained sections are not a complete verification."})
    return safe
