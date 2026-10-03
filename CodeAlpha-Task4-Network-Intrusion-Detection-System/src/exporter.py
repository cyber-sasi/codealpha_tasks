"""Metadata-only CSV and JSON alert export."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


EXPORT_FIELDS = (
    "alert_id",
    "rule_id",
    "timestamp",
    "severity",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "description",
    "detection_reason",
    "status",
)


def export_alerts(
    alerts: Iterable[dict[str, Any]], destination: str | Path, file_format: str
) -> int:
    """Export alerts to CSV or JSON and return the exported record count."""
    if file_format not in {"csv", "json"}:
        raise ValueError("Export format must be 'csv' or 'json'.")
    records = [
        {field: _json_value(alert.get(field)) for field in EXPORT_FIELDS}
        for alert in alerts
    ]
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    if file_format == "json":
        target.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        with target.open("w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=EXPORT_FIELDS)
            writer.writeheader()
            writer.writerows(records)
    return len(records)


def _json_value(value: Any) -> Any:
    return value.isoformat() if isinstance(value, datetime) else value
