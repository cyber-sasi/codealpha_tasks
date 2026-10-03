"""Export packet metadata without payloads."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .analyzer import PacketRecord


class ExportError(ValueError):
    """Raised for unsupported export formats or file-writing failures."""


_FIELDS = [
    "number", "timestamp", "src_ip", "dst_ip", "protocol", "src_port",
    "dst_port", "length", "tcp_flags", "layers",
]


def export_records(
    records: Iterable[PacketRecord], destination: str | Path, file_format: str | None = None
) -> Path:
    """Write records as CSV or JSON and return the output path."""
    path = Path(destination)
    selected_format = (file_format or path.suffix.lstrip(".")).lower()
    if selected_format not in {"csv", "json"}:
        raise ExportError("export format must be csv or json")

    rows = [record.to_dict() for record in records]
    try:
        if selected_format == "json":
            with path.open("w", encoding="utf-8") as output:
                json.dump(rows, output, indent=2)
                output.write("\n")
        else:
            with path.open("w", encoding="utf-8", newline="") as output:
                writer = csv.DictWriter(output, fieldnames=_FIELDS)
                writer.writeheader()
                for row in rows:
                    row["layers"] = " > ".join(row["layers"])
                    writer.writerow(row)
    except OSError as error:
        raise ExportError(f"could not write {path}: {error}") from error
    return path