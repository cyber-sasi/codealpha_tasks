"""Command-line entry point for the metadata-only local NIDS."""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
import sys
from datetime import timedelta
from pathlib import Path
from typing import Sequence

from src.alerts import Alert, AlertManager, Severity
from src.analyzer import PacketMetadata, extract_metadata
from src.capture import CaptureError, capture_packets, list_interfaces
from src.database import EventStore
from src.detector import Detector
from src.exporter import export_alerts
from src.response import ResponseManager
from src.rules import RuleConfigError, RuleEngine
from src.utils import parse_ip, utc_now

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def build_parser() -> argparse.ArgumentParser:
    """Create the NIDS CLI parser."""
    parser = argparse.ArgumentParser(
        prog="nids",
        description=(
            "Metadata-only local network intrusion detection for authorized monitoring. "
            "Capture requires permission; no firewall or network settings are changed."
        ),
    )
    parser.add_argument("--list-interfaces", action="store_true", help="List interfaces visible to Scapy.")
    parser.add_argument("--interface", help="Interface to monitor (select from --list-interfaces).")
    capture_mode = parser.add_mutually_exclusive_group()
    capture_mode.add_argument("--count", type=_positive_int, help="Capture this many packets then stop.")
    capture_mode.add_argument("--monitor", action="store_true", help="Monitor continuously until Ctrl+C.")
    parser.add_argument("--show-alerts", action="store_true", help="List recent stored alerts.")
    parser.add_argument("--severity", type=_severity, help="Filter --show-alerts by severity.")
    parser.add_argument("--source", help="Filter --show-alerts by source IP address.")
    parser.add_argument("--limit", type=_positive_int, default=50, help="Maximum alerts to display (default: 50).")
    parser.add_argument("--stats", action="store_true", help="Show persisted packet and alert statistics.")
    parser.add_argument("--export", metavar="PATH", help="Export alerts to PATH.")
    parser.add_argument("--format", choices=("csv", "json"), help="Export format (required with --export).")
    parser.add_argument("--rules", action="store_true", help="Show loaded detection rules.")
    parser.add_argument("--rules-file", default=str(PROJECT_ROOT / "rules" / "rules.json"), help="Rule JSON file.")
    parser.add_argument("--demo", action="store_true", help="Run a safe synthetic-metadata demonstration.")
    parser.add_argument("--db", default="nids_events.sqlite3", help="SQLite event database path.")
    parser.add_argument("--cooldown-seconds", type=_nonnegative_float, default=60.0, help="Duplicate alert cooldown (default: 60).")
    parser.add_argument("--flag-seconds", type=_positive_float, default=300.0, help="Logical source flag duration (default: 300).")
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validate combinations and values that argparse cannot express."""
    action_flags = [
        args.list_interfaces,
        args.show_alerts,
        args.stats,
        args.export is not None,
        args.rules,
        args.demo,
        args.interface is not None,
    ]
    if sum(action_flags) != 1:
        raise ValueError("Choose exactly one action: capture, --demo, --list-interfaces, --show-alerts, --stats, --export, or --rules.")
    if args.interface is None and args.count is not None:
        raise ValueError("--count requires --interface.")
    if args.interface is None and args.monitor:
        raise ValueError("--monitor requires --interface.")
    if args.interface is not None and args.count is None and not args.monitor:
        raise ValueError("--interface requires either --count or --monitor.")
    if args.export is not None and args.format is None:
        raise ValueError("--export requires --format csv or json.")
    if args.export is None and args.format is not None:
        raise ValueError("--format can only be used with --export.")
    if not args.show_alerts and (args.severity is not None or args.source is not None):
        raise ValueError("--severity and --source can only be used with --show-alerts.")
    if args.source is not None:
        args.source = parse_ip(args.source)


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive number") from exc
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a positive number")
    return number


def _nonnegative_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be zero or greater") from exc
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def _severity(value: str) -> Severity:
    try:
        return Severity(value.upper())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be LOW, MEDIUM, or HIGH") from exc


def _load_engine(rules_file: str) -> RuleEngine:
    return RuleEngine.from_file(rules_file)


def _make_detector(engine: RuleEngine, args: argparse.Namespace) -> Detector:
    return Detector(
        engine,
        alert_manager=AlertManager(cooldown_seconds=args.cooldown_seconds),
        response_manager=ResponseManager(flag_seconds=args.flag_seconds),
    )


def _print_alert(alert: Alert) -> None:
    print(
        f"[{alert.severity.value}] {alert.rule_id} from {alert.source_ip}: "
        f"{alert.description} {alert.detection_reason} "
        f"(response={alert.status}, id={alert.alert_id})"
    )


def _handle_packet(packet: object, detector: Detector, store: EventStore) -> None:
    metadata = extract_metadata(packet)
    if metadata is None:
        return
    store.record_packet(metadata)
    for alert in detector.process(metadata):
        store.save_alert(alert)
        _print_alert(alert)


def _run_demo(detector: Detector, store: EventStore) -> int:
    """Feed synthetic metadata only; no packets are transmitted or captured."""
    source = "192.0.2.10"
    destination = "192.0.2.20"
    base = utc_now()
    alerts: list[Alert] = []
    for index, port in enumerate((21, 22, 23, 25, 53, 80, 443)):
        packet = PacketMetadata(
            timestamp=base + timedelta(milliseconds=index * 100),
            source_ip=source,
            destination_ip=destination,
            protocol="TCP",
            packet_length=60,
            source_port=49152 + index,
            destination_port=port,
            tcp_flags="S",
        )
        store.record_packet(packet)
        for alert in detector.process(packet):
            store.save_alert(alert)
            alerts.append(alert)
            _print_alert(alert)
    if not alerts:
        print("Demo completed: no alert crossed the configured thresholds.")
        return 1
    print(
        f"Demo complete: {len(alerts)} alert(s) stored in {store.database_path}; "
        f"source temporarily flagged in memory: {source}."
    )
    return 0


def run(argv: Sequence[str] | None = None) -> int:
    """Run one CLI operation and return its process status."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        validate_args(args)
    except ValueError as exc:
        parser.error(str(exc))

    try:
        if args.list_interfaces:
            interfaces = list_interfaces()
            if not interfaces:
                print("No network interfaces are available to Scapy.")
            else:
                print("\n".join(interfaces))
            return 0

        engine = _load_engine(args.rules_file) if args.rules or args.demo or args.interface else None
        if args.rules:
            assert engine is not None
            print(json.dumps([
                {
                    "id": rule.rule_id,
                    "description": rule.description,
                    "severity": rule.severity.value,
                    "threshold": rule.threshold,
                    "window_seconds": rule.window_seconds,
                    "enabled": rule.enabled,
                }
                for rule in engine.rules.values()
            ], indent=2))
            return 0

        with EventStore(args.db) as store:
            if args.demo:
                assert engine is not None
                return _run_demo(_make_detector(engine, args), store)
            if args.show_alerts:
                rows = store.list_alerts(args.limit, args.severity, args.source)
                print(json.dumps(rows, indent=2))
                return 0
            if args.stats:
                print(json.dumps(store.statistics(), indent=2))
                return 0
            if args.export is not None:
                rows = store.list_alerts(limit=2_147_483_647)
                exported = export_alerts(rows, args.export, args.format)
                print(f"Exported {exported} alert(s) to {args.export}.")
                return 0

            interfaces = list_interfaces()
            if args.interface not in interfaces:
                raise CaptureError(
                    f"Interface {args.interface!r} is unavailable. Choose a name from --list-interfaces."
                )
            assert engine is not None
            detector = _make_detector(engine, args)
            try:
                capture_packets(
                    args.interface,
                    lambda packet: _handle_packet(packet, detector, store),
                    count=args.count,
                    monitor=args.monitor,
                )
            except KeyboardInterrupt:
                print("\nMonitoring stopped by user.")
            print(f"Packets monitored: {detector.total_packets}")
            return 0
    except (CaptureError, RuleConfigError, OSError, sqlite3.Error, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
