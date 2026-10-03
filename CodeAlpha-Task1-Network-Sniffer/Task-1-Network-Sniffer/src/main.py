"""Command-line entry point for the passive network sniffer."""

from __future__ import annotations

import argparse
import sys

from .analyzer import PacketRecord, format_packet_details
from .capture import CaptureError, capture_packets, list_interfaces
from .exporter import ExportError, export_records
from .filters import FilterError, parse_filter
from .statistics import calculate_statistics
from .utils import BANNER, format_statistics


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Passively capture and summarize authorized network traffic. Payloads are not saved.",
        epilog="Use only on networks/devices you own or are explicitly authorized to monitor.",
    )
    parser.add_argument("-i", "--interface", help="network interface name (use --list-interfaces to view options)")
    parser.add_argument("-c", "--count", type=int, default=0, help="packet limit; 0 captures until Ctrl+C (default: 0)")
    parser.add_argument("-f", "--filter", dest="filter_expression", help="filter: tcp, udp, icmp, arp, dns, host <IP>, port <PORT>")
    parser.add_argument("--list-interfaces", action="store_true", help="list interfaces Scapy can capture on and exit")
    parser.add_argument("--inspect", type=int, metavar="PACKET_NUMBER", help="inspect one captured packet's safe metadata")
    parser.add_argument("-o", "--export", metavar="FILE", help="export metadata to a .csv or .json file")
    parser.add_argument("--format", choices=("csv", "json"), help="export format (otherwise inferred from file extension)")
    return parser


def _select_interface() -> str:
    interfaces = list_interfaces()
    if not interfaces:
        raise CaptureError("Scapy did not detect any network interfaces")
    print("Available interfaces:")
    for index, name in enumerate(interfaces, start=1):
        print(f"  {index}. {name}")
    while True:
        answer = input("Select interface number: ").strip()
        try:
            selected = int(answer)
            if 1 <= selected <= len(interfaces):
                return interfaces[selected - 1]
        except ValueError:
            pass
        print(f"Enter a number from 1 to {len(interfaces)}.")


def _print_records(records: list[PacketRecord]) -> None:
    print("\nPackets (payloads omitted)")
    print("#    Timestamp (UTC)                 Source                  Destination             Protocol  Length  Flags")
    for record in records:
        source = record.src_ip or "-"
        destination = record.dst_ip or "-"
        if record.src_port is not None:
            source += f":{record.src_port}"
        if record.dst_port is not None:
            destination += f":{record.dst_port}"
        print(
            f"{record.number:<4} {record.timestamp:<30} {source:<23} {destination:<23} "
            f"{record.protocol:<9} {record.length:<7} {record.tcp_flags or '-'}"
        )


def _export(records: list[PacketRecord], filename: str, file_format: str | None) -> None:
    path = export_records(records, filename, file_format)
    print(f"Exported {len(records)} metadata records to {path}")


def _interactive_options(records: list[PacketRecord]) -> None:
    if not sys.stdin.isatty() or not records:
        return
    print("\nOptions: enter a packet number to inspect, 'e' to export, or 'q' to finish.")
    while True:
        choice = input("sniffer> ").strip().lower()
        if choice in {"q", "quit", ""}:
            return
        if choice in {"e", "export"}:
            filename = input("Export filename (.csv or .json): ").strip()
            try:
                _export(records, filename, None)
            except (ExportError, OSError) as error:
                print(f"Export error: {error}")
            continue
        try:
            number = int(choice)
            record = records[number - 1] if 1 <= number <= len(records) else None
        except ValueError:
            record = None
        if record is None:
            print(f"Enter a packet number from 1 to {len(records)}, 'e', or 'q'.")
        else:
            print("\n" + format_packet_details(record))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    print(BANNER)

    try:
        if args.list_interfaces:
            interfaces = list_interfaces()
            if not interfaces:
                print("No interfaces detected.")
            for interface in interfaces:
                print(interface)
            return 0
        if args.count < 0:
            parser.error("--count must be zero or greater")
        bpf_filter = parse_filter(args.filter_expression)
        interface = args.interface or _select_interface()
        print(f"Interface: {interface}")
        print(f"Capture filter: {args.filter_expression or 'none'}")
        print(f"Packet limit: {args.count if args.count else 'unlimited (Ctrl+C to stop)'}")
        print("Starting passive capture. Press Ctrl+C to stop.\n")

        def progress(packet_count: int) -> None:
            print(f"\rCaptured packets: {packet_count}", end="", flush=True)

        result = capture_packets(interface, args.count, bpf_filter, progress)
        if result.records:
            print()
        if result.interrupted:
            print("Capture stopped by user.")
        elif not result.records:
            print("Capture ended without matching packets.")

        _print_records(result.records)
        print(format_statistics(calculate_statistics(result.records)))

        if args.inspect is not None:
            if not 1 <= args.inspect <= len(result.records):
                print(
                    f"Inspection error: packet number must be between 1 and {len(result.records)}.",
                    file=sys.stderr,
                )
                return 2
            print("\n" + format_packet_details(result.records[args.inspect - 1]))
        if args.export:
            _export(result.records, args.export, args.format)
        if args.inspect is None and args.export is None:
            _interactive_options(result.records)
        return 0
    except (CaptureError, FilterError, ExportError, OSError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("\nExiting safely.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())