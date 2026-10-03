"""Small presentation helpers for the command-line interface."""

from __future__ import annotations

from .statistics import CaptureStatistics


BANNER = """
============================================================
                 BASIC NETWORK SNIFFER
============================================================
AUTHORIZED USE ONLY: capture traffic only on networks and
 devices you own or have explicit permission to monitor.
Metadata only; packet payloads are not retained or displayed.
""".strip()


def format_statistics(stats: CaptureStatistics) -> str:
    """Render a compact human-readable capture summary."""
    lines = [
        "\nCapture summary",
        "---------------",
        f"Total packets: {stats.total}",
        f"TCP: {stats.tcp}  UDP: {stats.udp}  ICMP: {stats.icmp}  ARP: {stats.arp}",
        f"DNS: {stats.dns}  Other: {stats.other}",
    ]
    for title, values in (
        ("Top source IPs", stats.top_sources),
        ("Top destination IPs", stats.top_destinations),
        ("Top protocols", stats.top_protocols),
    ):
        lines.append(
            f"{title}: "
            + (", ".join(f"{value} ({count})" for value, count in values) or "none")
        )
    return "\n".join(lines)