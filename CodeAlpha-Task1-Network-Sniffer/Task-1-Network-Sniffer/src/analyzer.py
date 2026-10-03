"""Extract privacy-conscious metadata from Scapy packets."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, ICMPv6Unknown
from scapy.layers.l2 import ARP
from scapy.packet import Packet


@dataclass(frozen=True)
class PacketRecord:
    """Metadata retained for one packet; application payload is never stored."""

    number: int
    timestamp: str
    src_ip: str | None
    dst_ip: str | None
    protocol: str
    src_port: int | None
    dst_port: int | None
    length: int
    tcp_flags: str | None
    layers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation of the metadata."""
        record = asdict(self)
        record["layers"] = list(self.layers)
        return record


def _layer_names(packet: Packet) -> tuple[str, ...]:
    return tuple(layer.__name__ for layer in packet.layers())


def analyze_packet(packet: Packet, number: int) -> PacketRecord:
    """Identify common protocols and extract headers without reading payloads."""
    layers = _layer_names(packet)
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    elif packet.haslayer(ARP):
        src_ip = packet[ARP].psrc or None
        dst_ip = packet[ARP].pdst or None

    if packet.haslayer(TCP):
        transport = packet[TCP]
        src_port, dst_port = int(transport.sport), int(transport.dport)
        tcp_flags = str(transport.flags)
    elif packet.haslayer(UDP):
        transport = packet[UDP]
        src_port, dst_port = int(transport.sport), int(transport.dport)

    if packet.haslayer(ARP):
        protocol = "ARP"
    elif packet.haslayer("DNS"):
        protocol = "DNS"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
    elif packet.haslayer(ICMPv6Unknown) or any(name.startswith("ICMPv6") for name in layers):
        protocol = "ICMPv6"
    elif packet.haslayer(TCP) and (
        {src_port, dst_port} & {80, 8080}
        or any(name in {"HTTPRequest", "HTTPResponse"} for name in layers)
    ):
        protocol = "HTTP"
    elif packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"
    else:
        protocol = "OTHER"

    packet_timestamp = float(packet.time)
    timestamp = datetime.fromtimestamp(packet_timestamp, timezone.utc).isoformat(timespec="milliseconds")

    return PacketRecord(
        number=number,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        length=len(packet),
        tcp_flags=tcp_flags,
        layers=layers,
    )


def format_packet_details(record: PacketRecord) -> str:
    """Format safe packet metadata for the interactive inspection view."""
    source = record.src_ip or "-"
    destination = record.dst_ip or "-"
    if record.src_port is not None:
        source = f"{source}:{record.src_port}"
    if record.dst_port is not None:
        destination = f"{destination}:{record.dst_port}"
    return "\n".join(
        (
            f"Packet: {record.number}",
            f"Timestamp (UTC): {record.timestamp}",
            f"Source: {source}",
            f"Destination: {destination}",
            f"Protocol: {record.protocol}",
            f"Length: {record.length} bytes",
            f"TCP flags: {record.tcp_flags or '-'}",
            f"Layers: {' > '.join(record.layers)}",
            "Payload: not retained or displayed",
        )
    )