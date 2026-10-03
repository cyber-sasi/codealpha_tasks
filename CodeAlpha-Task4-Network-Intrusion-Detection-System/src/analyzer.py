"""Packet metadata extraction; packet contents are never returned or stored."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6Unknown, IPv6

from src.utils import timestamp_from_epoch, utc_now


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    """Security-relevant packet metadata with no payload field."""

    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    packet_length: int
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str | None = None


def extract_metadata(packet: Any) -> PacketMetadata | None:
    """Extract network and transport metadata from a Scapy packet."""
    ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip_layer is None:
        return None

    source_ip = str(ip_layer.src)
    destination_ip = str(ip_layer.dst)
    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP)
    icmp = packet.getlayer(ICMP)
    icmpv6 = packet.getlayer(ICMPv6Unknown)

    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: str | None = None
    if tcp is not None:
        protocol = "TCP"
        source_port = int(tcp.sport)
        destination_port = int(tcp.dport)
        tcp_flags = str(tcp.flags)
    elif udp is not None:
        protocol = "UDP"
        source_port = int(udp.sport)
        destination_port = int(udp.dport)
    elif icmp is not None:
        protocol = "ICMP"
    elif icmpv6 is not None or _has_icmpv6_layer(packet):
        protocol = "ICMPv6"
    else:
        protocol = "OTHER"

    packet_time = getattr(packet, "time", None)
    timestamp = timestamp_from_epoch(float(packet_time)) if packet_time is not None else utc_now()
    return PacketMetadata(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        packet_length=len(packet),
        source_port=source_port,
        destination_port=destination_port,
        tcp_flags=tcp_flags,
    )


def _has_icmpv6_layer(packet: Any) -> bool:
    """Recognize Scapy's ICMPv6 message subclasses, including echo requests."""
    return any(layer.__name__.startswith("ICMPv6") for layer in packet.layers())
