"""Capture summary calculations."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.inet6 import ICMPv6Unknown
from scapy.layers.l2 import ARP
from scapy.packet import Packet

from .analyzer import PacketRecord


@dataclass(frozen=True)
class CaptureStatistics:
    total: int
    tcp: int
    udp: int
    icmp: int
    arp: int
    dns: int
    other: int
    top_sources: tuple[tuple[str, int], ...]
    top_destinations: tuple[tuple[str, int], ...]
    top_protocols: tuple[tuple[str, int], ...]


def calculate_statistics(
    records: list[PacketRecord], packets: list[Packet] | None = None, top_n: int = 5
) -> CaptureStatistics:
    """Calculate counts and most common endpoints from captured records.

    Transport counts use original Scapy layers when supplied, so DNS-over-UDP
    is counted as both DNS and UDP and HTTP-over-TCP as both HTTP and TCP.
    """
    tcp_count = udp_count = icmp_count = arp_count = 0
    dns_count = other_count = 0

    for index, record in enumerate(records):
        packet = packets[index] if packets is not None and index < len(packets) else None
        layer_names = set(record.layers)
        if packet is not None:
            tcp_count += int(packet.haslayer(TCP))
            udp_count += int(packet.haslayer(UDP))
            icmp_count += int(packet.haslayer(ICMP) or packet.haslayer(ICMPv6Unknown))
            arp_count += int(packet.haslayer(ARP))
        else:
            tcp_count += int("TCP" in layer_names)
            udp_count += int("UDP" in layer_names)
            icmp_count += int(
                "ICMP" in layer_names or any(name.startswith("ICMPv6") for name in layer_names)
            )
            arp_count += int("ARP" in layer_names)

        dns_count += int(record.protocol == "DNS")
        if not (
            "TCP" in layer_names
            or "UDP" in layer_names
            or "ICMP" in layer_names
            or any(name.startswith("ICMPv6") for name in layer_names)
            or "ARP" in layer_names
        ):
            other_count += 1

    ip_records = [record for record in records if "IP" in record.layers or "IPv6" in record.layers]
    source_counts = Counter(record.src_ip for record in ip_records if record.src_ip)
    destination_counts = Counter(record.dst_ip for record in ip_records if record.dst_ip)
    protocol_counts = Counter(record.protocol for record in records)

    return CaptureStatistics(
        total=len(records),
        tcp=tcp_count,
        udp=udp_count,
        icmp=icmp_count,
        arp=arp_count,
        dns=dns_count,
        other=other_count,
        top_sources=tuple(source_counts.most_common(top_n)),
        top_destinations=tuple(destination_counts.most_common(top_n)),
        top_protocols=tuple(protocol_counts.most_common(top_n)),
    )