"""Offline tests for analysis, filters, statistics, and metadata exports."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from src.analyzer import analyze_packet
from src.exporter import ExportError, export_records
from src.filters import FilterError, parse_filter
from src.statistics import calculate_statistics


class AnalyzerTests(unittest.TestCase):
    def test_protocol_identification_and_metadata(self) -> None:
        packet = Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=43210, dport=443, flags="S")
        packet.time = 1_700_000_000
        record = analyze_packet(packet, 7)

        self.assertEqual(record.number, 7)
        self.assertEqual(record.protocol, "TCP")
        self.assertEqual((record.src_ip, record.dst_ip), ("192.0.2.10", "198.51.100.20"))
        self.assertEqual((record.src_port, record.dst_port), (43210, 443))
        self.assertEqual(record.tcp_flags, "S")
        self.assertEqual(record.length, len(packet))
        self.assertIn("Ether", record.layers)
        self.assertIn("TCP", record.layers)
        self.assertNotIn("payload", record.to_dict())

    def test_dns_http_icmp_and_arp_protocols(self) -> None:
        dns_packet = (
            Ether() / IP(src="192.0.2.1", dst="192.0.2.53") / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.test"))
        )
        http_packet = Ether() / IP(src="192.0.2.1", dst="198.51.100.1") / TCP(sport=50000, dport=80)
        icmp_packet = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / ICMP()
        arp_packet = Ether() / ARP(psrc="192.0.2.1", pdst="192.0.2.2")

        self.assertEqual(analyze_packet(dns_packet, 1).protocol, "DNS")
        self.assertEqual(analyze_packet(http_packet, 2).protocol, "HTTP")
        self.assertEqual(analyze_packet(icmp_packet, 3).protocol, "ICMP")
        self.assertEqual(analyze_packet(arp_packet, 4).protocol, "ARP")

    def test_supported_filters_are_translated(self) -> None:
        self.assertEqual(parse_filter(" TCP "), "tcp")
        self.assertEqual(parse_filter("dns"), "udp port 53 or tcp port 53")
        self.assertEqual(parse_filter("host 2001:db8::1"), "host 2001:db8::1")
        self.assertEqual(parse_filter("port 443"), "port 443")
        self.assertIsNone(parse_filter(None))

    def test_filter_rejects_arbitrary_expressions_and_invalid_values(self) -> None:
        for expression in ("tcp or port 22", "host not-an-ip", "port 65536", "port -1"):
            with self.subTest(expression=expression), self.assertRaises(FilterError):
                parse_filter(expression)

    def test_statistics_count_protocols_and_endpoints(self) -> None:
        packets = [
            Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=1000, dport=443),
            Ether() / IP(src="192.0.2.1", dst="192.0.2.53") / UDP(sport=5000, dport=53) / DNS(),
            Ether() / IP(src="192.0.2.3", dst="192.0.2.2") / ICMP(),
            Ether() / ARP(psrc="192.0.2.1", pdst="192.0.2.2"),
        ]
        records = [analyze_packet(packet, index) for index, packet in enumerate(packets, 1)]
        stats = calculate_statistics(records, packets)

        self.assertEqual(
            (stats.total, stats.tcp, stats.udp, stats.icmp, stats.arp, stats.dns, stats.other),
            (4, 1, 1, 1, 1, 1, 0),
        )
        self.assertEqual(stats.top_sources[0], ("192.0.2.1", 2))
        self.assertEqual(stats.top_destinations[0], ("192.0.2.2", 2))
        self.assertEqual(stats.top_protocols[0][1], 1)

    def test_csv_export_contains_only_metadata(self) -> None:
        record = analyze_packet(Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(dport=443), 1)
        with tempfile.TemporaryDirectory() as directory:
            destination = export_records([record], Path(directory) / "capture.csv")
            with destination.open(encoding="utf-8", newline="") as source:
                rows = list(csv.DictReader(source))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["protocol"], "TCP")
        self.assertIn("Ether > IP > TCP", rows[0]["layers"])
        self.assertNotIn("payload", rows[0])

    def test_json_export_contains_only_metadata(self) -> None:
        record = analyze_packet(Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(dport=53) / DNS(), 1)
        with tempfile.TemporaryDirectory() as directory:
            destination = export_records([record], Path(directory) / "capture.json")
            data = json.loads(destination.read_text(encoding="utf-8"))

        self.assertEqual(data[0]["protocol"], "DNS")
        self.assertIsInstance(data[0]["layers"], list)
        self.assertNotIn("payload", data[0])

    def test_export_rejects_unsupported_format(self) -> None:
        with self.assertRaises(ExportError):
            export_records([], "capture.txt")


if __name__ == "__main__":
    unittest.main()