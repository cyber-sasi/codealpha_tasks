from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone

import pytest
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.packet import Raw

from src.alerts import Alert, AlertManager, Severity
from src.analyzer import PacketMetadata, extract_metadata
from src.database import EventStore
from src.detector import Detector
from src.exporter import export_alerts
from src.main import run
from src.response import ResponseManager
from src.rules import DetectionRule, RuleConfigError, RuleEngine


def metadata(
    *,
    at: datetime,
    source: str = "192.0.2.10",
    destination: str = "192.0.2.20",
    protocol: str = "TCP",
    destination_port: int | None = 443,
    flags: str | None = "S",
) -> PacketMetadata:
    return PacketMetadata(
        timestamp=at,
        source_ip=source,
        destination_ip=destination,
        protocol=protocol,
        packet_length=60,
        source_port=50000 if protocol == "TCP" else None,
        destination_port=destination_port if protocol in {"TCP", "UDP"} else None,
        tcp_flags=flags if protocol == "TCP" else None,
    )


def engine(
    *,
    port_threshold: int = 4,
    flood_threshold: int = 100,
    icmp_threshold: int = 4,
    repeated_threshold: int = 4,
    window: float = 10,
) -> RuleEngine:
    return RuleEngine(
        [
            DetectionRule("PORT_SCAN", "Possible TCP port scan", Severity.MEDIUM, port_threshold, window, True),
            DetectionRule("CONNECTION_FLOOD", "Repeated TCP attempts", Severity.HIGH, flood_threshold, window, True),
            DetectionRule("ICMP_ANOMALY", "Frequent ICMP", Severity.MEDIUM, icmp_threshold, window, True),
            DetectionRule("REPEATED_PATTERN", "Repeated pattern", Severity.LOW, repeated_threshold, window, True),
        ]
    )


def test_metadata_parser_extracts_fields_without_payload() -> None:
    packet = IP(src="192.0.2.1", dst="198.51.100.4") / TCP(sport=4321, dport=8443, flags="S") / Raw(load=b"private-data")
    packet.time = 1_700_000_000

    result = extract_metadata(packet)

    assert result is not None
    assert result.source_ip == "192.0.2.1"
    assert result.destination_ip == "198.51.100.4"
    assert (result.protocol, result.source_port, result.destination_port) == ("TCP", 4321, 8443)
    assert result.tcp_flags == "S"
    assert result.packet_length == len(packet)
    assert result.timestamp == datetime.fromtimestamp(1_700_000_000, timezone.utc)
    assert "private-data" not in repr(result)
    assert "payload" not in result.__dataclass_fields__


def test_metadata_parser_handles_udp_icmp_and_non_ip() -> None:
    udp = extract_metadata(IP(src="192.0.2.2", dst="198.51.100.2") / UDP(sport=53, dport=53000))
    icmp = extract_metadata(IP(src="192.0.2.2", dst="198.51.100.2") / ICMP())
    assert udp is not None and (udp.protocol, udp.source_port, udp.destination_port) == ("UDP", 53, 53000)
    assert icmp is not None and icmp.protocol == "ICMP"
    assert extract_metadata(Raw(load=b"not an IP packet")) is None
    ipv6_icmp = extract_metadata(
        IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest()
    )
    assert ipv6_icmp is not None and ipv6_icmp.protocol == "ICMPv6"


def test_port_scan_triggers_at_distinct_port_threshold() -> None:
    detector = Detector(engine())
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    generated = []
    for port in (21, 22, 23, 80):
        generated.extend(detector.process(metadata(at=base, destination_port=port)))

    assert len(generated) == 1
    assert generated[0].rule_id == "PORT_SCAN"
    assert generated[0].severity == Severity.MEDIUM
    assert "4 distinct destination ports" in generated[0].detection_reason


def test_port_scan_counts_distinct_ports_across_destinations() -> None:
    detector = Detector(engine())
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    alerts = []
    for index, port in enumerate((20, 21, 22, 23)):
        alerts.extend(
            detector.process(
                metadata(
                    at=base + timedelta(seconds=index),
                    destination=f"192.0.2.{20 + index}",
                    destination_port=port,
                )
            )
        )
    assert any(alert.rule_id == "PORT_SCAN" for alert in alerts)


def test_port_scan_requires_syn_and_unique_ports() -> None:
    detector = Detector(engine())
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    for port in (22, 22, 22, 22):
        alerts = detector.process(metadata(at=base, destination_port=port))
        assert not any(alert.rule_id == "PORT_SCAN" for alert in alerts)
    for port in (23, 24, 25):
        detector.process(metadata(at=base, destination_port=port, flags="SA"))
    assert detector.rule_detection_counts.get("PORT_SCAN", 0) == 0


def test_connection_attempt_rule_counts_one_source_destination_pair() -> None:
    detector = Detector(engine(port_threshold=100, flood_threshold=3))
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    alerts = []
    for index in range(3):
        alerts.extend(detector.process(metadata(at=base + timedelta(seconds=index))))
    assert [alert.rule_id for alert in alerts] == ["CONNECTION_FLOOD"]
    assert alerts[0].severity == Severity.HIGH


def test_icmp_threshold_and_time_window() -> None:
    detector = Detector(engine(port_threshold=100, flood_threshold=100, icmp_threshold=3))
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    alerts = []
    for index in range(3):
        alerts.extend(
            detector.process(
                metadata(at=base + timedelta(seconds=index), protocol="ICMP", destination_port=None)
            )
        )
    assert any(alert.rule_id == "ICMP_ANOMALY" for alert in alerts)

    expired = Detector(engine(port_threshold=100, flood_threshold=100, icmp_threshold=3, window=2))
    for second in (0, 3, 6):
        assert not any(
            alert.rule_id == "ICMP_ANOMALY"
            for alert in expired.process(
                metadata(at=base + timedelta(seconds=second), protocol="ICMP", destination_port=None)
            )
        )


def test_repeated_pattern_rule_and_threshold_boundary() -> None:
    detector = Detector(engine(port_threshold=100, flood_threshold=100, repeated_threshold=3))
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    results = [
        detector.process(metadata(at=base + timedelta(seconds=index), protocol="UDP", destination_port=53))
        for index in range(3)
    ]
    assert any(alert.rule_id == "REPEATED_PATTERN" for alert in results[-1])


def test_rule_engine_rejects_bad_thresholds_and_duplicate_ids() -> None:
    with pytest.raises(RuleConfigError, match="positive"):
        RuleEngine([DetectionRule("X", "invalid", Severity.LOW, 0, 2, True)])
    rule = DetectionRule("X", "duplicate", Severity.LOW, 1, 1, True)
    with pytest.raises(RuleConfigError, match="unique"):
        RuleEngine([rule, rule])
    with pytest.raises(RuleConfigError, match="too large"):
        RuleEngine([DetectionRule("LONG", "too long", Severity.LOW, 1, 1e308, True)])


def test_rule_file_rejects_non_boolean_enabled_state(tmp_path) -> None:
    rule_file = tmp_path / "rules.json"
    rule_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "SAMPLE",
                        "description": "Sample rule",
                        "severity": "LOW",
                        "threshold": 1,
                        "window_seconds": 1,
                        "enabled": "false",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(RuleConfigError, match="true or false"):
        RuleEngine.from_file(rule_file)


def test_disabled_rule_does_not_detect() -> None:
    disabled = DetectionRule("PORT_SCAN", "disabled", Severity.MEDIUM, 1, 10, False)
    detector = Detector(RuleEngine([disabled]))
    result = detector.process(metadata(at=datetime(2025, 1, 1, tzinfo=timezone.utc)))
    assert result == []


def test_alert_deduplication_respects_cooldown() -> None:
    rule = DetectionRule("X", "test", Severity.LOW, 1, 1, True)
    manager = AlertManager(cooldown_seconds=5)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    first = manager.create(rule, metadata(at=base), "reason")
    second = manager.create(rule, metadata(at=base + timedelta(seconds=4)), "reason")
    third = manager.create(rule, metadata(at=base + timedelta(seconds=5)), "reason")
    assert first is not None
    assert second is None
    assert third is not None
    assert first.alert_id != third.alert_id


def test_alert_creation_contains_required_fields() -> None:
    detector = Detector(engine(port_threshold=2, flood_threshold=100, repeated_threshold=100))
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    detector.process(metadata(at=base, destination_port=1))
    alert = detector.process(metadata(at=base + timedelta(seconds=1), destination_port=2))[0]
    assert alert.alert_id
    assert alert.rule_id == "PORT_SCAN"
    assert alert.timestamp == base + timedelta(seconds=1)
    assert alert.severity == Severity.MEDIUM
    assert alert.status == "FLAGGED"
    assert alert.source_ip == "192.0.2.10"
    assert alert.destination_ip == "192.0.2.20"
    assert alert.protocol == "TCP"
    assert alert.destination_port == 2
    assert alert.detection_reason


def test_response_flags_sources_and_escalates_repeated_alerts() -> None:
    manager = ResponseManager(flag_seconds=5)
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    alert = Alert(
        "one", "X", base, Severity.MEDIUM, "192.0.2.10", None, "ICMP", None, None,
        "test", "reason",
    )
    first = manager.respond(alert)
    second = manager.respond(alert)
    assert first.status == "FLAGGED" and first.severity == Severity.MEDIUM
    assert second.severity == Severity.HIGH
    assert manager.is_flagged(alert.source_ip, base + timedelta(seconds=4))
    assert not manager.is_flagged(alert.source_ip, base + timedelta(seconds=5))
    with pytest.raises(ValueError, match="too large"):
        ResponseManager(flag_seconds=1e308)


def test_sqlite_alert_storage_filters_and_statistics(tmp_path) -> None:
    database = tmp_path / "events.sqlite3"
    store = EventStore(database)
    detector = Detector(engine(port_threshold=2, flood_threshold=100, repeated_threshold=100))
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    packets = [metadata(at=base, destination_port=1), metadata(at=base + timedelta(seconds=1), destination_port=2)]
    for packet in packets:
        store.record_packet(packet)
        for alert in detector.process(packet):
            store.save_alert(alert)
    assert len(store.list_alerts()) == 1
    assert len(store.list_alerts(severity=Severity.MEDIUM)) == 1
    assert len(store.list_alerts(source_ip="192.0.2.10")) == 1
    assert store.list_alerts(source_ip="198.51.100.1") == []
    stats = store.statistics()
    assert stats["total_packets"] == 2
    assert stats["total_alerts"] == 1
    assert stats["alerts_by_rule"] == {"PORT_SCAN": 1}
    assert stats["protocol_distribution"] == {"TCP": 2}
    store.close()
    assert database.exists()


def test_csv_export_has_metadata_only(tmp_path) -> None:
    destination = tmp_path / "alerts.csv"
    row = {
        "alert_id": "abc",
        "rule_id": "PORT_SCAN",
        "severity": "MEDIUM",
        "source_ip": "192.0.2.10",
        "raw_payload": "must-not-export",
    }
    assert export_alerts([row], destination, "csv") == 1
    with destination.open(encoding="utf-8", newline="") as source:
        exported = list(csv.DictReader(source))
    assert exported[0]["alert_id"] == "abc"
    assert "raw_payload" not in exported[0]
    assert "must-not-export" not in destination.read_text(encoding="utf-8")


def test_json_export_has_metadata_only(tmp_path) -> None:
    destination = tmp_path / "alerts.json"
    row = {"alert_id": "abc", "raw_payload": "must-not-export", "severity": "HIGH"}
    assert export_alerts([row], destination, "json") == 1
    exported = json.loads(destination.read_text(encoding="utf-8"))
    assert exported[0]["alert_id"] == "abc"
    assert "raw_payload" not in exported[0]
    assert "must-not-export" not in destination.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "arguments",
    [
        ["--count", "0", "--interface", "iface"],
        ["--interface", "iface"],
        ["--monitor"],
        ["--show-alerts", "--format", "json"],
        ["--export", "alerts.csv"],
        ["--stats", "--show-alerts"],
        ["--show-alerts", "--source", "not-an-ip"],
        ["--demo", "--cooldown-seconds", "nan"],
    ],
)
def test_cli_rejects_invalid_arguments(arguments) -> None:
    with pytest.raises(SystemExit):
        run(arguments)


def test_cli_demo_persists_synthetic_alert(tmp_path, capsys) -> None:
    database = tmp_path / "demo.sqlite3"
    status = run(["--demo", "--db", str(database)])
    output = capsys.readouterr().out
    assert status == 0
    assert "PORT_SCAN" in output
    assert "192.0.2.10" in output
    with EventStore(database) as store:
        alerts = store.list_alerts()
        assert len(alerts) == 1
        assert alerts[0]["rule_id"] == "PORT_SCAN"
        assert alerts[0]["status"] == "FLAGGED"
        assert store.statistics()["total_packets"] == 7


def test_cli_help_is_available(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        run(["--help"])
    assert raised.value.code == 0
    assert "--list-interfaces" in capsys.readouterr().out
