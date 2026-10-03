"""Coordinate rule evaluation, alert deduplication, and logical response."""

from __future__ import annotations

from src.alerts import Alert, AlertManager
from src.analyzer import PacketMetadata
from src.response import ResponseManager
from src.rules import RuleEngine


class Detector:
    """Apply deterministic rules and return newly generated alerts."""

    def __init__(
        self,
        rule_engine: RuleEngine,
        alert_manager: AlertManager | None = None,
        response_manager: ResponseManager | None = None,
    ) -> None:
        self.rule_engine = rule_engine
        self.alert_manager = alert_manager or AlertManager()
        self.response_manager = response_manager or ResponseManager()
        self.total_packets = 0
        self.protocol_counts: dict[str, int] = {}
        self.rule_detection_counts: dict[str, int] = {}

    def process(self, packet: PacketMetadata) -> list[Alert]:
        """Evaluate one metadata record and return non-duplicate alerts."""
        self.total_packets += 1
        self.protocol_counts[packet.protocol] = self.protocol_counts.get(packet.protocol, 0) + 1
        alerts: list[Alert] = []
        for rule, reason in self.rule_engine.evaluate(packet):
            alert = self.alert_manager.create(rule, packet, reason)
            if alert is None:
                continue
            alert = self.response_manager.respond(alert)
            self.rule_detection_counts[rule.rule_id] = (
                self.rule_detection_counts.get(rule.rule_id, 0) + 1
            )
            alerts.append(alert)
        return alerts
