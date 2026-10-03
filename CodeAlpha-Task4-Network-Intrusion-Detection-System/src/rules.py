"""Configurable deterministic detection rules."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import math
from pathlib import Path
from typing import Any

from src.alerts import Severity
from src.analyzer import PacketMetadata


class RuleConfigError(ValueError):
    """Raised when the detection rule configuration is invalid."""


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """Configuration for one rule."""

    rule_id: str
    description: str
    severity: Severity
    threshold: int
    window_seconds: float
    enabled: bool


class RuleEngine:
    """Evaluate packet metadata against configured time-window rules."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        ids = [rule.rule_id for rule in rules]
        if len(ids) != len(set(ids)):
            raise RuleConfigError("Rule IDs must be unique.")
        try:
            for rule in rules:
                timedelta(seconds=rule.window_seconds)
        except OverflowError as exc:
            raise RuleConfigError("Rule time windows are too large.") from exc
        if any(
            rule.threshold < 1
            or not math.isfinite(rule.window_seconds)
            or rule.window_seconds <= 0
            for rule in rules
        ):
            raise RuleConfigError("Rule thresholds and time windows must be positive.")
        self.rules = {rule.rule_id: rule for rule in rules}
        self._events: dict[str, dict[Any, deque[datetime]]] = defaultdict(
            lambda: defaultdict(deque)
        )
        self._port_events: dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)
        self._packet_count = 0

    @classmethod
    def from_file(cls, path: str | Path) -> RuleEngine:
        """Load and validate rules from a JSON file."""
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or not isinstance(raw.get("rules"), list):
                raise ValueError("configuration must contain a rules list")
            rules = []
            for entry in raw["rules"]:
                if not isinstance(entry, dict):
                    raise ValueError("each rule must be an object")
                threshold = entry["threshold"]
                window_seconds = entry["window_seconds"]
                enabled = entry["enabled"]
                if isinstance(threshold, bool) or not isinstance(threshold, int):
                    raise ValueError("rule thresholds must be integers")
                if isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)):
                    raise ValueError("rule windows must be numbers")
                if not isinstance(enabled, bool):
                    raise ValueError("rule enabled state must be true or false")
                rule_id = entry["id"]
                description = entry["description"]
                severity_text = entry["severity"]
                if not isinstance(rule_id, str) or not rule_id.strip():
                    raise ValueError("rule IDs must be non-empty strings")
                if not isinstance(description, str) or not description.strip():
                    raise ValueError("rule descriptions must be non-empty strings")
                if not isinstance(severity_text, str):
                    raise ValueError("rule severity must be LOW, MEDIUM, or HIGH")
                rules.append(
                    DetectionRule(
                        rule_id=rule_id,
                        description=description,
                        severity=Severity(severity_text.upper()),
                        threshold=threshold,
                        window_seconds=float(window_seconds),
                        enabled=enabled,
                    )
                )
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RuleConfigError(f"Could not load rule configuration: {exc}") from exc
        return cls(rules)

    def evaluate(self, packet: PacketMetadata) -> list[tuple[DetectionRule, str]]:
        """Return each matching enabled rule and a deterministic explanation."""
        self._packet_count += 1
        if self._packet_count % 256 == 0:
            self._prune_idle_state(packet.timestamp)
        matches: list[tuple[DetectionRule, str]] = []
        for rule in self.rules.values():
            if not rule.enabled:
                continue
            key = self._key(rule.rule_id, packet)
            if key is None:
                continue
            cutoff = packet.timestamp - timedelta(seconds=rule.window_seconds)
            if rule.rule_id == "PORT_SCAN":
                port_events = self._port_events[packet.source_ip]
                while port_events and port_events[0][0] < cutoff:
                    port_events.popleft()
                port_events.append((packet.timestamp, packet.destination_port))
                distinct_ports = {port for _, port in port_events}
                if len(distinct_ports) >= rule.threshold:
                    matches.append(
                        (rule, f"{len(distinct_ports)} distinct destination ports from {packet.source_ip} within {rule.window_seconds:g}s (threshold {rule.threshold}).")
                    )
                continue

            events = self._events[rule.rule_id][key]
            while events and events[0] < cutoff:
                events.popleft()
            if self._qualifies(rule.rule_id, packet):
                events.append(packet.timestamp)
            if len(events) >= rule.threshold:
                matches.append(
                    (rule, f"{len(events)} matching packets within {rule.window_seconds:g}s (threshold {rule.threshold}).")
                )
        return matches

    def _prune_idle_state(self, now: datetime) -> None:
        """Discard stale rule state periodically to bound memory during long runs."""
        for rule_id, keyed_events in self._events.items():
            window = self.rules[rule_id].window_seconds
            cutoff = now - timedelta(seconds=window)
            for key, events in list(keyed_events.items()):
                while events and events[0] < cutoff:
                    events.popleft()
                if not events:
                    del keyed_events[key]
        port_rule = self.rules.get("PORT_SCAN")
        if port_rule is not None:
            cutoff = now - timedelta(seconds=port_rule.window_seconds)
            for source_ip, events in list(self._port_events.items()):
                while events and events[0][0] < cutoff:
                    events.popleft()
                if not events:
                    del self._port_events[source_ip]

    def _key(self, rule_id: str, packet: PacketMetadata) -> Any | None:
        if rule_id == "PORT_SCAN":
            if packet.protocol != "TCP" or packet.destination_port is None or not _is_syn(packet.tcp_flags):
                return None
            return packet.source_ip
        if rule_id == "CONNECTION_FLOOD":
            if packet.protocol != "TCP" or packet.destination_port is None or not _is_syn(packet.tcp_flags):
                return None
            return (packet.source_ip, packet.destination_ip)
        if rule_id == "ICMP_ANOMALY":
            if packet.protocol not in {"ICMP", "ICMPv6"}:
                return None
            return packet.source_ip
        if rule_id == "REPEATED_PATTERN":
            return (
                packet.source_ip,
                packet.destination_ip,
                packet.protocol,
                packet.destination_port,
            )
        return None

    def _qualifies(self, rule_id: str, packet: PacketMetadata) -> bool:
        if rule_id in {"PORT_SCAN", "CONNECTION_FLOOD"}:
            return _is_syn(packet.tcp_flags)
        if rule_id == "ICMP_ANOMALY":
            return packet.protocol in {"ICMP", "ICMPv6"}
        return True


def _is_syn(flags: str | None) -> bool:
    """Return True for an initial TCP SYN without the ACK flag."""
    return flags is not None and "S" in flags and "A" not in flags
