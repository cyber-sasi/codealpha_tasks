"""Alert models and duplicate suppression."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import math
from typing import TYPE_CHECKING
from uuid import uuid4

from src.analyzer import PacketMetadata

if TYPE_CHECKING:
    from src.rules import DetectionRule


class Severity(str, Enum):
    """Supported alert severity values."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True, slots=True)
class Alert:
    """Alert record containing metadata only."""

    alert_id: str
    rule_id: str
    timestamp: datetime
    severity: Severity
    source_ip: str
    destination_ip: str | None
    protocol: str
    source_port: int | None
    destination_port: int | None
    description: str
    detection_reason: str
    status: str = "OPEN"


class AlertManager:
    """Create alerts while suppressing repeated alerts during a cooldown."""

    def __init__(self, cooldown_seconds: float = 60.0) -> None:
        if not math.isfinite(cooldown_seconds) or cooldown_seconds < 0:
            raise ValueError("Cooldown must be zero or greater.")
        try:
            self.cooldown = timedelta(seconds=cooldown_seconds)
        except OverflowError as exc:
            raise ValueError("Cooldown is too large.") from exc
        self._last_alert: dict[tuple[str, str, str | None], datetime] = {}
        self._created_count = 0

    def create(
        self,
        rule: DetectionRule,
        packet: PacketMetadata,
        reason: str,
    ) -> Alert | None:
        """Create an alert, or return None while its deduplication key cools down."""
        self._created_count += 1
        if self._created_count % 256 == 0:
            cutoff = packet.timestamp - self.cooldown
            self._last_alert = {
                key: timestamp
                for key, timestamp in self._last_alert.items()
                if timestamp >= cutoff
            }
        key = (rule.rule_id, packet.source_ip, packet.destination_ip)
        last_seen = self._last_alert.get(key)
        if last_seen is not None and packet.timestamp - last_seen < self.cooldown:
            return None
        self._last_alert[key] = packet.timestamp
        return Alert(
            alert_id=str(uuid4()),
            rule_id=rule.rule_id,
            timestamp=packet.timestamp,
            severity=rule.severity,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            protocol=packet.protocol,
            source_port=packet.source_port,
            destination_port=packet.destination_port,
            description=rule.description,
            detection_reason=reason,
        )
