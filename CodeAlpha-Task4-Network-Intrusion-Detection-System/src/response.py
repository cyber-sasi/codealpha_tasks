"""Safe logical response actions; no external network configuration is changed."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
import math

from src.alerts import Alert, Severity


class ResponseManager:
    """Temporarily flag sources in memory and escalate repeated alerts."""

    _ESCALATION = {
        Severity.LOW: Severity.MEDIUM,
        Severity.MEDIUM: Severity.HIGH,
        Severity.HIGH: Severity.HIGH,
    }

    def __init__(self, flag_seconds: float = 300.0) -> None:
        if not math.isfinite(flag_seconds) or flag_seconds <= 0:
            raise ValueError("Flag duration must be greater than zero.")
        try:
            self.flag_duration = timedelta(seconds=flag_seconds)
        except OverflowError as exc:
            raise ValueError("Flag duration is too large.") from exc
        self._flagged_until: dict[str, datetime] = {}
        self._alert_counts: dict[str, int] = {}
        self._response_count = 0

    def respond(self, alert: Alert) -> Alert:
        """Mark a source as flagged and escalate severity on repeated detections."""
        self._response_count += 1
        if self._response_count % 256 == 0:
            self._expire_flags(alert.timestamp)
        if not self.is_flagged(alert.source_ip, alert.timestamp):
            self._alert_counts.pop(alert.source_ip, None)
        count = self._alert_counts.get(alert.source_ip, 0) + 1
        self._alert_counts[alert.source_ip] = count
        self._flagged_until[alert.source_ip] = alert.timestamp + self.flag_duration
        severity = alert.severity
        if count > 1:
            severity = self._ESCALATION[severity]
        return replace(alert, severity=severity, status="FLAGGED")

    def is_flagged(self, source_ip: str, now: datetime) -> bool:
        """Return whether a source is still on the logical temporary blocklist."""
        until = self._flagged_until.get(source_ip)
        if until is None:
            return False
        if now >= until:
            del self._flagged_until[source_ip]
            return False
        return True

    def flagged_sources(self, now: datetime) -> dict[str, datetime]:
        """Return active source flags, removing expired entries."""
        self._expire_flags(now)
        return dict(self._flagged_until)

    def _expire_flags(self, now: datetime) -> None:
        for source_ip in list(self._flagged_until):
            if not self.is_flagged(source_ip, now):
                self._alert_counts.pop(source_ip, None)
