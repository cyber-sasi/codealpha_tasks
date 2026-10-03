"""SQLite event and monitoring-statistics storage."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any

from src.alerts import Alert, Severity
from src.analyzer import PacketMetadata


class EventStore:
    """Persist security metadata and aggregate packet counts locally."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = str(database_path)
        if self.database_path != ":memory:":
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.database_path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._initialize()

    def _initialize(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH')),
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT,
                    protocol TEXT NOT NULL,
                    source_port INTEGER,
                    destination_port INTEGER,
                    description TEXT NOT NULL,
                    detection_reason TEXT NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_ip);
                CREATE TABLE IF NOT EXISTS packet_stats (
                    protocol TEXT PRIMARY KEY,
                    packet_count INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS monitor_stats (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO monitor_stats(key, value) VALUES ('total_packets', 0);
                """
            )

    def record_packet(self, packet: PacketMetadata) -> None:
        """Persist packet counts and protocol distribution only."""
        with self._lock, self._connection:
            self._connection.execute(
                "UPDATE monitor_stats SET value = value + 1 WHERE key = 'total_packets'"
            )
            self._connection.execute(
                """
                INSERT INTO packet_stats(protocol, packet_count) VALUES (?, 1)
                ON CONFLICT(protocol) DO UPDATE SET packet_count = packet_count + 1
                """,
                (packet.protocol,),
            )

    def save_alert(self, alert: Alert) -> None:
        """Insert one alert using metadata-only columns."""
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, rule_id, timestamp, severity, source_ip, destination_ip,
                    protocol, source_port, destination_port, description,
                    detection_reason, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.alert_id,
                    alert.rule_id,
                    alert.timestamp.isoformat(),
                    alert.severity.value,
                    alert.source_ip,
                    alert.destination_ip,
                    alert.protocol,
                    alert.source_port,
                    alert.destination_port,
                    alert.description,
                    alert.detection_reason,
                    alert.status,
                ),
            )

    def list_alerts(
        self,
        limit: int = 50,
        severity: Severity | None = None,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        """List newest alerts with optional validated metadata filters."""
        if limit < 1:
            raise ValueError("Limit must be at least one.")
        conditions: list[str] = []
        parameters: list[Any] = []
        if severity is not None:
            conditions.append("severity = ?")
            parameters.append(severity.value)
        if source_ip is not None:
            conditions.append("source_ip = ?")
            parameters.append(source_ip)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        with self._lock:
            rows = self._connection.execute(
                f"SELECT * FROM alerts {where} ORDER BY timestamp DESC LIMIT ?",
                (*parameters, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def statistics(self) -> dict[str, Any]:
        """Return packet totals, alert groups, and top source addresses."""
        with self._lock:
            total_row = self._connection.execute(
                "SELECT value FROM monitor_stats WHERE key = 'total_packets'"
            ).fetchone()
            total_alerts = self._connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            by_severity = self._group_counts("severity")
            by_rule = self._group_counts("rule_id")
            by_source = self._connection.execute(
                """
                SELECT source_ip, COUNT(*) AS alert_count FROM alerts
                GROUP BY source_ip ORDER BY alert_count DESC, source_ip LIMIT 10
                """
            ).fetchall()
            protocols = self._connection.execute(
                "SELECT protocol, packet_count FROM packet_stats ORDER BY protocol"
            ).fetchall()
        return {
            "total_packets": int(total_row[0]),
            "total_alerts": int(total_alerts),
            "alerts_by_severity": by_severity,
            "alerts_by_rule": by_rule,
            "top_sources": {row["source_ip"]: row["alert_count"] for row in by_source},
            "protocol_distribution": {row["protocol"]: row["packet_count"] for row in protocols},
        }

    def _group_counts(self, column: str) -> dict[str, int]:
        if column not in {"severity", "rule_id"}:
            raise ValueError("Unsupported statistic column.")
        rows = self._connection.execute(
            f"SELECT {column}, COUNT(*) AS item_count FROM alerts GROUP BY {column}"
        ).fetchall()
        return {str(row[0]): int(row[1]) for row in rows}

    def close(self) -> None:
        """Close the SQLite connection."""
        with self._lock:
            self._connection.close()

    def __enter__(self) -> EventStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
