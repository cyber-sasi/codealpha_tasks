"""Shared validation and timestamp helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address


def utc_now() -> datetime:
    """Return the current UTC time."""
    return datetime.now(timezone.utc)


def timestamp_from_epoch(value: float) -> datetime:
    """Convert a packet epoch timestamp to an aware UTC datetime."""
    return datetime.fromtimestamp(value, tz=timezone.utc)


def parse_ip(value: str) -> str:
    """Validate and normalize an IPv4 or IPv6 address."""
    try:
        return str(ip_address(value))
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {value}") from exc
