"""Authorized live packet capture using Scapy without payload retention."""

from __future__ import annotations

from collections.abc import Callable

from scapy.all import get_if_list, sniff
from scapy.error import Scapy_Exception


class CaptureError(RuntimeError):
    """Capture setup or permission failure."""


def list_interfaces() -> list[str]:
    """Return interfaces visible to Scapy."""
    try:
        return sorted(get_if_list())
    except (OSError, Scapy_Exception) as exc:
        raise CaptureError(f"Could not enumerate network interfaces: {exc}") from exc


def capture_packets(
    interface: str,
    callback: Callable[[object], None],
    *,
    count: int | None = None,
    monitor: bool = False,
) -> None:
    """Capture packets on an explicitly selected interface."""
    if not interface:
        raise ValueError("An interface must be selected.")
    if monitor == (count is not None):
        raise ValueError("Choose either a positive count or continuous monitoring.")
    if count is not None and count < 1:
        raise ValueError("Packet count must be at least one.")
    try:
        sniff(
            iface=interface,
            count=0 if monitor else count,
            prn=callback,
            store=False,
        )
    except (OSError, PermissionError, Scapy_Exception) as exc:
        raise CaptureError(
            f"Capture failed on interface {interface!r}. Check the interface and "
            "capture permissions (on Windows, verify Npcap is installed). "
            f"Details: {exc}"
        ) from exc
