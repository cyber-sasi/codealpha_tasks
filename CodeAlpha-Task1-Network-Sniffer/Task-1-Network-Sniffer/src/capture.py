"""Passive live capture using Scapy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from scapy.all import get_if_list, sniff
from scapy.error import Scapy_Exception
from scapy.packet import Packet

from .analyzer import PacketRecord, analyze_packet


class CaptureError(RuntimeError):
    """Raised when live capture cannot start or continue."""


@dataclass(frozen=True)
class CaptureResult:
    records: list[PacketRecord]
    interrupted: bool


def list_interfaces() -> list[str]:
    """Return interfaces Scapy currently recognizes."""
    try:
        return sorted(get_if_list())
    except (OSError, Scapy_Exception) as error:
        raise CaptureError(f"could not enumerate network interfaces: {error}") from error


def capture_packets(
    interface: str,
    limit: int = 0,
    capture_filter: str | None = None,
    on_progress: Callable[[int], None] | None = None,
) -> CaptureResult:
    """Capture packets passively; limit 0 means stop only on Ctrl+C."""
    if limit < 0:
        raise CaptureError("packet limit cannot be negative")

    interfaces = list_interfaces()
    if interface not in interfaces:
        available = ", ".join(interfaces) if interfaces else "none detected"
        raise CaptureError(f"interface {interface!r} is unavailable; detected interfaces: {available}")

    records: list[PacketRecord] = []

    def process(packet: Packet) -> None:
        records.append(analyze_packet(packet, len(records) + 1))
        if on_progress is not None:
            on_progress(len(records))

    try:
        sniff(
            iface=interface,
            filter=capture_filter,
            count=limit,
            prn=process,
            store=False,
        )
    except KeyboardInterrupt:
        return CaptureResult(records=records, interrupted=True)
    except PermissionError as error:
        raise CaptureError(
            "permission denied; run with the required capture privileges and verify Npcap/libpcap is installed"
        ) from error
    except (OSError, Scapy_Exception) as error:
        raise CaptureError(
            f"capture could not start or continue: {error}. Check interface, privileges, and packet-capture driver."
        ) from error

    return CaptureResult(records=records, interrupted=False)