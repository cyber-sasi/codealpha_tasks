"""Validation and translation for the sniffer's small, safe filter language."""

from __future__ import annotations

import ipaddress
import re


class FilterError(ValueError):
    """Raised when a user-supplied filter is not supported."""


_SIMPLE_FILTERS = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp or icmp6",
    "arp": "arp",
    "dns": "udp port 53 or tcp port 53",
}


def parse_filter(expression: str | None) -> str | None:
    """Validate a supported filter and return its fixed BPF equivalent.

    The returned value is assembled only from validated IPs and integer ports;
    arbitrary BPF expressions are never passed through to Scapy.
    """
    if expression is None or not expression.strip():
        return None

    value = expression.strip().lower()
    if value in _SIMPLE_FILTERS:
        return _SIMPLE_FILTERS[value]

    host_match = re.fullmatch(r"host\s+(\S+)", value)
    if host_match:
        try:
            address = ipaddress.ip_address(host_match.group(1))
        except ValueError as error:
            raise FilterError("host filter requires a valid IPv4 or IPv6 address") from error
        return f"host {address}"

    port_match = re.fullmatch(r"port\s+(\d+)", value)
    if port_match:
        port = int(port_match.group(1))
        if not 0 <= port <= 65535:
            raise FilterError("port must be between 0 and 65535")
        return f"port {port}"

    raise FilterError(
        "unsupported filter; use tcp, udp, icmp, arp, dns, host <IP>, or port <PORT>"
    )