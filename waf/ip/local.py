"""Utilities for identifying local/private IP addresses."""

import ipaddress


def is_local_ip(ip: str) -> bool:
    """Return True if IP is loopback or private network address."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_loopback or addr.is_private
    except ValueError:
        return False


