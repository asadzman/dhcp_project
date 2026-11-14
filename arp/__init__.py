"""ARP Extension Package for DHCP Project.

This package defines the interfaces and constants for implementing the RFC 826
Address Resolution Protocol (ARP) extension.
"""
from .constants import ArpOpcode, ETHERTYPE_ARP

__all__ = ["ArpOpcode", "ETHERTYPE_ARP"]
