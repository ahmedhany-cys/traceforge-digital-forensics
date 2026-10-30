"""IP address and domain namespace classification.

Python's ``ipaddress.is_private`` lumps documentation and other special-purpose
ranges together with RFC 1918 space, which is not what an investigator needs.
This module separates them explicitly.
"""

from __future__ import annotations

import ipaddress

_RANGES: list[tuple[str, str]] = [
    ("10.0.0.0/8", "private"),
    ("172.16.0.0/12", "private"),
    ("192.168.0.0/16", "private"),
    ("100.64.0.0/10", "carrier_grade_nat"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link_local"),
    ("192.0.2.0/24", "documentation"),
    ("198.51.100.0/24", "documentation"),
    ("203.0.113.0/24", "documentation"),
    ("198.18.0.0/15", "benchmarking"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
    ("0.0.0.0/8", "unspecified"),
    ("255.255.255.255/32", "broadcast"),
    ("192.0.0.0/24", "reserved"),
    ("::1/128", "loopback"),
    ("fc00::/7", "private"),
    ("fe80::/10", "link_local"),
    ("2001:db8::/32", "documentation"),
    ("ff00::/8", "multicast"),
    ("::/128", "unspecified"),
]
_NETWORKS = [(ipaddress.ip_network(cidr), label) for cidr, label in _RANGES]

IP_CLASS_DESCRIPTIONS = {
    "private": "Private address space (RFC 1918 / RFC 4193) – internal to an organisation",
    "carrier_grade_nat": "Shared address space for carrier-grade NAT (RFC 6598)",
    "loopback": "Loopback – the host itself",
    "link_local": "Link-local – not routed beyond the local segment",
    "documentation": "Documentation range (RFC 5737 / RFC 3849) – not routable on the Internet; used here as a stand-in for an external address in simulated data",
    "benchmarking": "Benchmarking range (RFC 2544)",
    "multicast": "Multicast",
    "reserved": "Reserved / special-purpose",
    "unspecified": "Unspecified address",
    "broadcast": "Limited broadcast",
    "public": "Publicly routable address",
}

INTERNAL_CLASSES = {"private", "carrier_grade_nat", "loopback", "link_local", "unspecified", "broadcast", "multicast"}

RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local", "internal", "lan", "corp", "home"}
RESERVED_SECOND_LEVEL = {"example.com", "example.net", "example.org"}


def classify_ip(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    for network, label in _NETWORKS:
        if ip.version == network.version and ip in network:
            return label
    return "public"


def is_external_ip(value: str) -> bool:
    """True for addresses outside internal/special local ranges (documentation ranges count as external)."""
    cls = classify_ip(value)
    return cls is not None and cls not in INTERNAL_CLASSES


def classify_domain(domain: str) -> str:
    d = domain.lower().rstrip(".")
    tld = d.rsplit(".", 1)[-1]
    if tld in RESERVED_TLDS or any(d == s or d.endswith("." + s) for s in RESERVED_SECOND_LEVEL):
        return "reserved_example" if tld == "example" or "example." in d else "internal_or_reserved"
    return "public_namespace"
