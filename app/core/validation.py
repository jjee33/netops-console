"""Network input validation.

Every IP, network, and hostname the application touches passes through here.
Phase 1 uses it for the settings page; discovery, diagnostics, and actions all
depend on it from Phase 2 onward, which is why the SSRF guards exist before
anything can reach the network.

The guiding rule: parse into a real type, then check the parsed value. Never
pattern-match a string and hope.
"""

from __future__ import annotations

import ipaddress
import re

# Ranges that must never be reachable, regardless of what an operator has
# configured. Loopback would let the app scan itself; link-local carries the
# cloud metadata endpoint, which is the single most valuable SSRF target on a
# hosted box.
_ALWAYS_BLOCKED = [
    ipaddress.IPv4Network("127.0.0.0/8"),  # loopback
    ipaddress.IPv4Network("169.254.0.0/16"),  # link-local, incl. 169.254.169.254
    ipaddress.IPv4Network("224.0.0.0/4"),  # multicast
    ipaddress.IPv4Network("240.0.0.0/4"),  # reserved
    ipaddress.IPv4Network("0.0.0.0/8"),  # "this network"
]

# RFC 1918 plus CGNAT. Anything outside these is public and out of scope for a
# tool whose entire premise is a private management network.
_PRIVATE_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),  # CGNAT, used by some homelab VPNs
]

# RFC 1123 label rules, plus a total-length cap. Deliberately does not accept
# a trailing dot or underscores.
_HOSTNAME_LABEL = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

MAX_HOSTNAME_LENGTH = 253


class ValidationError(ValueError):
    """Raised when input is rejected. The message is safe to show a user."""


def parse_ipv4(value: str) -> ipaddress.IPv4Address:
    """Parse a single IPv4 address.

    Rejects IPv6 explicitly rather than by accident — it is out of scope for
    v0.1, and a silent pass here would mean unvalidated addresses downstream.
    """
    candidate = value.strip()
    if not candidate:
        raise ValidationError("No address given.")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValidationError(f"{value!r} is not a valid IP address.") from exc
    if isinstance(address, ipaddress.IPv6Address):
        raise ValidationError("IPv6 is not supported in this version.")
    return address


def parse_ipv4_network(value: str, *, strict: bool = True) -> ipaddress.IPv4Network:
    """Parse a CIDR network.

    ``strict`` rejects host bits being set (``192.168.1.5/24``). That is almost
    always a typo for the network address, and quietly normalising it hides the
    mistake from whoever typed it.
    """
    candidate = value.strip()
    if not candidate:
        raise ValidationError("No network given.")
    if "/" not in candidate:
        raise ValidationError(f"{value!r} is missing a prefix length, e.g. /24.")
    try:
        network = ipaddress.ip_network(candidate, strict=strict)
    except ValueError as exc:
        message = str(exc)
        if "has host bits set" in message:
            try:
                suggestion = ipaddress.ip_network(candidate, strict=False)
            except ValueError:  # pragma: no cover - unreachable in practice
                raise ValidationError(f"{value!r} is not a valid network.") from exc
            raise ValidationError(
                f"{value!r} has host bits set. Did you mean {suggestion}?"
            ) from exc
        raise ValidationError(f"{value!r} is not a valid network.") from exc

    if isinstance(network, ipaddress.IPv6Network):
        raise ValidationError("IPv6 is not supported in this version.")
    return network


def is_blocked(address: ipaddress.IPv4Address) -> bool:
    """True for addresses that are never a legitimate target."""
    return any(address in blocked for blocked in _ALWAYS_BLOCKED)


def is_private(address: ipaddress.IPv4Address) -> bool:
    return any(address in private for private in _PRIVATE_RANGES)


def validate_allowed_cidr(value: str) -> ipaddress.IPv4Network:
    """Validate a network an operator is trying to add to the allowlist.

    Stricter than :func:`parse_ipv4_network`: the allowlist decides what the
    whole application may touch, so a mistake here widens every later check.
    """
    network = parse_ipv4_network(value)

    if any(network.subnet_of(blocked) or network.overlaps(blocked) for blocked in _ALWAYS_BLOCKED):
        raise ValidationError(
            f"{network} overlaps a reserved range (loopback, link-local, or multicast) "
            f"and cannot be managed."
        )

    if not any(network.subnet_of(private) for private in _PRIVATE_RANGES):
        raise ValidationError(
            f"{network} is not a private range. This application only manages "
            f"RFC 1918 and CGNAT addresses."
        )

    return network


def network_in_allowlist(
    network: ipaddress.IPv4Network, allowed: list[ipaddress.IPv4Network]
) -> bool:
    return any(network.subnet_of(entry) for entry in allowed)


def address_in_allowlist(
    address: ipaddress.IPv4Address, allowed: list[ipaddress.IPv4Network]
) -> bool:
    return any(address in entry for entry in allowed)


def validate_scan_target(
    value: str, allowed: list[ipaddress.IPv4Network], max_hosts: int
) -> ipaddress.IPv4Network:
    """Validate a subnet a user is asking to scan.

    Three separate gates, because they fail for different reasons and the
    operator needs to know which: is it a valid network, is it in scope, and is
    it small enough to finish.
    """
    network = parse_ipv4_network(value)

    if not network_in_allowlist(network, allowed):
        raise ValidationError(
            f"{network} is outside the configured allowed ranges. "
            f"Add it in Settings first if you intend to manage it."
        )

    # Checked after the allowlist so an enormous out-of-scope range reports the
    # more useful of the two errors.
    if network.num_addresses > max_hosts:
        raise ValidationError(
            f"{network} covers {network.num_addresses} addresses, above the "
            f"limit of {max_hosts}. Scan a smaller range or raise the limit."
        )

    return network


def validate_hostname(value: str) -> str:
    """Validate a DNS hostname.

    Length and charset only. This says nothing about where the name resolves —
    callers that will connect to it must resolve and then re-validate the
    resulting address, because a name is not a destination.
    """
    candidate = value.strip().lower()
    if not candidate:
        raise ValidationError("No hostname given.")
    if len(candidate) > MAX_HOSTNAME_LENGTH:
        raise ValidationError(f"Hostname exceeds {MAX_HOSTNAME_LENGTH} characters.")
    if candidate.endswith("."):
        candidate = candidate[:-1]

    try:
        # Reject anything that is not representable as IDNA, which also filters
        # homograph tricks and stray control characters.
        candidate.encode("idna")
    except UnicodeError as exc:
        raise ValidationError(f"{value!r} is not a valid hostname.") from exc

    labels = candidate.split(".")
    if not all(_HOSTNAME_LABEL.match(label) for label in labels):
        raise ValidationError(f"{value!r} is not a valid hostname.")

    return candidate


def validate_port(value: int | str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{value!r} is not a valid port.") from exc
    if not 1 <= port <= 65535:
        raise ValidationError("Port must be between 1 and 65535.")
    return port
