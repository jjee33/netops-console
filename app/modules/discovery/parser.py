"""Parsing nmap's XML output.

``defusedxml`` rather than the standard library parser. nmap output is
generated locally, so this is defence in depth rather than a live threat — but
the cost is one import and it removes entity expansion and external entity
questions from the review entirely.

The parser is written to tolerate the messy real cases rather than the clean
one: hosts with no MAC (anything across a router), no hostname (no reverse DNS),
no open ports, or a "down" state. Every one of these appears in a normal scan
and none of them is an error.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from defusedxml import ElementTree as DefusedET

logger = logging.getLogger("netops.discovery")


@dataclass
class ParsedPort:
    port: int
    protocol: str
    state: str
    service: str | None = None


@dataclass
class ParsedHost:
    ip_address: str
    mac_address: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    is_up: bool = True
    ports: list[ParsedPort] = field(default_factory=list)


@dataclass
class ParsedScan:
    hosts: list[ParsedHost] = field(default_factory=list)
    hosts_up: int = 0
    hosts_total: int = 0

    @property
    def up_hosts(self) -> list[ParsedHost]:
        return [host for host in self.hosts if host.is_up]


class ScanParseError(ValueError):
    """The output was not usable nmap XML."""


def parse_scan(xml: str | bytes) -> ParsedScan:
    """Parse ``nmap -oX`` output into hosts and ports."""
    if not xml or not str(xml).strip():
        raise ScanParseError("nmap produced no output to parse.")

    try:
        root = DefusedET.fromstring(xml)
    except Exception as exc:  # defusedxml raises several distinct types
        raise ScanParseError(f"could not parse nmap XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise ScanParseError(f"expected an <nmaprun> document, got <{root.tag}>.")

    scan = ParsedScan()

    for host_element in root.findall("host"):
        host = _parse_host(host_element)
        if host is not None:
            scan.hosts.append(host)

    runstats = root.find("runstats/hosts")
    if runstats is not None:
        scan.hosts_up = _to_int(runstats.get("up"), 0)
        scan.hosts_total = _to_int(runstats.get("total"), 0)
    else:
        scan.hosts_up = sum(1 for host in scan.hosts if host.is_up)
        scan.hosts_total = len(scan.hosts)

    return scan


def _parse_host(element: object) -> ParsedHost | None:
    find = element.find  # type: ignore[attr-defined]
    findall = element.findall  # type: ignore[attr-defined]

    ip_address: str | None = None
    mac_address: str | None = None
    vendor: str | None = None

    for address in findall("address"):
        kind = address.get("addrtype")
        value = address.get("addr")
        if not value:
            continue
        if kind == "ipv4":
            ip_address = value
        elif kind == "mac":
            # Normalise to lowercase colon-separated so dedup is not defeated
            # by formatting differences between sources.
            mac_address = value.lower()
            vendor = address.get("vendor") or None
        # ipv6 is deliberately ignored — out of scope for v0.1.

    if ip_address is None:
        # A host with no IPv4 address is not something this version can act on.
        logger.debug("skipping host element with no IPv4 address")
        return None

    status = find("status")
    is_up = status is None or status.get("state") == "up"

    hostname: str | None = None
    hostnames = find("hostnames")
    if hostnames is not None:
        for candidate in hostnames.findall("hostname"):
            name = candidate.get("name")
            if name:
                hostname = name
                break

    ports: list[ParsedPort] = []
    ports_element = find("ports")
    if ports_element is not None:
        for port_element in ports_element.findall("port"):
            parsed = _parse_port(port_element)
            if parsed is not None:
                ports.append(parsed)

    return ParsedHost(
        ip_address=ip_address,
        mac_address=mac_address,
        vendor=vendor,
        hostname=hostname,
        is_up=is_up,
        ports=ports,
    )


def _parse_port(element: object) -> ParsedPort | None:
    port_id = _to_int(element.get("portid"), 0)  # type: ignore[attr-defined]
    if not 1 <= port_id <= 65535:
        return None

    protocol = element.get("protocol", "tcp")  # type: ignore[attr-defined]
    if protocol not in ("tcp", "udp"):
        return None

    state_element = element.find("state")  # type: ignore[attr-defined]
    state = state_element.get("state", "closed") if state_element is not None else "closed"
    # nmap emits combined states such as "open|filtered"; store the first, and
    # anything unrecognised becomes "filtered" rather than being dropped.
    state = state.split("|")[0]
    if state not in ("open", "filtered", "closed"):
        state = "filtered"

    service_element = element.find("service")  # type: ignore[attr-defined]
    service = service_element.get("name") if service_element is not None else None

    return ParsedPort(port=port_id, protocol=protocol, state=state, service=service or None)


def _to_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default
