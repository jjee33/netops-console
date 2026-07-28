"""Argv builders for the built-in diagnostics.

These are **hardcoded**, not admin-editable, which is what makes them the safest
execution surface in the application. A caller chooses a diagnostic by name from
a fixed registry and supplies at most a couple of bounded numeric parameters;
there is no path by which user text becomes a flag.

Every builder returns arguments only — the program name is passed separately to
the ExecutionEngine, which resolves it against its own allowlist.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# Bounds on the only numbers a user can influence. Chosen so the worst case an
# operator can request still finishes inside the engine's timeout.
MIN_PING_COUNT: Final = 1
MAX_PING_COUNT: Final = 20
DEFAULT_PING_COUNT: Final = 4

MIN_TRACE_HOPS: Final = 1
MAX_TRACE_HOPS: Final = 30
DEFAULT_TRACE_HOPS: Final = 15

# Deliberately short. A service scan is the heaviest diagnostic here and this is
# a device page, not a pentest tool.
SERVICE_SCAN_PORTS: Final = "22,53,80,443,445,3389,5000,8006,8080,8443"


@dataclass(frozen=True)
class Command:
    program: str
    arguments: list[str]
    timeout: float


def clamp(value: int | None, minimum: int, maximum: int, default: int) -> int:
    """Force a number into range rather than rejecting it.

    These come from a form's number input, where a browser has already
    constrained them. Clamping keeps a stray value from becoming an error page
    for something that has no security consequence — the bound is what matters,
    not which side of it the user landed on.
    """
    if value is None:
        return default
    return max(minimum, min(maximum, int(value)))


def ping(target: str, count: int | None = None) -> Command:
    packets = clamp(count, MIN_PING_COUNT, MAX_PING_COUNT, DEFAULT_PING_COUNT)
    return Command(
        program="ping",
        arguments=[
            "-c", str(packets),
            "-W", "2",          # per-reply timeout
            "-w", str(packets * 2 + 5),  # overall deadline; the engine timeout is the backstop
            "-n",               # no name resolution: this measures reachability, not DNS
            target,
        ],
        # Always longer than the tool's own deadline, so a normal run finishes
        # on its terms and the engine only fires when the tool misbehaves.
        timeout=packets * 2 + 15,
    )  # fmt: skip


def traceroute(target: str, max_hops: int | None = None) -> Command:
    hops = clamp(max_hops, MIN_TRACE_HOPS, MAX_TRACE_HOPS, DEFAULT_TRACE_HOPS)
    return Command(
        program="traceroute",
        arguments=[
            "-m", str(hops),
            "-w", "2",   # wait per probe
            "-q", "1",   # one probe per hop keeps this quick
            "-n",
            target,
        ],
        timeout=hops * 3 + 15,
    )  # fmt: skip


def dns_lookup(hostname: str) -> Command:
    return Command(
        program="dig",
        arguments=["+timeout=3", "+tries=2", "+noall", "+answer", hostname, "A"],
        timeout=15,
    )


def reverse_dns(address: str) -> Command:
    return Command(
        program="dig",
        arguments=["+timeout=3", "+tries=2", "+noall", "+answer", "-x", address],
        timeout=15,
    )


def tcp_check(target: str, port: int) -> Command:
    """Single-port TCP connect test.

    nmap rather than a raw socket so this shares the engine's timeout,
    concurrency limit and process-group kill. `-sT` is a plain connect, which
    needs no elevated privilege and cannot be mistaken for a stealth scan.
    """
    return Command(
        program="nmap",
        arguments=[
            "-sT",
            "-Pn",  # do not ping first; the caller already knows the host
            "-p", str(port),
            "--host-timeout", "10s",
            "-n",
            target,
        ],
        timeout=25,
    )  # fmt: skip


def service_scan(target: str) -> Command:
    return Command(
        program="nmap",
        arguments=[
            "-sT",
            "-sV",
            "--version-intensity", "2",  # light probing; full intensity is slow and noisy
            "-Pn",
            "-p", SERVICE_SCAN_PORTS,
            "--host-timeout", "60s",
            "-n",
            target,
        ],
        timeout=90,
    )  # fmt: skip


def arp_neighbour(target: str) -> Command:
    """Read the neighbour table entry for an address.

    Reads the kernel's existing cache rather than probing. Under host
    networking this is the host's real ARP table; under bridge networking it is
    the container's, which is useless — the same visibility caveat as discovery.
    """
    return Command(
        program="ip",
        arguments=["-4", "neigh", "show", target],
        timeout=10,
    )
