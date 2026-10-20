"""Explaining what a check result means, and what to try next.

Deterministic rules over a stored result: the diagnostic type, its status, and
a handful of well-known phrases in the tool's own output. No model, no guess at
a root cause presented as fact. Each explanation names the evidence it was
based on, lists the plausible causes in rough order of likelihood on a small
network, and points at the next check worth running — usually another built-in
diagnostic on the same page.

Some of these fire on a *successful* run. ``dig`` exits 0 with an empty answer
for a name that does not exist, and an nmap connect test exits 0 whether the
port was open or closed. Status alone would report those as fine.

Output is matched, never executed or rendered as markup; the evidence string is
a fixed phrase from this module, not a slice of the output.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from app.models import DiagnosticResult

CAPABILITY_DOC = "docs/INSTALL.md (capability verification)"


@dataclass(frozen=True)
class Explanation:
    headline: str
    evidence: str | None = None
    causes: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)


def has_phrase(output: str, *phrases: str) -> str | None:
    lowered = output.lower()
    for phrase in phrases:
        if phrase.lower() in lowered:
            return phrase
    return None


PERMISSION_PHRASES = (
    "Operation not permitted",
    "requires root privileges",
    "Couldn't open a raw socket",
    "dnet: Failed to open device",
    "permission denied",
)


def _capability(evidence: str) -> Explanation:
    return Explanation(
        headline="The tool was not allowed to send raw packets.",
        evidence=f"Output contains “{evidence}”.",
        causes=[
            "The container is missing CAP_NET_RAW, or the binary lost its file capability.",
            "A custom image or a hardened runtime dropped the capability after build.",
        ],
        next_steps=[
            f"Verify capabilities as described in {CAPABILITY_DOC}.",
            "Check that compose.yaml still has cap_add: [NET_RAW].",
        ],
    )


def _rejected(result: DiagnosticResult) -> Explanation:
    output = result.output or ""
    if "outside the currently allowed ranges" in output:
        return Explanation(
            headline="Refused: this device is outside the ranges you allow.",
            evidence="The address failed the allowed-range check at run time.",
            causes=[
                "The allowed ranges were narrowed after this device was discovered.",
                "The device moved to an address on a subnet you have not allowed.",
            ],
            next_steps=[
                "If you intend to manage it, add its range under Settings → Allowed ranges.",
                "If the address changed, rescan its current subnet so the inventory catches up.",
            ],
        )
    if "reserved range" in output:
        return Explanation(
            headline="Refused: the address is in a reserved range.",
            evidence="Loopback, link-local and multicast are never contacted.",
            causes=["The inventory holds an address that can never be a managed target."],
            next_steps=["Remove this device, or rescan if its address has since changed."],
        )
    if "no discovered hostname" in output:
        return Explanation(
            headline="Nothing to look up: no hostname is known for this device.",
            evidence="Forward DNS needs a name, and no scan has reported one.",
            causes=["The device has no PTR record, so the scan's reverse lookup found no name."],
            next_steps=["Run Reverse DNS to confirm, or set a name on the device's DNS server."],
        )
    return Explanation(
        headline="Refused before anything ran.",
        evidence="The request failed validation; the message above says which check.",
        next_steps=["Correct the value named in the message and run the check again."],
    )


def _ping(result: DiagnosticResult) -> Explanation | None:
    output = result.output or ""
    if evidence := has_phrase(output, *PERMISSION_PHRASES):
        return _capability(evidence)

    if evidence := has_phrase(output, "Destination Host Unreachable"):
        return Explanation(
            headline="Nothing answered at this address on the local segment.",
            evidence=f"Output contains “{evidence}”: no ARP reply was received.",
            causes=[
                "The device is off, asleep, or disconnected.",
                "It has moved to a different address (DHCP) and something else may "
                "take this one later.",
            ],
            next_steps=[
                "Rescan the subnet: if the device moved, it reappears under its MAC.",
                "Check the switch port or Wi-Fi client list for its MAC address.",
            ],
        )

    loss = result.packet_loss_pct
    if loss is not None and loss >= 100:
        return Explanation(
            headline="No echo replies, but no error either.",
            evidence="100% packet loss without “Destination Host Unreachable”.",
            causes=[
                "The device is up and its firewall drops ICMP echo — the Windows default, "
                "and common on cameras and hardened appliances.",
                "The device is on another subnet and is down or unreachable past the router.",
                "A firewall between this host and the device blocks ICMP.",
            ],
            next_steps=[
                "Run ARP entry: an entry in REACHABLE or STALE state proves the device is "
                "present on the segment even though it ignores ping.",
                "Run TCP port test against a port the device is known to have open.",
            ],
        )
    if loss is not None and loss > 0:
        return Explanation(
            headline=f"Intermittent: {loss:.0f}% of echo requests went unanswered.",
            evidence="Some replies arrived and some did not.",
            causes=[
                "Wi-Fi interference or a weak signal, if the device is wireless.",
                "A congested or failing link, or a duplex mismatch on a wired port.",
                "Devices that rate-limit ICMP under load (some switches and routers).",
            ],
            next_steps=[
                "Run Ping again with a higher count to see whether the loss is consistent.",
                "Run Traceroute to see whether loss begins at a particular hop.",
            ],
        )
    if result.status == "timeout":
        return Explanation(
            headline="Ping did not finish within its time limit.",
            causes=["The host is unusually slow to answer or the local resolver is stalled."],
            next_steps=["Run it again with a lower count."],
        )
    return None


_TRACE_LINE = re.compile(r"^\s*(\d+)\s+(.*)$")


def _traceroute(result: DiagnosticResult) -> Explanation | None:
    output = result.output or ""
    if evidence := has_phrase(output, *PERMISSION_PHRASES):
        return _capability(evidence)

    for marker, meaning in (
        ("!X", "communication administratively prohibited — a firewall rejected the probe"),
        ("!N", "network unreachable — a router has no route onward"),
        ("!H", "host unreachable — the last router could not deliver to the device"),
    ):
        if marker in output:
            return Explanation(
                headline="A router along the path rejected the probe.",
                evidence=f"Output contains “{marker}”: {meaning}.",
                causes=["A firewall rule or missing route between this host and the device."],
                next_steps=["Check routing and ACLs on the last hop shown before the marker."],
            )

    hops = [match for line in output.splitlines() if (match := _TRACE_LINE.match(line))]
    if hops and result.target not in hops[-1].group(2):
        return Explanation(
            headline="The trace did not reach the device.",
            evidence=f"The last hop listed ({hops[-1].group(1)}) is not {result.target}.",
            causes=[
                "Hops that do not answer (shown as *) are common and usually harmless; "
                "many devices simply do not send the ICMP replies traceroute relies on.",
                "If every hop after a point is *, traffic may be dropped there.",
            ],
            next_steps=[
                "Run TCP port test against a known open port: if it connects, the path works "
                "and only ICMP is filtered.",
            ],
        )
    return None


def _dns(result: DiagnosticResult) -> Explanation | None:
    output = (result.output or "").strip()
    if evidence := has_phrase(output, "no servers could be reached", "connection timed out"):
        return Explanation(
            headline="The resolver did not answer.",
            evidence=f"Output contains “{evidence}”.",
            causes=[
                "The DNS server configured for this host is down or unreachable.",
                "Under bridge networking, the container's resolver differs from the host's.",
            ],
            next_steps=["Check /etc/resolv.conf on the host and that the DNS server is up."],
        )
    if evidence := has_phrase(output, "SERVFAIL"):
        return Explanation(
            headline="The resolver answered but could not resolve the name.",
            evidence=f"Output contains “{evidence}”.",
            causes=["An upstream or DNSSEC failure on the resolver."],
            next_steps=["Check the resolver's own logs."],
        )
    if result.status == "success" and output in ("", "(no output)"):
        if result.type == "rdns":
            return Explanation(
                headline="No PTR record exists for this address.",
                evidence="The query succeeded and returned an empty answer.",
                causes=[
                    "Very common on home and small-office networks: many routers do not "
                    "register DHCP clients in reverse DNS.",
                ],
                next_steps=["Give the device a name here instead — it is never overwritten."],
            )
        return Explanation(
            headline="The name does not resolve to an address.",
            evidence="The query succeeded and returned no A record.",
            causes=[
                "The hostname came from a reverse lookup and has no matching forward record.",
                "The record was removed, or exists only on a different DNS server.",
            ],
            next_steps=["Run Reverse DNS to see which name the address currently maps to."],
        )
    return None


_PORT_STATE = re.compile(r"^(\d+)/(tcp|udp)\s+(open|closed|filtered|open\|filtered)\b", re.M)


def _tcp(result: DiagnosticResult) -> Explanation | None:
    output = result.output or ""
    if evidence := has_phrase(output, *PERMISSION_PHRASES):
        return _capability(evidence)
    match = _PORT_STATE.search(output)
    if not match:
        return None
    port, state = f"{match.group(1)}/{match.group(2)}", match.group(3)
    if state == "closed":
        return Explanation(
            headline=f"The device is up, but nothing is listening on {port}.",
            evidence="nmap reported the port “closed”: the device actively refused.",
            causes=[
                "The service is stopped, or listens on a different port.",
                "The service is bound to another interface (for example, localhost only).",
            ],
            next_steps=["Run Service scan to see which common ports are open instead."],
        )
    if state in ("filtered", "open|filtered"):
        return Explanation(
            headline=f"No answer on {port}.",
            evidence=f"nmap reported the port “{state}”: probes were silently dropped.",
            causes=[
                "A firewall on the device or in between drops connections to this port.",
                "The device is down — a connect test does not ping first.",
            ],
            next_steps=[
                "Run ARP entry or Ping to establish whether the device itself is up.",
                "Check the device's firewall for this port.",
            ],
        )
    return None


def _arp(result: DiagnosticResult) -> Explanation | None:
    output = (result.output or "").strip()
    if result.status != "success":
        return None
    if output in ("", "(no output)"):
        return Explanation(
            headline="No neighbour table entry for this address.",
            evidence="The kernel's ARP cache has nothing for it.",
            causes=[
                "Nothing has talked to the device recently; entries expire after a few minutes.",
                "The device is on another subnet: ARP only covers the local segment.",
                "Under bridge networking this is the container's table, not the host's, "
                "and is nearly always empty.",
            ],
            next_steps=["Run Ping first (it triggers ARP), then ARP entry again."],
        )
    if evidence := has_phrase(output, "FAILED", "INCOMPLETE"):
        return Explanation(
            headline="ARP was attempted and nothing answered.",
            evidence=f"The entry is in state {evidence}.",
            causes=["The device is off or disconnected, or this address is no longer in use."],
            next_steps=["Rescan the subnet to see whether the device moved address."],
        )
    return None


def _http(result: DiagnosticResult) -> Explanation | None:
    output = result.output or ""
    if evidence := has_phrase(output, "Connection refused"):
        return Explanation(
            headline="The device refused the connection.",
            evidence=f"Output contains “{evidence}”.",
            causes=["No web server is listening on this port."],
            next_steps=["Try the other common port (80, 443, 8080, 8443) or run Service scan."],
        )
    if evidence := has_phrase(output, "WRONG_VERSION_NUMBER", "wrong version number"):
        return Explanation(
            headline="HTTPS was attempted against a plain-HTTP port.",
            evidence=f"Output contains “{evidence}”.",
            causes=["The check uses HTTPS only for 443 and 8443; this service speaks HTTP."],
            next_steps=["Check the port again: plain HTTP is used for any port but 443/8443."],
        )
    if evidence := has_phrase(output, "RemoteProtocolError", "Server disconnected"):
        return Explanation(
            headline="The server closed the connection without an HTTP response.",
            evidence=f"Output contains “{evidence}”.",
            causes=[
                "Plain HTTP was sent to a port that expects TLS.",
                "The service on this port is not a web server.",
            ],
            next_steps=["Run Service scan to identify what is listening."],
        )
    if evidence := has_phrase(output, "No response from"):
        return Explanation(
            headline="The connection attempt timed out.",
            evidence="No response within the check's time limit.",
            causes=["A firewall drops the connection, or the device is down."],
            next_steps=["Run TCP port test on the same port to separate the two."],
        )
    status = re.search(r"^status:\s+(\d{3})", output, re.M)
    if status:
        code = int(status.group(1))
        if code in (401, 403):
            return Explanation(
                headline=f"Reachable — the web interface answered and requires login ({code}).",
                evidence=f"HTTP {code}.",
                causes=["Normal for an admin interface. The service itself is working."],
            )
        if code == 404:
            return Explanation(
                headline="Reachable — but nothing is served at /.",
                evidence="HTTP 404.",
                causes=["The interface lives under a path, or this is an API endpoint."],
            )
        if code >= 500:
            return Explanation(
                headline=f"The web server answered with an error ({code}).",
                evidence=f"HTTP {code}.",
                causes=["The application behind the server is failing or still starting."],
                next_steps=["Check the device's own logs; try again after a minute."],
            )
    return None


def _service_scan(result: DiagnosticResult) -> Explanation | None:
    output = result.output or ""
    if evidence := has_phrase(output, *PERMISSION_PHRASES):
        return _capability(evidence)
    if result.status == "timeout":
        return Explanation(
            headline="The service scan ran out of time.",
            causes=["Many filtered ports make version probing slow."],
            next_steps=["Use TCP port test on the specific port you care about."],
        )
    return None


_RULES: dict[str, Callable[[DiagnosticResult], Explanation | None]] = {
    "ping": _ping,
    "traceroute": _traceroute,
    "dns": _dns,
    "rdns": _dns,
    "tcp": _tcp,
    "service_scan": _service_scan,
    "arp": _arp,
    "http_check": _http,
}


def explain_diagnostic(result: DiagnosticResult) -> Explanation | None:
    """An explanation for a result, or None when the result speaks for itself."""
    if result.status == "rejected":
        return _rejected(result)
    if result.status == "busy":
        return Explanation(
            headline="Not run: every execution slot was in use.",
            evidence="Concurrency is capped so the host cannot be overloaded.",
            causes=["Other diagnostics, actions or a scan were running at the same moment."],
            next_steps=[
                "Run it again in a few seconds.",
                "If this happens routinely, raise concurrent executions in Settings.",
            ],
        )

    rule = _RULES.get(result.type)
    explanation = rule(result) if rule else None
    if explanation is None and result.status == "timeout":
        return Explanation(
            headline="The check did not finish within its time limit.",
            causes=["The device or the path to it is very slow, or probes are being dropped."],
            next_steps=["Run Ping to check basic reachability first."],
        )
    if explanation is None and result.status == "failed":
        return Explanation(
            headline="The check failed without a recognised cause.",
            evidence=(f"Exit code {result.exit_code}." if result.exit_code is not None else None),
            next_steps=["Read the output above; the tool's own message is the best guide."],
        )
    return explanation
