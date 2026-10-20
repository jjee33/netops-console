"""Explaining a discovery run's outcome.

Same approach as the diagnostic explanations: fixed rules over what was
recorded, each naming its evidence. The most valuable rule here is not about a
failure at all. A scan of a directly attached subnet that returns hosts but no
MAC addresses "succeeds" — and is the silent symptom of the container running
without host networking, which otherwise shows up only as empty columns.
"""

from __future__ import annotations

from collections.abc import Sequence

from app.models import DiscoveryObservation, DiscoveryRun
from app.modules.diagnostics.explain import (
    CAPABILITY_DOC,
    PERMISSION_PHRASES,
    Explanation,
    has_phrase,
)


def explain_run(
    run: DiscoveryRun, observations: Sequence[DiscoveryObservation]
) -> Explanation | None:
    summary = run.output_summary or ""

    if run.status == "running":
        return None

    if run.status in ("failed", "rejected") and (
        evidence := has_phrase(summary, *PERMISSION_PHRASES)
    ):
        return Explanation(
            headline="nmap was not allowed to send raw packets.",
            evidence=f"The scan output contains “{evidence}”.",
            causes=["The container is missing CAP_NET_RAW, or nmap lost its file capability."],
            next_steps=[
                f"Verify capabilities as described in {CAPABILITY_DOC}.",
                "As a stopgap, uncheck port detection: host discovery needs less privilege.",
            ],
        )

    if summary.startswith("Interrupted"):
        return Explanation(
            headline="The application restarted while this scan was running.",
            evidence="Closed out at startup; no results were recorded.",
            causes=["A container restart, upgrade, or crash during the scan."],
            next_steps=["Run the scan again."],
        )

    if run.status == "timeout":
        return Explanation(
            headline="The scan ran past its time limit and was stopped.",
            evidence=summary or None,
            causes=[
                "The range is large and many addresses are filtered, so each probe waits.",
                "Port detection multiplies the work per host.",
            ],
            next_steps=[
                "Scan a smaller range, such as one /24 at a time.",
                "Run host discovery only (uncheck port detection), then check ports on the "
                "devices you care about from their pages.",
            ],
        )

    if run.status == "rejected":
        if "slots are in use" in summary or "concurrent" in summary.lower():
            return Explanation(
                headline="Not run: the concurrent-scan limit was reached.",
                evidence=summary,
                next_steps=["Wait for the running scan to finish, then start this one."],
            )
        return Explanation(
            headline="Refused before anything ran.",
            evidence=summary or None,
            next_steps=["Correct the range named in the message, or adjust Settings."],
        )

    if run.status == "failed":
        return Explanation(
            headline="The scan failed without a recognised cause.",
            evidence=summary[:300] or None,
            next_steps=["Check the application logs for the full nmap error."],
        )

    # Success from here on.
    present = [row for row in observations if row.present]
    if run.devices_found == 0:
        return Explanation(
            headline="The scan completed and nothing answered.",
            evidence="Zero hosts responded in the range.",
            causes=[
                "The range is not one this host can reach, or is unused.",
                "The container is on Docker bridge networking, so ARP discovery cannot see "
                "the LAN and only hosts answering IP probes are found.",
                "Hosts drop the probes nmap uses for discovery (strict host firewalls).",
            ],
            next_steps=[
                "Confirm the range matches the subnet chips detected on the Discovery page.",
                "Check that compose.yaml uses network_mode: host (README, “Why host networking”).",
            ],
        )

    if len(present) >= 2 and not any(row.mac_address for row in present):
        return Explanation(
            headline="Hosts answered, but none reported a MAC address.",
            evidence=f"0 of {len(present)} responding hosts had a MAC address.",
            causes=[
                "Expected if this subnet is behind a router: MAC addresses are not visible "
                "across layer 3.",
                "If this subnet is directly attached to the host, the container is very likely "
                "not using host networking, so ARP is hidden behind Docker's NAT.",
            ],
            next_steps=[
                "Check compose.yaml for network_mode: host (README, “Why host networking”).",
                "Compare against the subnets detected on this host on the Discovery page.",
            ],
        )

    return None
