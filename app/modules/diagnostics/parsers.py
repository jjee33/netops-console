"""Extracting structured values from diagnostic output.

Only latency and packet loss, and only where the tool reports them. Storing
these as columns means the device page can show a trend without re-parsing text
on every render, and means a failed parse degrades to "no number" rather than
to a broken page.
"""

from __future__ import annotations

import re

# `4 packets transmitted, 4 received, 0% packet loss, time 3005ms`
# BSD and busybox word it differently; both spellings are covered.
_LOSS = re.compile(r"(\d+(?:\.\d+)?)%\s*(?:packet\s*)?loss", re.IGNORECASE)

# `rtt min/avg/max/mdev = 0.312/0.401/0.502/0.071 ms`
_RTT = re.compile(
    r"(?:rtt|round-trip)\s+min/avg/max(?:/m?dev)?\s*=\s*"
    r"([\d.]+)/([\d.]+)/([\d.]+)",
    re.IGNORECASE,
)

# Fallback for a single reply: `time=0.412 ms`
_SINGLE_TIME = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def parse_ping(output: str) -> tuple[float | None, float | None]:
    """Return ``(average latency ms, packet loss percent)``.

    Either may be ``None``: a host that answered nothing has no latency, and a
    tool that reported no summary line has no loss figure. Neither is an error.
    """
    loss: float | None = None
    match = _LOSS.search(output)
    if match:
        try:
            loss = float(match.group(1))
        except ValueError:  # pragma: no cover - regex guarantees digits
            loss = None

    latency: float | None = None
    rtt = _RTT.search(output)
    if rtt:
        try:
            latency = float(rtt.group(2))
        except ValueError:  # pragma: no cover
            latency = None
    else:
        times = [float(value) for value in _SINGLE_TIME.findall(output)]
        if times:
            latency = round(sum(times) / len(times), 3)

    return latency, loss


def summarise_ping(latency: float | None, loss: float | None) -> str:
    """A one-line human summary for the result header."""
    if loss is not None and loss >= 100:
        return "No reply"
    parts = []
    if latency is not None:
        parts.append(f"{latency:.1f} ms average")
    if loss is not None:
        parts.append(f"{loss:.0f}% loss")
    return ", ".join(parts) if parts else "Completed"
