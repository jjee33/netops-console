"""HTTP(S) reachability check.

The one diagnostic that is not a subprocess, and therefore the one that does not
inherit the ExecutionEngine's guarantees for free. Each has to be provided
explicitly here: a hard timeout, a capped read, and — the part that matters —
destination validation that survives DNS.

Why this is the SSRF surface. Every other diagnostic targets an address that
came from discovery inside an allowed range. This one takes a scheme, a host and
a port, and asks the server to make a request. Validating the *name* is not
enough: a name resolves to an address, and the address is what gets connected
to. So the resolution happens here, the resolved address is checked against the
allowlist, and the connection is pinned to that address rather than re-resolved
by the HTTP client.

Known limit, accepted and documented: between our resolution and the connection
there is a window in which a DNS answer could change (rebinding). Pinning the
connection to the address we validated closes the usual form of it; short
timeouts and private-range enforcement bound whatever remains.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Final

import httpx

from app.core.validation import (
    ValidationError,
    address_in_allowlist,
    is_blocked,
    validate_hostname,
    validate_port,
)

logger = logging.getLogger("netops.diagnostics")

REQUEST_TIMEOUT: Final = 10.0
# Enough to see a title or an error page. This is a reachability check, not a
# scraper, and an unbounded read is a memory problem waiting for a big response.
MAX_BODY_BYTES: Final = 64 * 1024

ALLOWED_SCHEMES: Final = ("http", "https")


@dataclass(frozen=True)
class HttpCheckResult:
    ok: bool
    summary: str
    detail: str
    status_code: int | None = None
    latency_ms: float | None = None


def _resolve(host: str) -> list[ipaddress.IPv4Address]:
    """Resolve a name to IPv4 addresses, or return the literal if it is one."""
    try:
        return [ipaddress.IPv4Address(host)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValidationError(f"{host!r} did not resolve.") from exc

    addresses: list[ipaddress.IPv4Address] = []
    for info in infos:
        try:
            addresses.append(ipaddress.IPv4Address(info[4][0]))
        except ValueError:  # pragma: no cover - getaddrinfo returned something odd
            continue

    if not addresses:
        raise ValidationError(f"{host!r} did not resolve to an IPv4 address.")
    return addresses


def validate_target(
    host: str, port: int | str, scheme: str, allowed: list[ipaddress.IPv4Network]
) -> tuple[ipaddress.IPv4Address, int]:
    """Validate and resolve a check target. Returns the address to connect to.

    Raises :class:`ValidationError` with a message safe to show the operator.
    """
    if scheme not in ALLOWED_SCHEMES:
        raise ValidationError(f"{scheme!r} is not a supported scheme.")

    checked_port = validate_port(port)

    # A literal address skips hostname rules; a name must pass them first.
    try:
        ipaddress.IPv4Address(host)
    except ValueError:
        host = validate_hostname(host)

    addresses = _resolve(host)

    # Every resolved address must be acceptable, not merely the first. A name
    # answering with one allowed and one public address must not be reachable
    # by retry or by round-robin.
    for address in addresses:
        if is_blocked(address):
            raise ValidationError(
                f"{host} resolves to {address}, which is in a reserved range "
                f"(loopback, link-local, or multicast) and cannot be contacted."
            )
        if not address_in_allowlist(address, allowed):
            raise ValidationError(
                f"{host} resolves to {address}, which is outside the configured allowed ranges."
            )

    return addresses[0], checked_port


async def check(
    host: str,
    port: int | str,
    scheme: str,
    allowed: list[ipaddress.IPv4Network],
    *,
    path: str = "/",
) -> HttpCheckResult:
    """Perform the check against a validated, pinned address."""
    address, checked_port = validate_target(host, port, scheme, allowed)

    url = f"{scheme}://{host}:{checked_port}{path if path.startswith('/') else '/'}"

    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            # Redirects are not followed. A 302 to an internal or public address
            # would be a validated request turning into an unvalidated one.
            follow_redirects=False,
            # Device certificates are self-signed as a rule; this checks
            # reachability, and refusing to connect would report every appliance
            # as down. It is stated in the result so nobody reads it as
            # certificate validation.
            verify=False,  # noqa: S501
            # Pin the connection to the address we validated, so the client does
            # not resolve the name a second time and possibly differently.
            transport=httpx.AsyncHTTPTransport(local_address=None),
        ) as client:
            request = client.build_request("GET", url, headers={"Host": f"{host}:{checked_port}"})
            request.url = request.url.copy_with(host=str(address))
            response = await client.send(request, stream=True)
            try:
                body = b""
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) >= MAX_BODY_BYTES:
                        break
            finally:
                await response.aclose()

    except httpx.TimeoutException:
        return HttpCheckResult(
            ok=False,
            summary="Timed out",
            detail=f"No response from {url} within {REQUEST_TIMEOUT:.0f}s.",
        )
    except httpx.HTTPError as exc:
        return HttpCheckResult(
            ok=False, summary="Connection failed", detail=f"{type(exc).__name__}: {exc}"
        )

    latency = response.elapsed.total_seconds() * 1000 if response.elapsed else None
    server = response.headers.get("server", "not reported")
    preview = body[:512].decode("utf-8", errors="replace")

    detail = (
        f"{url}\n"
        f"connected to: {address}:{checked_port}\n"
        f"status:       {response.status_code} {response.reason_phrase}\n"
        f"server:       {server}\n"
        f"content-type: {response.headers.get('content-type', 'not reported')}\n"
        f"bytes read:   {len(body)}{' (capped)' if len(body) >= MAX_BODY_BYTES else ''}\n"
        f"note:         TLS certificates are not verified; this checks reachability only\n"
        f"\n--- first 512 bytes ---\n{preview}"
    )

    return HttpCheckResult(
        ok=response.status_code < 400,
        summary=f"HTTP {response.status_code}",
        detail=detail,
        status_code=response.status_code,
        latency_ms=latency,
    )
