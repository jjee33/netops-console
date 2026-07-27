"""Request helpers."""

from __future__ import annotations

from starlette.requests import Request


def client_ip(request: Request) -> str:
    """Best-known client address.

    Reads ``request.client.host``, which uvicorn has already rewritten from
    ``X-Forwarded-For`` when started with ``--proxy-headers`` and a matching
    ``--forwarded-allow-ips``. The header is deliberately not parsed here:
    doing so would trust it from any source, and uvicorn already applies the
    trusted-proxy check that makes it meaningful.
    """
    return request.client.host if request.client else "unknown"


def wants_partial(request: Request) -> bool:
    """True when HTMX issued the request and expects a fragment, not a page."""
    return request.headers.get("HX-Request") == "true"
