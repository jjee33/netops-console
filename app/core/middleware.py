"""Security headers and CSRF protection.

Both are pure ASGI middleware rather than ``BaseHTTPMiddleware`` subclasses.
That is not stylistic. ``BaseHTTPMiddleware`` builds a fresh ``Request`` for the
downstream app, so a body read inside the middleware consumes the stream and
the route handler receives nothing — the visible symptom is every form POST
failing validation with 422 while the middleware itself appears to work. CSRF
has to read the body to find the token in a form field, so it buffers the body
and replays it downstream.

CSRF is enforced here rather than as a per-route dependency because a
dependency has to be remembered on every new state-changing route, and
forgetting one fails open: the route works, it is simply unprotected.
Middleware fails closed for anything anyone adds later.
"""

from __future__ import annotations

import logging
from typing import Final
from urllib.parse import parse_qs

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.session import CSRF_FIELD, CSRF_HEADER, verify_csrf

logger = logging.getLogger("netops.security")

SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

# Exempt from CSRF: only the liveness probe, which is a GET and changes nothing.
CSRF_EXEMPT_PATHS: Final = frozenset({"/healthz"})

# Refuse to buffer an unbounded body while looking for a token. Forms in this
# application are a few hundred bytes.
MAX_CSRF_BODY_BYTES: Final = 1024 * 1024

# No 'unsafe-inline' anywhere. That is the entire point of a CSP for an app that
# renders command output from untrusted hosts: even if escaping fails somewhere,
# an injected <script> has nothing to execute. It also means every script and
# stylesheet must be a real file served from this origin, which is why HTMX is
# vendored into static/ instead of loaded from a CDN.
CONTENT_SECURITY_POLICY: Final = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        # This app talks only to its own origin.
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "object-src 'none'",
    ]
)

SECURITY_HEADERS: Final = {
    b"content-security-policy": CONTENT_SECURITY_POLICY.encode(),
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    # Device hostnames and addresses appear in URLs; never leak them onward.
    b"referrer-policy": b"no-referrer",
    b"cross-origin-opener-policy": b"same-origin",
    b"cross-origin-resource-policy": b"same-origin",
    b"permissions-policy": b"geolocation=(), camera=(), microphone=(), payment=(), usb=()",
    # An admin panel has no business in a search index.
    b"x-robots-tag": b"noindex, nofollow",
}

HSTS: Final = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        # HSTS only over TLS. Sending it on a plain-HTTP response is how a
        # hostname gets pinned to https for everyone who ever visited it.
        secure = headers.get("x-forwarded-proto") == "https" or scope.get("scheme") == "https"

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                raw = message.setdefault("headers", [])
                present = {name.lower() for name, _ in raw}
                for name, value in SECURITY_HEADERS.items():
                    if name not in present:
                        raw.append((name, value))
                if secure and HSTS[0] not in present:
                    raw.append(HSTS)
            await send(message)

        await self.app(scope, receive, send_with_headers)


class CSRFMiddleware:
    """Reject state-changing requests without a valid synchronizer token."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "")
        if method in SAFE_METHODS or path in CSRF_EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        submitted = headers.get(CSRF_HEADER)
        downstream_receive = receive

        if submitted is None and _is_form(headers.get("content-type", "")):
            body, downstream_receive = await _buffer_body(receive)
            submitted = _token_from_form(body, headers.get("content-type", ""))

        request = Request(scope, downstream_receive)
        if not verify_csrf(request, submitted):
            logger.warning(
                "CSRF rejection: %s %s from %s",
                method,
                path,
                request.client.host if request.client else "unknown",
            )
            response = JSONResponse(
                {"detail": "Invalid or missing CSRF token. Reload the page and try again."},
                status_code=403,
            )
            await response(scope, downstream_receive, send)
            return

        await self.app(scope, downstream_receive, send)


def _is_form(content_type: str) -> bool:
    return content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data"))


async def _buffer_body(receive: Receive) -> tuple[bytes, Receive]:
    """Read the whole body, and return a receive that replays it downstream."""
    chunks: list[bytes] = []
    size = 0
    more = True
    while more:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > MAX_CSRF_BODY_BYTES:
            # Stop buffering; the token will not be found and the request is
            # rejected. A body this large is not one of our forms.
            chunks.append(chunk)
            break
        chunks.append(chunk)
        more = bool(message.get("more_body", False))

    body = b"".join(chunks)

    async def replay() -> Message:
        return {"type": "http.request", "body": body, "more_body": False}

    return body, replay


def _token_from_form(body: bytes, content_type: str) -> str | None:
    if content_type.startswith("application/x-www-form-urlencoded"):
        values = parse_qs(body.decode("utf-8", errors="replace")).get(CSRF_FIELD)
        return values[0] if values else None

    # multipart: scan for the field rather than running a full parser. The token
    # is a urlsafe-base64 string, so no encoding subtleties apply.
    marker = f'name="{CSRF_FIELD}"'.encode()
    index = body.find(marker)
    if index == -1:
        return None
    separator = body.find(b"\r\n\r\n", index)
    if separator == -1:
        return None
    end = body.find(b"\r\n", separator + 4)
    raw = body[separator + 4 : end if end != -1 else len(body)]
    return raw.decode("utf-8", errors="replace").strip() or None
