"""Jinja2 setup.

Autoescaping is on — it is Starlette's default for ``.html`` and this file
exists partly to make that explicit, because everything this application
renders from Phase 2 onward is untrusted output from network hosts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from starlette.requests import Request
from starlette.templating import Jinja2Templates

from app import __version__
from app.core.session import get_csrf_token

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.autoescape = True
# Surface a typo in a variable name instead of rendering an empty string.
templates.env.undefined = __import__("jinja2").StrictUndefined


def safe_external_url(value: str | None) -> str | None:
    """Return a URL only if it is plainly http(s).

    Device hostnames are discovered from the network and end up in href
    attributes. Without this, a hostname of ``javascript:alert(1)`` is stored
    XSS that autoescaping does not catch, because the payload is the attribute
    value rather than markup.
    """
    if not value:
        return None
    candidate = value.strip()
    lowered = candidate.lower()
    if lowered.startswith(("http://", "https://")) and "\n" not in candidate:
        return candidate
    return None


templates.env.filters["safe_external_url"] = safe_external_url


def render(
    request: Request, name: str, context: dict[str, Any] | None = None, **kwargs: Any
) -> Any:
    """Render a template with the values every page needs."""
    merged: dict[str, Any] = {
        "request": request,
        "csrf_token": get_csrf_token(request),
        "version": __version__,
        "current_user": getattr(request.state, "user", None),
    }
    if context:
        merged.update(context)
    return templates.TemplateResponse(request, name, merged, **kwargs)
