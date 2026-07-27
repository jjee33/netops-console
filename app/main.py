"""FastAPI application factory.

Middleware order matters and is not arbitrary. Starlette applies middleware in
reverse registration order, so the last one added is the outermost. Session
must be outside CSRF, because CSRF verification reads the session to find the
expected token.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_303_SEE_OTHER

from app import __version__
from app.core.config import get_settings
from app.core.db import dispose_engine
from app.core.middleware import CSRFMiddleware, SecurityHeadersMiddleware
from app.core.session import ABSOLUTE_LIFETIME
from app.modules.auth.dependencies import MustChangePassword, RedirectToLogin, redirect_to_login
from app.modules.auth.routes import router as auth_router
from app.modules.devices.routes import router as devices_router
from app.modules.settings.routes import router as settings_router

logger = logging.getLogger("netops")

STATIC_DIR = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logger.info("netops-console %s starting (db=%s)", __version__, settings.db_path)
    try:
        yield
    finally:
        await dispose_engine()
        logger.info("shutdown complete")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="NetOps Console",
        # No version in the OpenAPI metadata and no docs endpoints: this is an
        # admin panel, not a public API, and unauthenticated surface should
        # disclose nothing.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    # --- middleware (registered inner to outer) ---------------------------

    app.add_middleware(SecurityHeadersMiddleware)

    # CSRF sits inside the session middleware so it can read request.session.
    app.add_middleware(CSRFMiddleware)

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.read_secret_key(),
        session_cookie="netops_session",
        max_age=int(ABSOLUTE_LIFETIME.total_seconds()),
        same_site="strict",
        # All traffic is same-origin behind the proxy, so Strict costs nothing
        # and removes cross-site request forgery as a delivery vector entirely.
        https_only=settings.environment == "production",
    )

    # --- routes -----------------------------------------------------------

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    app.include_router(auth_router)
    app.include_router(devices_router)
    app.include_router(settings_router)

    @app.get("/healthz", include_in_schema=False)
    @app.head("/healthz", include_in_schema=False)
    async def healthz() -> Response:
        """Liveness probe.

        Returns 200 and nothing else. No version, no build info, no database
        state — this is the one endpoint reachable without authentication, so
        it must not be usable for fingerprinting.

        HEAD is accepted alongside GET because uptime monitors commonly default
        to it, and answering 405 there looks like an outage.
        """
        return Response(status_code=200)

    # --- exception handlers -----------------------------------------------

    @app.exception_handler(RedirectToLogin)
    async def _handle_redirect_to_login(
        _request: Request, exc: RedirectToLogin
    ) -> RedirectResponse:
        return redirect_to_login(exc.next_url)

    @app.exception_handler(MustChangePassword)
    async def _handle_must_change_password(
        _request: Request, _exc: MustChangePassword
    ) -> RedirectResponse:
        return RedirectResponse("/account/password", status_code=HTTP_303_SEE_OTHER)

    if settings.environment != "production":
        logger.warning(
            "running with environment=%s — not a production configuration", settings.environment
        )

    return app


# Deliberately no module-level `app = create_app()`. Building the app reads the
# session-signing key from disk, and doing that at import time means merely
# importing this module can fail — which breaks test collection and makes any
# tooling that imports the package depend on runtime secrets existing. uvicorn
# is started with --factory instead.
