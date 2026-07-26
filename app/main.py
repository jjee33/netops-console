"""FastAPI application factory.

Phase 0 scaffold: liveness only. Routers, session middleware, CSRF, and the
template layer land in Phase 1.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Response

from app import __version__
from app.core.config import get_settings
from app.core.db import dispose_engine

logger = logging.getLogger("netops")


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

    @app.api_route("/healthz", methods=["GET", "HEAD"], include_in_schema=False)
    async def healthz() -> Response:
        """Liveness probe.

        Returns 200 and nothing else. No version, no build info, no database
        state — this is the one endpoint reachable without authentication, so
        it must not be usable for fingerprinting.

        HEAD is accepted alongside GET because uptime monitors commonly default
        to it, and answering 405 there looks like an outage.
        """
        return Response(status_code=200)

    if settings.environment != "production":
        logger.warning(
            "running with environment=%s — not a production configuration", settings.environment
        )

    return app


app = create_app()
