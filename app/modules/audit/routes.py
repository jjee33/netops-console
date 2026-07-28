"""Audit log.

A single chronological view over everything the application has done —
diagnostics and discovery runs today, actions when they land. Kept as one
timeline rather than per-feature tables because the question an operator
actually asks is "what happened to my network", not "what did the diagnostics
subsystem do".

Paginated with a keyset on ``started_at`` rather than an offset. This table only
grows, and an offset scan gets slower the further back you look while also
skipping or repeating rows when new entries arrive mid-read.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Request
from fastapi.responses import Response
from sqlalchemy import select

from app.core.templating import render
from app.models import DiagnosticResult, DiscoveryRun
from app.modules.auth.dependencies import ActiveUser, SessionDep
from app.modules.diagnostics import service as diagnostics_service

logger = logging.getLogger("netops.audit")

router = APIRouter(tags=["audit"])

PAGE_SIZE = 50


@dataclass(frozen=True)
class AuditEntry:
    """One row of the timeline, whatever it came from."""

    kind: Literal["diagnostic", "discovery"]
    when: datetime
    action: str
    target: str
    status: str
    detail: str
    username: str | None
    client_ip: str | None
    duration_ms: int | None
    link: str | None = None


def _from_diagnostic(result: DiagnosticResult) -> AuditEntry:
    spec = diagnostics_service.REGISTRY.get(result.type)
    return AuditEntry(
        kind="diagnostic",
        when=result.started_at,
        action=spec.label if spec else result.type,
        target=result.target,
        status=result.status,
        detail=diagnostics_service.result_summary(result),
        username=result.username_snapshot,
        client_ip=result.client_ip,
        duration_ms=result.duration_ms,
        link=f"/diagnostics/{result.id}",
    )


def _from_run(run: DiscoveryRun) -> AuditEntry:
    return AuditEntry(
        kind="discovery",
        when=run.started_at,
        action="Discovery scan",
        target=run.subnet,
        status=run.status,
        detail=run.output_summary or "",
        username=run.username_snapshot,
        client_ip=run.client_ip,
        duration_ms=run.duration_ms,
    )


@router.get("/audit")
async def audit_log(
    request: Request,
    session: SessionDep,
    user: ActiveUser,
    before: str = "",
    kind: str = "",
) -> Response:
    """Combined, newest-first timeline."""
    cursor: datetime | None = None
    if before:
        try:
            cursor = datetime.fromisoformat(before)
            if cursor.tzinfo is None:
                cursor = cursor.replace(tzinfo=UTC)
        except ValueError:
            # A malformed cursor shows the first page rather than an error;
            # it is a position in a list, not a security boundary.
            cursor = None

    entries: list[AuditEntry] = []

    # Both sources are over-fetched by a page and merged, because either could
    # supply the whole of the next page on its own.
    # Separate names per query: reusing one loses the row type and lets a
    # mismatched converter through unnoticed.
    if kind in ("", "diagnostic"):
        diagnostics = select(DiagnosticResult).order_by(DiagnosticResult.started_at.desc())
        if cursor:
            diagnostics = diagnostics.where(DiagnosticResult.started_at < cursor)
        entries += [
            _from_diagnostic(row) for row in await session.scalars(diagnostics.limit(PAGE_SIZE + 1))
        ]

    if kind in ("", "discovery"):
        runs = select(DiscoveryRun).order_by(DiscoveryRun.started_at.desc())
        if cursor:
            runs = runs.where(DiscoveryRun.started_at < cursor)
        entries += [_from_run(row) for row in await session.scalars(runs.limit(PAGE_SIZE + 1))]

    entries.sort(key=lambda entry: entry.when, reverse=True)
    page = entries[:PAGE_SIZE]
    has_more = len(entries) > PAGE_SIZE

    return render(
        request,
        "audit.html",
        {
            "entries": page,
            "kind": kind,
            "has_more": has_more,
            "next_cursor": page[-1].when.isoformat() if page and has_more else None,
        },
    )
