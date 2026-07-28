"""diagnostic results

Revision ID: 0752c657ca29
Revises: 50e718c1643d
Created: 2026-07-28 03:16:30.689911+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0752c657ca29"
down_revision: str | None = "50e718c1643d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "diagnostic_result",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("device_label_snapshot", sa.String(length=255), nullable=True),
        sa.Column("username_snapshot", sa.String(length=64), nullable=True),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.Column("type", sa.String(length=16), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        sa.Column("params_redacted", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("packet_loss_pct", sa.Float(), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "status IN ('success', 'failed', 'timeout', 'rejected', 'busy')",
            name="ck_diagnostic_status",
        ),
        sa.CheckConstraint(
            "type IN ('ping', 'traceroute', 'dns', 'rdns', 'tcp', 'service_scan', 'arp', 'http_check')",
            name="ck_diagnostic_type",
        ),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("diagnostic_result", schema=None) as batch_op:
        batch_op.create_index(
            "ix_diagnostic_device_started", ["device_id", "started_at"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_diagnostic_result_started_at"), ["started_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("diagnostic_result", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_diagnostic_result_started_at"))
        batch_op.drop_index("ix_diagnostic_device_started")

    op.drop_table("diagnostic_result")
