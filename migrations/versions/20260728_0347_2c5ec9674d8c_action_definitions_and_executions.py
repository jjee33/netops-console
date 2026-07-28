"""action definitions and executions

Revision ID: 2c5ec9674d8c
Revises: 0752c657ca29
Created: 2026-07-28 03:47:02.454198+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "2c5ec9674d8c"
down_revision: str | None = "0752c657ca29"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "action_definition",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("execution_type", sa.String(length=8), nullable=False),
        sa.Column("argv_template", sa.JSON(), nullable=False),
        sa.Column("param_schema", sa.JSON(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("confirmation_required", sa.Boolean(), nullable=False),
        sa.Column("elevated_required", sa.Boolean(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("applicable_types", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint("execution_type IN ('local','ssh')", name="ck_action_execution_type"),
        sa.CheckConstraint("timeout_seconds > 0", name="ck_action_timeout_positive"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "action_execution",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("action_definition_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("device_label_snapshot", sa.String(length=255), nullable=True),
        sa.Column("action_name_snapshot", sa.String(length=128), nullable=True),
        sa.Column("username_snapshot", sa.String(length=64), nullable=True),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.Column("params_redacted", sa.JSON(), nullable=True),
        sa.Column("command_preview", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("stdout", sa.Text(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "status IN ('running', 'success', 'failed', 'timeout', 'rejected', 'busy')",
            name="ck_action_execution_status",
        ),
        sa.ForeignKeyConstraint(
            ["action_definition_id"], ["action_definition.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("action_execution", schema=None) as batch_op:
        batch_op.create_index(
            "ix_action_execution_device_started", ["device_id", "started_at"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_action_execution_started_at"), ["started_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("action_execution", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_action_execution_started_at"))
        batch_op.drop_index("ix_action_execution_device_started")

    op.drop_table("action_execution")
    op.drop_table("action_definition")
