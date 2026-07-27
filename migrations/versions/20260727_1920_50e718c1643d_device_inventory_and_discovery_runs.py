"""device inventory and discovery runs

Revision ID: 50e718c1643d
Revises: e04d6d07594e
Created: 2026-07-27 19:20:28.014310+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "50e718c1643d"
down_revision: str | None = "e04d6d07594e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "device",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("mac_address", sa.String(length=17), nullable=True),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("device_type", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "first_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("avg_latency_ms", sa.Float(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "status IN ('online','offline','unknown','warning')", name="ck_device_status"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("device", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_device_ip_address"), ["ip_address"], unique=False)
        batch_op.create_index(batch_op.f("ix_device_is_deleted"), ["is_deleted"], unique=False)
        batch_op.create_index(batch_op.f("ix_device_mac_address"), ["mac_address"], unique=False)
        batch_op.create_index("ix_device_status_deleted", ["status", "is_deleted"], unique=False)

    op.create_table(
        "device_port",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=3), nullable=False),
        sa.Column("service", sa.String(length=64), nullable=True),
        sa.Column("state", sa.String(length=8), nullable=False),
        sa.Column(
            "last_seen",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.CheckConstraint("protocol IN ('tcp','udp')", name="ck_port_protocol"),
        sa.CheckConstraint("state IN ('open','filtered','closed')", name="ck_port_state"),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "port", "protocol", name="uq_device_port"),
    )
    with op.batch_alter_table("device_port", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_device_port_device_id"), ["device_id"], unique=False)

    op.create_table(
        "discovery_run",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("subnet", sa.String(length=45), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username_snapshot", sa.String(length=64), nullable=True),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("devices_found", sa.Integer(), nullable=False),
        sa.Column("devices_new", sa.Integer(), nullable=False),
        sa.Column("output_summary", sa.Text(), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.CheckConstraint(
            "status IN ('running','success','failed','timeout','rejected')",
            name="ck_discovery_run_status",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("discovery_run", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_discovery_run_started_at"), ["started_at"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("discovery_run", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_discovery_run_started_at"))

    op.drop_table("discovery_run")
    with op.batch_alter_table("device_port", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_device_port_device_id"))

    op.drop_table("device_port")
    with op.batch_alter_table("device", schema=None) as batch_op:
        batch_op.drop_index("ix_device_status_deleted")
        batch_op.drop_index(batch_op.f("ix_device_mac_address"))
        batch_op.drop_index(batch_op.f("ix_device_is_deleted"))
        batch_op.drop_index(batch_op.f("ix_device_ip_address"))

    op.drop_table("device")
