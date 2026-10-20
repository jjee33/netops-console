"""discovery observations and change events

Revision ID: 4cdd051ae46a
Revises: 36c5a90d852f
Created: 2026-10-20 03:28:43.580189+00:00

Additive only: two new tables and one nullable column. Existing rows are not
rewritten, so the upgrade is fast on any database size.

Runs recorded before this revision have no observations and ``scanned_ports``
NULL. The UI says so ("recorded before per-host history existed") rather than
presenting them as empty scans.

Downgrading drops the per-host scan history and the change log. Nothing else is
touched, but that history cannot be recovered afterwards except from a backup.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "4cdd051ae46a"
down_revision: str | None = "36c5a90d852f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "change_event",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("device_label_snapshot", sa.String(length=255), nullable=True),
        sa.Column("subject", sa.String(length=255), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("username_snapshot", sa.String(length=64), nullable=True),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.CheckConstraint(
            "kind IN ('device_edited', 'device_removed', 'host_key_trusted', 'host_key_revoked', 'credential_created', 'credential_deleted', 'credential_assigned', 'credential_unassigned', 'action_created', 'action_enabled', 'action_disabled', 'action_deleted', 'settings_changed')",
            name="ck_change_event_kind",
        ),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("change_event", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_change_event_created_at"), ["created_at"], unique=False
        )
        batch_op.create_index(
            "ix_change_event_device_created", ["device_id", "created_at"], unique=False
        )

    op.create_table(
        "discovery_observation",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("run_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("present", sa.Boolean(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("mac_address", sa.String(length=17), nullable=True),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("vendor", sa.String(length=255), nullable=True),
        sa.Column("ports", sa.JSON(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["run_id"], ["discovery_run.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("discovery_observation", schema=None) as batch_op:
        batch_op.create_index(
            "ix_observation_device_observed", ["device_id", "observed_at"], unique=False
        )
        batch_op.create_index("ix_observation_run", ["run_id"], unique=False)

    with op.batch_alter_table("discovery_run", schema=None) as batch_op:
        batch_op.add_column(sa.Column("scanned_ports", sa.Boolean(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("discovery_run", schema=None) as batch_op:
        batch_op.drop_column("scanned_ports")

    with op.batch_alter_table("discovery_observation", schema=None) as batch_op:
        batch_op.drop_index("ix_observation_run")
        batch_op.drop_index("ix_observation_device_observed")

    op.drop_table("discovery_observation")
    with op.batch_alter_table("change_event", schema=None) as batch_op:
        batch_op.drop_index("ix_change_event_device_created")
        batch_op.drop_index(batch_op.f("ix_change_event_created_at"))

    op.drop_table("change_event")
