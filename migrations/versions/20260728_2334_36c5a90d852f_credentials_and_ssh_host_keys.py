"""credentials and ssh host keys

Revision ID: 36c5a90d852f
Revises: 2c5ec9674d8c
Created: 2026-07-28 23:34:03.849053+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "36c5a90d852f"
down_revision: str | None = "2c5ec9674d8c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "credential",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("auth_type", sa.String(length=16), nullable=False),
        sa.Column("secret_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("passphrase_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("key_fingerprint", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("auth_type IN ('ssh_key','password')", name="ck_credential_auth_type"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "device_credential",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("credential_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["credential_id"], ["credential.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "credential_id", name="uq_device_credential"),
    )
    with op.batch_alter_table("device_credential", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_device_credential_credential_id"), ["credential_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_device_credential_device_id"), ["device_id"], unique=False
        )

    op.create_table(
        "ssh_host_key",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=False),
        sa.Column("key_type", sa.String(length=32), nullable=False),
        sa.Column("key_base64", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column(
            "trusted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("trusted_by_user_id", sa.Integer(), nullable=True),
        sa.Column("trusted_by_snapshot", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["trusted_by_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "key_type", name="uq_host_key_device_type"),
    )
    with op.batch_alter_table("ssh_host_key", schema=None) as batch_op:
        batch_op.create_index("ix_ssh_host_key_device", ["device_id"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("ssh_host_key", schema=None) as batch_op:
        batch_op.drop_index("ix_ssh_host_key_device")

    op.drop_table("ssh_host_key")
    with op.batch_alter_table("device_credential", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_device_credential_device_id"))
        batch_op.drop_index(batch_op.f("ix_device_credential_credential_id"))

    op.drop_table("device_credential")
    op.drop_table("credential")
