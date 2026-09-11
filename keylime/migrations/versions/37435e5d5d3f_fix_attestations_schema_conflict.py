"""Fix attestations table schema conflict and nullable constraint

On databases where the legacy VerifierAttestations declarative class
created the attestations table via create_all() before migration
870c218abd9a ran, the table has old-schema columns (boottime, status,
nonce, etc.) instead of the v3 columns. This migration detects that
case, drops the legacy table, and recreates it with the correct schema.

For databases where 870c218abd9a already ran correctly, this migration
fixes system_info__boot_time from NOT NULL to nullable, matching the
model definition (boot_time may not be available at INSERT time).

Revision ID: 37435e5d5d3f
Revises: c4e8f2a1b9d7
Create Date: 2026-09-11

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "37435e5d5d3f"
down_revision = "c4e8f2a1b9d7"
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()[f"upgrade_{engine_name}"]()


def downgrade(engine_name):
    globals()[f"downgrade_{engine_name}"]()


def upgrade_registrar():
    pass


def downgrade_registrar():
    pass


def _has_column(table_name, column_name):
    """Check if a column exists in a table."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = [c["name"] for c in inspector.get_columns(table_name)]
    return column_name in columns


def _table_exists(table_name):
    """Check if a table exists."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return table_name in inspector.get_table_names()


def upgrade_cloud_verifier():
    if not _table_exists("attestations"):
        # 870c218abd9a should have created it; nothing to fix
        return

    if _has_column("attestations", "stage"):
        # Table has v3 schema from 870c218abd9a — just fix nullable
        with op.batch_alter_table("attestations") as batch_op:
            batch_op.alter_column(
                "system_info__boot_time",
                nullable=True,
                existing_type=sa.String(32),
            )
    else:
        # Table has legacy schema from VerifierAttestations create_all()
        # — no v3 attestation data exists, safe to recreate
        op.drop_table("evidence_items", if_exists=True)
        op.drop_table("attestations")

        op.create_table(
            "attestations",
            sa.Column("agent_id", sa.String(80), sa.ForeignKey("verifiermain.agent_id"), nullable=False),
            sa.Column("index", sa.Integer, nullable=False),
            sa.Column("stage", sa.String(25), server_default="awaiting_evidence", nullable=False),
            sa.Column("evaluation", sa.String(10), server_default="pending", nullable=False),
            sa.Column("failure_reason", sa.String(25)),
            sa.Column("system_info__boot_time", sa.String(32), nullable=True),
            sa.Column("capabilities_received_at", sa.String(32), nullable=False),
            sa.Column("challenges_expire_at", sa.String(32)),
            sa.Column("evidence_received_at", sa.String(32)),
            sa.Column("verification_completed_at", sa.String(32)),
            sa.PrimaryKeyConstraint("agent_id", "index"),
        )

        op.create_table(
            "evidence_items",
            sa.Column("id", sa.Integer, nullable=False),
            sa.Column("agent_id", sa.String(80), nullable=False),
            sa.Column("attestation_index", sa.Integer, nullable=False),
            sa.Column("evidence_class", sa.String(20), nullable=False),
            sa.Column("evidence_type", sa.String(30), nullable=False),
            sa.Column("capabilities__component_version", sa.String(20)),
            sa.Column("capabilities__evidence_version", sa.String(20)),
            sa.Column("capabilities__signature_schemes", sa.Text),
            sa.Column("capabilities__hash_algorithms", sa.Text),
            sa.Column("capabilities__available_subjects", sa.Text),
            sa.Column("capabilities__certification_keys", sa.Text),
            sa.Column("capabilities__entry_count", sa.Integer),
            sa.Column("capabilities__supports_partial_access", sa.Boolean),
            sa.Column("capabilities__appendable", sa.Boolean),
            sa.Column("capabilities__formats", sa.Text),
            sa.Column("capabilities__meta", sa.Text),
            sa.Column("chosen_parameters__challenge", sa.LargeBinary),
            sa.Column("chosen_parameters__signature_scheme", sa.String(20)),
            sa.Column("chosen_parameters__hash_algorithm", sa.String(20)),
            sa.Column("chosen_parameters__selected_subjects", sa.Text),
            sa.Column("chosen_parameters__certification_key", sa.Text),
            sa.Column("chosen_parameters__starting_offset", sa.Integer),
            sa.Column("chosen_parameters__entry_count", sa.Integer),
            sa.Column("chosen_parameters__format", sa.String(255)),
            sa.Column("chosen_parameters__meta", sa.Text),
            sa.Column("data__subject_data", sa.Text),
            sa.Column("data__message", sa.LargeBinary),
            sa.Column("data__signature", sa.LargeBinary),
            sa.Column("data__entry_count", sa.Integer),
            sa.Column("data__entries", sa.Text),
            sa.Column("data__meta", sa.Text),
            sa.Column("results__certified_entry_count", sa.Integer),
            sa.Column("results__meta", sa.Text),
            sa.ForeignKeyConstraint(["agent_id", "attestation_index"], ["attestations.agent_id", "attestations.index"]),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade_cloud_verifier():
    # Only reverse the nullable change; cannot restore legacy schema
    if _table_exists("attestations") and _has_column("attestations", "stage"):
        with op.batch_alter_table("attestations") as batch_op:
            batch_op.alter_column(
                "system_info__boot_time",
                nullable=False,
                existing_type=sa.String(32),
            )
