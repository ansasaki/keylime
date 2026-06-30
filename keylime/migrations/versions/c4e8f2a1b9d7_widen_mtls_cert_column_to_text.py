"""Widen mtls_cert column from String(2048) to Text

Revision ID: c4e8f2a1b9d7
Revises: a59cc9366774
Create Date: 2026-06-30 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "c4e8f2a1b9d7"
down_revision = "a59cc9366774"
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


def upgrade_cloud_verifier():
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.alter_column(
            "mtls_cert",
            existing_type=sa.String(2048),
            type_=sa.Text().with_variant(sa.Text(429400000), "mysql"),
            existing_nullable=True,
        )


def downgrade_cloud_verifier():
    with op.batch_alter_table("verifiermain") as batch_op:
        batch_op.alter_column(
            "mtls_cert",
            existing_type=sa.Text().with_variant(sa.Text(429400000), "mysql"),
            type_=sa.String(2048),
            existing_nullable=True,
        )
