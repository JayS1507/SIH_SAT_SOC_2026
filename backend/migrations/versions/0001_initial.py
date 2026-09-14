"""initial schema

Revision ID: 0001_initial
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("submissions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("source", sa.String(100), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(20), nullable=False, server_default="1.0"))
    op.create_table("assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("submission_id", sa.String(36), sa.ForeignKey("submissions.id"), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(20), nullable=False, server_default="1.0"))
    op.create_index("ix_assessments_submission_id", "assessments", ["submission_id"])
    op.create_table("findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False))
    op.create_index("ix_findings_assessment_id", "findings", ["assessment_id"])
    op.create_table("reviews",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_index("ix_reviews_assessment_id", "reviews", ["assessment_id"])
    op.create_table("schema_metadata",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.String(200), nullable=False))

def downgrade():
    op.drop_table("schema_metadata")
    op.drop_index("ix_reviews_assessment_id", table_name="reviews")
    op.drop_table("reviews")
    op.drop_index("ix_findings_assessment_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_assessments_submission_id", table_name="assessments")
    op.drop_table("assessments")
    op.drop_table("submissions")
