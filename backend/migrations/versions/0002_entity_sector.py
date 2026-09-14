"""add entity registry and sector

Revision ID: 0002_entity_sector
Revises: 0001_initial
"""

import json

from alembic import op
import sqlalchemy as sa


revision = "0002_entity_sector"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def _entity_from_row(row: dict) -> tuple[str, str, str | None] | None:
    entity_id = str(
        row.get("entity_id") or row.get("entity") or row.get("user") or row.get("host") or ""
    ).strip()
    if not entity_id:
        return None
    name = str(row.get("entity_name") or row.get("name") or entity_id).strip() or entity_id
    sector_value = row.get("sector") or row.get("entity_sector") or row.get("sector_name")
    sector = str(sector_value).strip() if sector_value else None
    return entity_id, name, sector


def upgrade():
    op.create_table(
        "entities",
        sa.Column("id", sa.String(200), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("sector", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_entities_sector", "entities", ["sector"])

    bind = op.get_bind()
    entities: dict[str, dict[str, str | None]] = {}
    for payload, in bind.execute(sa.text("SELECT payload FROM submissions")):
        try:
            submission = json.loads(payload)
        except (TypeError, json.JSONDecodeError):
            continue
        for row in submission.get("records", []):
            if not isinstance(row, dict):
                continue
            parsed = _entity_from_row(row)
            if parsed is None:
                continue
            entity_id, name, sector = parsed
            current = entities.setdefault(entity_id, {"name": entity_id, "sector": None})
            if current["name"] == entity_id and name != entity_id:
                current["name"] = name
            if current["sector"] is None and sector is not None:
                current["sector"] = sector
    for entity_id in sorted(entities):
        metadata = entities[entity_id]
        bind.execute(
            sa.text(
                "INSERT INTO entities (id, name, sector) VALUES (:id, :name, :sector)"
            ),
            {"id": entity_id, "name": metadata["name"], "sector": metadata["sector"]},
        )


def downgrade():
    op.drop_index("ix_entities_sector", table_name="entities")
    op.drop_table("entities")
