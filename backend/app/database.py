from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import DateTime, ForeignKey, String, Text, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


# Serverless (Vercel) bundles are read-only; only /tmp is writable there and it
# is per-instance and ephemeral. Set DATABASE_URL (e.g. PostgreSQL) to persist.
ON_SERVERLESS = bool(os.getenv("VERCEL"))
DEFAULT_DATABASE_URL = ("sqlite:////tmp/soc_inspect.db" if ON_SERVERLESS else
                        f"sqlite:///{(Path(__file__).resolve().parents[2] / 'soc_inspect.db').as_posix()}")
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class SubmissionRow(Base):
    __tablename__ = "submissions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(String(100))
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    schema_version: Mapped[str] = mapped_column(String(20), default="1.0")


class AssessmentRow(Base):
    __tablename__ = "assessments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    submission_id: Mapped[str] = mapped_column(ForeignKey("submissions.id"), index=True)
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    schema_version: Mapped[str] = mapped_column(String(20), default="1.0")


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    payload: Mapped[str] = mapped_column(Text)


class ReviewRow(Base):
    __tablename__ = "reviews"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    assessment_id: Mapped[str] = mapped_column(ForeignKey("assessments.id"), index=True)
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SchemaMetadataRow(Base):
    __tablename__ = "schema_metadata"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(String(200))


class EntityRow(Base):
    __tablename__ = "entities"
    id: Mapped[str] = mapped_column(String(200), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    sector: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")
    )


class DeclarationRow(Base):
    """CSE self-assessment values (declared KPIs) for paper-vs-practice checks."""
    __tablename__ = "declarations"
    id: Mapped[str] = mapped_column(String(300), primary_key=True)
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


def persist_declarations(rows: list[dict[str, Any]], replace: bool = False) -> None:
    import json
    with SessionLocal.begin() as session:
        if replace:
            session.query(DeclarationRow).delete()
        for row in rows:
            session.merge(DeclarationRow(id=f"{row['entity_id']}|{row['metric']}",
                                         payload=json.dumps(row, default=str),
                                         created_at=datetime.fromisoformat(row["created_at"])))


def init_db() -> None:
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    for table, column in (("submissions", "schema_version"), ("assessments", "schema_version")):
        if table in inspector.get_table_names() and column not in {item["name"] for item in inspector.get_columns(table)}:
            with engine.begin() as connection:
                connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} VARCHAR(20) DEFAULT '1.0'"))
    with SessionLocal.begin() as session:
        session.merge(SchemaMetadataRow(key="schema_version", value="1.0"))
        session.merge(SchemaMetadataRow(key="migration_revision", value="prototype-001"))


def readiness_check() -> tuple[bool, str]:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True, "ok"
    except Exception:
        return False, "unavailable"


def persist_submission(item: dict[str, Any]) -> None:
    import json
    with SessionLocal.begin() as session:
        session.merge(SubmissionRow(
            id=item["id"], name=item["name"], source=item["source"],
            payload=json.dumps(item, default=str), created_at=datetime.fromisoformat(item["created_at"]),
            schema_version=str(item.get("metadata", {}).get("schema_version", "1.0")),
        ))
        entities: dict[str, dict[str, str | None]] = {}
        for row in item.get("records", []):
            entity_id = str(row.get("entity_id") or row.get("entity") or row.get("user") or row.get("host") or "").strip()
            if not entity_id:
                continue
            current = entities.setdefault(entity_id, {"name": entity_id, "sector": None})
            name = row.get("entity_name") or row.get("name")
            sector = row.get("sector") or row.get("entity_sector") or row.get("sector_name")
            if name and current["name"] == entity_id:
                current["name"] = str(name)
            if sector and current["sector"] is None:
                current["sector"] = str(sector)
        for entity_id in sorted(entities):
            metadata = entities[entity_id]
            existing = session.get(EntityRow, entity_id)
            if existing is None:
                session.add(EntityRow(id=entity_id, name=str(metadata["name"]), sector=metadata["sector"]))
            else:
                if existing.name == entity_id and metadata["name"] != entity_id:
                    existing.name = str(metadata["name"])
                if existing.sector is None and metadata["sector"] is not None:
                    existing.sector = str(metadata["sector"])


def persist_assessment(item: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    import json
    with SessionLocal.begin() as session:
        session.merge(AssessmentRow(
            id=item["id"], submission_id=item["submission_id"], payload=json.dumps(item, default=str),
            created_at=datetime.fromisoformat(item["created_at"]),
            schema_version="1.0",
        ))
        for finding in findings:
            session.merge(FindingRow(id=finding["id"], assessment_id=item["id"], payload=json.dumps(finding, default=str)))


def persist_review(review: dict[str, Any]) -> None:
    import json
    with SessionLocal.begin() as session:
        session.merge(ReviewRow(
            id=review["id"], assessment_id=review["assessment_id"], payload=json.dumps(review, default=str),
            created_at=datetime.fromisoformat(review["created_at"]),
        ))


def persist_audit_event(event: dict[str, Any]) -> None:
    import json
    with SessionLocal.begin() as session:
        session.merge(AuditEventRow(
            id=event["id"], payload=json.dumps(event, default=str),
            created_at=datetime.fromisoformat(event["timestamp"]),
        ))


def load_state(store: Any) -> None:
    import json
    with SessionLocal() as session:
        for row in session.query(SubmissionRow).all():
            store.submissions[row.id] = json.loads(row.payload)
        for row in session.query(AssessmentRow).all():
            store.assessments[row.id] = json.loads(row.payload)
        for row in session.query(FindingRow).all():
            store.findings.setdefault(row.assessment_id, []).append(json.loads(row.payload))
        for row in session.query(ReviewRow).all():
            store.reviews.append(json.loads(row.payload))
        if hasattr(store, "declarations"):
            for row in session.query(DeclarationRow).all():
                item = json.loads(row.payload)
                store.declarations[f"{item['entity_id']}|{item['metric']}"] = item
        if hasattr(store, "audit_events"):
            # Chronological order matters: audit events form a hash chain.
            seen = {item.get("id") for item in store.audit_events}
            for row in session.query(AuditEventRow).order_by(AuditEventRow.created_at).all():
                event = json.loads(row.payload)
                if event.get("id") not in seen:
                    seen.add(event.get("id"))
                    store.audit_events.append(event)


# Keep the offline demo usable even when an ASGI test client does not trigger
# lifespan events (the normal server still initializes this during startup).
def restore_demo_snapshot() -> bool:
    """On serverless cold start, unpack the bundled demo database into /tmp.

    Loading the snapshot takes ~1 s versus ~25 s to regenerate the dataset.
    Must run before anything creates the SQLite file.
    """
    if not (ON_SERVERLESS and DATABASE_URL == DEFAULT_DATABASE_URL
            and os.getenv("SEED_DEMO", "true") == "true"):
        return False
    import gzip
    import shutil
    target = Path(DATABASE_URL.removeprefix("sqlite:///"))
    snapshot = Path(__file__).resolve().parent / "seed" / "demo_snapshot.db.gz"
    if target.exists() or not snapshot.exists():
        return False
    partial = target.with_suffix(".partial")
    with gzip.open(snapshot, "rb") as src, partial.open("wb") as dst:
        shutil.copyfileobj(src, dst)
    partial.replace(target)
    return True


restore_demo_snapshot()

if os.getenv("ALEMBIC_RUNNING") != "1":
    init_db()
