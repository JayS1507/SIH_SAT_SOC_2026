import io

import pytest
from openpyxl import Workbook

try:
    from backend.app.ingestion import IngestionError, ingest_bytes, parse_pasted_logs
except ModuleNotFoundError:
    from app.ingestion import IngestionError, ingest_bytes, parse_pasted_logs


def test_json_ingestion_adds_source_row_lineage() -> None:
    records, source = ingest_bytes("events.json", b'[{"entity_id":"alice"}]')
    assert source == "json"
    assert records == [{"entity_id": "alice", "_row": 1}]


def test_xlsx_ingestion_reads_header_and_values() -> None:
    workbook = Workbook()
    sheet = workbook.active
    sheet.append(["entity_id", "timestamp"])
    sheet.append(["bob", "2026-01-01"])
    stream = io.BytesIO()
    workbook.save(stream)

    records, source = ingest_bytes("events.xlsx", stream.getvalue())
    assert source == "xlsx"
    assert records[0]["entity_id"] == "bob"
    assert records[0]["_row"] == 1


def test_ingestion_rejects_unsupported_format() -> None:
    with pytest.raises(IngestionError, match="Supported uploads"):
        ingest_bytes("events.txt", b"data")


def test_pasted_logs_support_json_lines_and_key_value_lines() -> None:
    records = parse_pasted_logs(
        '{"entity_id":"e1","alert_id":"a1","severity":"critical"}\n'
        "entity_id=e2 alert_id=a2 severity=high"
    )
    assert records[0]["entity_id"] == "e1"
    assert records[1]["severity"] == "high"
