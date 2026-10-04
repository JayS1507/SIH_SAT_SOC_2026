from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

from openpyxl import load_workbook

MAX_COLUMNS = 200
MAX_SQL_STATEMENTS = 10_000


class IngestionError(ValueError):
    pass


def _lineage(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{**record, "_row": index} for index, record in enumerate(records, 1)]


def ingest_bytes(filename: str, content: bytes) -> tuple[list[dict[str, Any]], str]:
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    try:
        if suffix == "json":
            value = json.loads(content.decode("utf-8"))
            records = _json_records(value)
            if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
                raise IngestionError("JSON must contain an array of objects or a supported database export")
        elif suffix == "csv":
            text = content.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames or len(reader.fieldnames) > MAX_COLUMNS:
                raise IngestionError("CSV has too many columns or no header")
            records = list(reader)
        elif suffix in {"xlsx", "xlsm"}:
            workbook = load_workbook(io.BytesIO(content), read_only=True, data_only=True)
            sheet = workbook.active
            rows = sheet.iter_rows(values_only=True)
            headers = [str(value).strip() if value is not None else "" for value in next(rows, ())]
            if not headers or len(headers) > MAX_COLUMNS or any(not header for header in headers):
                raise IngestionError("XLSX must have a non-empty header row")
            records = [dict(zip(headers, values)) for values in rows]
        elif suffix in {"sql", "dump"}:
            records = parse_sql_export(content)
        else:
            raise IngestionError("Supported uploads are JSON, CSV, XLSX, SQL, and PostgreSQL dump exports")
    except (UnicodeDecodeError, json.JSONDecodeError, csv.Error, StopIteration) as exc:
        raise IngestionError(f"Invalid {suffix.upper()} file: {exc}") from exc
    return _lineage(records), suffix


def parse_pasted_logs(content: str) -> list[dict[str, Any]]:
    """Parse offline pasted JSON-lines or conservative key=value log lines."""
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    if not lines:
        raise IngestionError("Pasted logs are empty")
    records: list[dict[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError
            records.append(value)
            continue
        except (json.JSONDecodeError, ValueError):
            pass
        matches = re.findall(r'([A-Za-z_][\w.-]*)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))', line)
        normalized = {key: next(value for value in values if value != "") for key, *values in matches}
        if not normalized:
            raise IngestionError("Each pasted log line must be a JSON object or key=value fields")
        records.append(normalized)
    return _lineage(records)


def _json_records(value: Any) -> Any:
    """Adapt common database exports without connecting to an external database."""
    if isinstance(value, list):
        return value
    if not isinstance(value, dict):
        return None
    for key in ("records", "rows", "data"):
        candidate = value.get(key)
        if isinstance(candidate, list):
            return candidate
    tables = value.get("tables")
    if isinstance(tables, dict):
        flattened: list[dict[str, Any]] = []
        for table, rows in tables.items():
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                return None
            flattened.extend({**row, "_table": table} for row in rows)
        return flattened
    return None


def adapt_database_export(value: Any) -> list[dict[str, Any]]:
    """Return records from a JSON database export.

    This is intentionally a file adapter: PostgreSQL connection/SQL dump
    ingestion is not attempted in the offline prototype.
    """
    records = _json_records(value)
    if not isinstance(records, list) or not all(isinstance(row, dict) for row in records):
        raise IngestionError("Database export must contain records, rows, data, or tables")
    return records


def _split_sql_values(value_text: str) -> list[str]:
    values, start, quote, depth, i = [], 0, None, 0, 0
    while i < len(value_text):
        char = value_text[i]
        if quote:
            if char == quote:
                if i + 1 < len(value_text) and value_text[i + 1] == quote:
                    i += 1
                else:
                    quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            values.append(value_text[start:i].strip())
            start = i + 1
        i += 1
    values.append(value_text[start:].strip())
    if quote or depth:
        raise IngestionError("Malformed SQL value list")
    return values


def _sql_value(token: str) -> Any:
    token = token.strip()
    if token.upper() == "NULL":
        return None
    if token.upper() in {"TRUE", "FALSE"}:
        return token.upper() == "TRUE"
    if len(token) >= 2 and token[0] == "'" and token[-1] == "'":
        return token[1:-1].replace("''", "'").replace("\\'", "'")
    if re.fullmatch(r"-?\d+", token):
        return int(token)
    if re.fullmatch(r"-?(?:\d+\.\d*|\.\d+)(?:[eE][+-]?\d+)?", token):
        return float(token)
    # Expressions, bytea, and subqueries are deliberately not executable.
    raise IngestionError("SQL export contains an unsupported expression")


def parse_sql_export(content: bytes) -> list[dict[str, Any]]:
    """Parse only plain PostgreSQL INSERT rows and COPY CSV blocks.

    DDL, functions, arbitrary expressions, and binary/custom pg_dump formats are
    rejected; this function never sends SQL to a database.
    """
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IngestionError("SQL export must be UTF-8 text") from exc
    records: list[dict[str, Any]] = []
    statements = 0
    lines = text.splitlines()
    i = 0
    insert_re = re.compile(
        r"^\s*INSERT\s+INTO\s+(?:\"?([\w.]+)\"?)\s*\(([^)]*)\)\s*VALUES\s*(.+?)\s*;\s*$",
        re.IGNORECASE | re.DOTALL,
    )
    copy_re = re.compile(
        r"^\s*COPY\s+(?:\"?([\w.]+)\"?)\s*\(([^)]*)\)\s+FROM\s+STDIN\s*;\s*$",
        re.IGNORECASE,
    )
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("--"):
            i += 1
            continue
        match = copy_re.match(line)
        if match:
            statements += 1
            if statements > MAX_SQL_STATEMENTS:
                raise IngestionError("SQL export exceeds the statement limit")
            table, columns = match.groups()
            columns = [c.strip().strip('"') for c in columns.split(",")]
            i += 1
            reader_lines = []
            while i < len(lines) and lines[i].strip() != r"\.":
                reader_lines.append(lines[i])
                i += 1
            if i == len(lines):
                raise IngestionError("COPY block is missing its terminator")
            for row in csv.reader(reader_lines):
                if len(row) != len(columns):
                    raise IngestionError("COPY row does not match its column count")
                records.append({**dict(zip(columns, row)), "_table": table})
            i += 1
            continue
        match = insert_re.match(line)
        if match:
            statements += 1
            if statements > MAX_SQL_STATEMENTS:
                raise IngestionError("SQL export exceeds the statement limit")
            table, columns_text, values_text = match.groups()
            columns = [c.strip().strip('"') for c in columns_text.split(",")]
            # Values are a sequence of parenthesized rows.
            for row_text in re.findall(r"\(([^()]*)\)", values_text):
                values = _split_sql_values(row_text)
                if len(values) != len(columns):
                    raise IngestionError("INSERT row does not match its column count")
                records.append({**dict(zip(columns, map(_sql_value, values))), "_table": table})
            i += 1
            continue
        raise IngestionError("SQL export contains unsupported statements; only INSERT and COPY are allowed")
    return records
