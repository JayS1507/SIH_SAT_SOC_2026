"""Professional report rendering (JSON / HTML / PDF) for the supervisory assessment.

The sat_report endpoint builds a structured ``report`` dict; this module turns
that same dict into a print-ready HTML document or a paginated PDF via ReportLab.
"""

from __future__ import annotations

import html
import io
from typing import Any

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_STATUS_PALETTE = {
    "COMPLIANT": ("#1f7a56", "#e6f4ee"),
    "PARTIALLY_COMPLIANT": ("#a06a12", "#fdf3e3"),
    "NON_COMPLIANT": ("#b3261e", "#fde8e7"),
    "INSUFFICIENT_EVIDENCE": ("#6b7280", "#f0f1f3"),
    "NOT_ASSESSED": ("#6b7280", "#f0f1f3"),
}

_SEV_PALETTE = {
    "critical": ("#b3261e", "#fde8e7"),
    "high": ("#d97a2b", "#fdf0e4"),
    "medium": ("#a06a12", "#fdf3e3"),
    "low": ("#1f7a56", "#e6f4ee"),
}


def _fmt(value: Any) -> str:
    if value is None:
        return "—"
    return str(value)


def _pct(value: Any) -> str:
    if value is None:
        return "—"
    return f"{value}%"


def _metric_label(key: str) -> str:
    return key.replace("_", " ").title()


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

_HTML_CSS = """
* { box-sizing: border-box; }
body {
  font-family: 'Segoe UI', -apple-system, Roboto, Helvetica, Arial, sans-serif;
  color: #1a2332; margin: 0; padding: 0; background: #eef1f5; line-height: 1.5;
}
.page {
  max-width: 900px; margin: 24px auto; background: #ffffff;
  box-shadow: 0 1px 6px rgba(20, 40, 80, .12); border-radius: 6px; overflow: hidden;
}
.cover {
  background: linear-gradient(120deg, #0d2b45 0%, #123a5e 55%, #1c5d8f 100%);
  color: #ffffff; padding: 44px 48px 30px;
}
.cover .kicker { font-size: 12px; letter-spacing: .18em; text-transform: uppercase; opacity: .75; }
.cover h1 { margin: 10px 0 6px; font-size: 26px; font-weight: 600; }
.cover .sub { font-size: 14px; opacity: .92; }
.cover .meta { margin-top: 22px; border-top: 1px solid rgba(255,255,255,.25); padding-top: 14px; font-size: 12.5px; display: flex; flex-wrap: wrap; gap: 8px 28px;}
.cover .meta span b { font-weight: 600; margin-right: 5px; }
.content { padding: 14px 48px 40px; }
h2.sec {
  font-size: 17px; font-weight: 650; color: #0d2b45; margin: 30px 0 12px;
  padding-bottom: 6px; border-bottom: 2px solid #dce3ea;
  counter-increment: none;
}
h2.sec .n { display: inline-block; background: #0d2b45; color: #fff; border-radius: 4px;
  font-size: 12px; padding: 2px 8px; margin-right: 8px; vertical-align: 2px; letter-spacing: .04em; }
p { margin: 8px 0; font-size: 14px; }
.summary-box {
  background: #f4f7fa; border-left: 4px solid #1c5d8f; border-radius: 4px;
  padding: 14px 16px; font-size: 14px;
}
table { width: 100%; border-collapse: collapse; margin: 10px 0 6px; font-size: 13px; }
th { background: #0d2b45; color: #fff; text-align: left; font-weight: 600;
  padding: 8px 10px; font-size: 12px; letter-spacing: .02em; }
td { padding: 7px 10px; border-bottom: 1px solid #e3e8ee; vertical-align: top; }
tr:nth-child(even) td { background: #f7f9fb; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 20px; font-size: 11.5px; font-weight: 600; white-space: nowrap; }
ul { margin: 6px 0; padding-left: 22px; }
li { margin: 5px 0; font-size: 13.5px; }
.small { font-size: 12px; color: #5a6572; }
.muted { color: #5a6572; }
.method { background: #f4f7fa; border-radius: 4px; padding: 10px 14px; font-size: 12.5px; color: #3d4550; }
.hash { font-family: 'SFMono-Regular', Consolas, Menlo, monospace; font-size: 11.5px; word-break: break-all; }
.footer { border-top: 1px solid #dce3ea; margin-top: 30px; padding-top: 12px;
  font-size: 11.5px; color: #8493a3; text-align: center; }
@media print {
  body { background: #fff; }
  .page { box-shadow: none; margin: 0; border-radius: 0; max-width: 100%; }
  .cover { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  th, .badge { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
"""


def _badge(kind: str, value: str | int) -> str:
    label = str(value).lower()
    pal = _STATUS_PALETTE.get(str(value), _SEV_PALETTE.get(label, ("#44506a", "#eef1f5")))
    fg, bg = pal
    return f'<span class="badge" style="color:{fg};background:{bg};">{html.escape(str(value))}</span>'


def render_html(report: dict[str, Any]) -> str:
    """Render the report dict as a self-contained, print-ready HTML document."""
    dist = report.get("compliance_distribution", {})
    entities = report.get("entities", [])
    scope = report.get("assessment_scope", {})
    dataset = report.get("dataset", {})
    dq = report.get("data_quality", {})
    workflow = report.get("workflow", [])
    gaps = report.get("execution_gaps", [])
    neg = report.get("negative_space", [])
    actions = report.get("recommended_actions", [])

    e = html.escape

    # ---- Entity table -----------------------------------------------------
    def sev_cell(v):
        return _badge("sev", v) if v else e("—")

    ent_rows = "".join(
        "<tr>"
        f"<td>{_fmt(rd.get('rank', ''))}</td>"
        f"<td><b>{e(_fmt(rd.get('entity_name')))}</b><div class='muted small'>{e(_fmt(rd.get('entity_id')))}</div></td>"
        f"<td>{e(_fmt(rd.get('sector')))}</td>"
        f"<td>{_badge('status', rd.get('status'))}</td>"
        f"<td>{_pct(rd.get('compliance_score'))}</td>"
        f"<td>{_pct(rd.get('evidence_coverage'))}</td>"
        f"<td>{_fmt(rd.get('risk_score'))}</td>"
        f"<td>{sev_cell(rd.get('critical'))} {sev_cell(rd.get('high'))} {sev_cell(rd.get('medium'))} {sev_cell(rd.get('low'))}</td>"
        f"<td>{e(_fmt(rd.get('recommended_action')))}</td>"
        "</tr>" for rd in entities)

    # ---- Sector benchmark -------------------------------------------------
    sector_bench = report.get("sector_benchmark", {}) or {}
    bench_rows = ""
    for sector, metrics in sorted(sector_bench.items()):
        for metric, stats in sorted(metrics.items()):
            bench_rows += (
                f"<tr><td>{e(sector)}</td><td>{_metric_label(metric)}</td>"
                f"<td>{_pct(stats.get('median'))}</td><td>{_pct(stats.get('mean'))}</td>"
                f"<td>{_pct(stats.get('min'))} – {_pct(stats.get('max'))}</td></tr>"
            )

    # ---- Critical / high findings ----------------------------------------
    def finding_rows(items):
        if not items:
            return f"<tr><td colspan='4' class='muted'>No findings in this category.</td></tr>"
        return "".join(
            "<tr>"
            f"<td>{_badge('sev', f.get('severity'))}</td>"
            f"<td><b>{e(_fmt(f.get('title')))}</b><div class='muted small'>{e(_fmt(f.get('description')))}</div></td>"
            f"<td>{e(_fmt(f.get('entity_id')))}</td>"
            f"<td>{e(_fmt(f.get('rule')))}<div class='muted small'>evidence records: {_fmt(len(f.get('evidence') or []))}</div></td>"
            "</tr>" for f in items[:100])

    # ---- Execution gaps / negative space ---------------------------------
    def signal_rows(items):
        if not items:
            return f"<tr><td colspan='5' class='muted'>No items.</td></tr>"
        return "".join(
            "<tr>"
            f"<td>{_badge('sev', s.get('severity'))}</td>"
            f"<td>{e(_fmt(s.get('finding')))}<div class='muted small'>{e(_fmt(s.get('description')))}</div></td>"
            f"<td>{e(_fmt(s.get('entity_name')))}</td>"
            f"<td>{_fmt(s.get('affected_count'))}</td>"
            f"<td>{e(_fmt(s.get('expected_behavior')))}</td>"
            "</tr>" for s in items[:100])

    # ---- Workflow funnel --------------------------------------------------
    wf_rows = "".join(
        f"<tr><td>{e(_fmt(w.get('stage')))}</td><td>{_fmt(w.get('count'))}</td>"
        f"<td>{_pct(w.get('coverage_pct'))}</td><td>{_pct(w.get('of_alerts_pct'))}</td></tr>"
        for w in workflow)

    # ---- Data quality -----------------------------------------------------
    dq_rows = "".join(
        f"<tr><td>{e(v)}</td><td>{_pct(dq.get(k))}</td></tr>"
        for k, v in [("Completeness", "completeness"), ("Validity", "validity"),
                     ("Consistency", "consistency"), ("Uniqueness", "uniqueness"),
                     ("Timeliness", "timeliness")]
    )

    # ---- Recommended actions ---------------------------------------------
    act_rows = "".join(
        "<tr>"
        f"<td><b>{e(_fmt(a.get('entity_name')))}</b><div class='muted small'>{e(_fmt(a.get('entity_id')))}</div></td>"
        f"<td>{_badge('status', a.get('status'))}</td>"
        f"<td>{_fmt(a.get('risk'))}</td>"
        f"<td>{e(_fmt(a.get('action')))}</td>"
        "</tr>" for a in actions)

    # ---- Peer comparison --------------------------------------------------
    peer = report.get("peer_benchmark", {}) or {}
    peer_rows = ""
    for eid, em in sorted((peer.get("entities") or {}).items()):
        for metric, vals in sorted((em.get("peer_comparison") or {}).items()):
            peer_rows += (
                f"<tr><td><b>{e(_fmt(em.get('entity_name')))}</b></td>"
                f"<td>{_metric_label(metric)}</td>"
                f"<td>{_fmt(vals.get('value'))}</td>"
                f"<td>{_fmt(vals.get('peer_median'))}</td>"
                f"<td>{_fmt(vals.get('deviation'))}</td>"
                f"<td>{_pct(vals.get('percentile'))}</td></tr>"
            )

    limitations = report.get("limitations", [])
    crit = report.get("critical_findings", [])
    high = report.get("high_findings", [])
    extra = report.get("_findings") or []
    if extra:
        crit_ids = {id(f) for f in crit}
        high_ids = {id(f) for f in high}
        extra = [f for f in extra if id(f) not in crit_ids and id(f) not in high_ids][:100]
    extra_findings_html = (
        f"<h2 class='sec'><span class='n'>8.1</span>Other Findings (Medium / Low)</h2>"
        f"<table><tr><th>Severity</th><th>Finding</th><th>Entity</th><th>Rule / Evidence</th></tr>{finding_rows(extra)}</table>"
        + (f"<p class='small muted'>Report SHA-256: <span class='hash'>{e(_fmt(report.get('_report_sha256')))}</span> · "
           f"Dataset hash verified: {'yes' if report.get('_hash_verified') else 'no'}.</p>" if report.get("_report_sha256") else "")
        if extra else "")
    generated = report.get("assessment_timestamp") or dataset.get("generated_at") or ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(_fmt(report.get('title')))}</title>
<style>{_HTML_CSS}</style></head>
<body><div class="page">
  <div class="cover">
    <div class="kicker">Supervisory Assessment &nbsp;·&nbsp; Report</div>
    <h1>{e(_fmt(report.get('title')))}</h1>
    <div class="sub">Evidence-backed supervisory assessment of cybersecurity posture across assessed entities.</div>
    <div class="meta">
      <span><b>Period:</b>{e(_fmt(scope.get('period')))}</span>
      <span><b>Entity filter:</b>{e(_fmt(scope.get('entity_filter')) or 'All')}</span>
      <span><b>Sector filter:</b>{e(_fmt(scope.get('sector_filter')) or 'All')}</span>
      <span><b>Generated:</b>{e(_fmt(generated))}</span>
      <span><b>Rule version:</b>{e(_fmt(report.get('rule_version')))}</span>
      <span><b>Alert records:</b>{_fmt(dataset.get('records'))}</span>
    </div>
  </div>

  <div class="content">

    <h2 class="sec"><span class="n">1</span>Executive Summary</h2>
    <div class="summary-box">{e(_fmt(report.get('executive_summary')))}</div>

    <h2 class="sec"><span class="n">2</span>Assessment Scope</h2>
    <p><b>Assessment period:</b> {e(_fmt(scope.get('period')))}.&nbsp;
      <b>Entity filter:</b> {e(_fmt(scope.get('entity_filter')) or 'All')}.&nbsp;
      <b>Sector filter:</b> {e(_fmt(scope.get('sector_filter')) or 'All')}.</p>

    <h2 class="sec"><span class="n">3</span>Dataset &amp; Integrity</h2>
    <p>{_fmt(dataset.get('records'))} alert records were assessed under rule version
      <b>{e(_fmt(report.get('rule_version')))}</b>.</p>
    <table>
      <tr><th>Property</th><th>Value</th></tr>
      <tr><td>Alert records assessed</td><td>{_fmt(dataset.get('records'))}</td></tr>
      <tr><td>Dataset SHA-256</td><td class="hash">{e(_fmt(dataset.get('sha256')))}</td></tr>
      <tr><td>Rule version</td><td>{e(_fmt(report.get('rule_version')))}</td></tr>
      <tr><td>Generated (UTC)</td><td>{e(_fmt(generated))}</td></tr>
    </table>

    <h2 class="sec"><span class="n">4</span>Compliance Distribution</h2>
    <table>
      <tr><th>Status</th><th>Count</th></tr>
      <tr><td>{_badge('status', 'COMPLIANT')}</td><td>{_fmt(dist.get('COMPLIANT'))}</td></tr>
      <tr><td>{_badge('status', 'PARTIALLY_COMPLIANT')}</td><td>{_fmt(dist.get('PARTIALLY_COMPLIANT'))}</td></tr>
      <tr><td>{_badge('status', 'NON_COMPLIANT')}</td><td>{_fmt(dist.get('NON_COMPLIANT'))}</td></tr>
      <tr><td>{_badge('status', 'INSUFFICIENT_EVIDENCE')}</td><td>{_fmt(dist.get('INSUFFICIENT_EVIDENCE'))}</td></tr>
    </table>

    <h2 class="sec"><span class="n">5</span>Entity Assessments &amp; Recommended Actions</h2>
    <table>
      <tr><th>#</th><th>Entity</th><th>Sector</th><th>Status</th><th>Compliance</th>
        <th>Evidence</th><th>Risk</th><th>C/H/M/L Findings</th><th>Recommended action</th></tr>
      {ent_rows or f"<tr><td colspan='9' class='muted'>No entities in scope.</td></tr>"}
    </table>

    <h2 class="sec"><span class="n">6</span>Sector Benchmark (Median Coverage %)</h2>
    {f"<table><tr><th>Sector</th><th>Metric</th><th>Median</th><th>Mean</th><th>Range</th></tr>{bench_rows}</table>" if bench_rows else "<p class='muted'>No sector benchmark data available.</p>"}

    <h2 class="sec"><span class="n">7</span>Critical Findings</h2>
    <table><tr><th>Severity</th><th>Finding</th><th>Entity</th><th>Rule / Evidence</th></tr>{finding_rows(crit)}</table>

    <h2 class="sec"><span class="n">8</span>High Findings</h2>
    <table><tr><th>Severity</th><th>Finding</th><th>Entity</th><th>Rule / Evidence</th></tr>{finding_rows(high)}</table>

    {extra_findings_html}

    <h2 class="sec"><span class="n">9</span>Execution Gaps</h2>
    <table>
      <tr><th>Severity</th><th>Gap</th><th>Entity</th><th>Affected</th><th>Expected behaviour</th></tr>
      {signal_rows(gaps)}
    </table>

    <h2 class="sec"><span class="n">10</span>Missing Evidence &amp; Negative Space</h2>
    <table>
      <tr><th>Severity</th><th>Signal</th><th>Entity</th><th>Affected</th><th>Expected behaviour</th></tr>
      {signal_rows(neg)}
    </table>

    <h2 class="sec"><span class="n">11</span>Peer Comparison vs Sector Median</h2>
    {f"<table><tr><th>Entity</th><th>Metric</th><th>Value</th><th>Sector median</th><th>Deviation</th><th>Percentile</th></tr>{peer_rows}</table>" if peer_rows else "<p class='muted'>No peer comparison data in scope.</p>"}

    <h2 class="sec"><span class="n">12</span>Data Quality</h2>
    <p><b>Overall score:</b> {_pct(dq.get('overall'))}
      <span class="small muted">— {e(_fmt(dq.get('formula')))}</span></p>
    <table><tr><th>Dimension</th><th>Score</th></tr>{dq_rows}</table>
    <div class="small muted">Valid records {_fmt(dq.get('valid_records'))} · invalid {_fmt(dq.get('invalid_records'))} ·
      duplicates {_fmt(dq.get('duplicate_records'))} · missing mandatory fields {_fmt(dq.get('missing_mandatory'))}.</div>

    <h2 class="sec"><span class="n">13</span>Workflow Funnel</h2>
    <table>
      <tr><th>Stage</th><th>Count</th><th>Coverage (prev stage)</th><th>Share of alerts</th></tr>
      {wf_rows or f"<tr><td colspan='4' class='muted'>No workflow data.</td></tr>"}
    </table>

    <h2 class="sec"><span class="n">14</span>Recommended Actions</h2>
    <table>
      <tr><th>Entity</th><th>Status</th><th>Risk</th><th>Action</th></tr>
      {act_rows or f"<tr><td colspan='4' class='muted'>No actions.</td></tr>"}
    </table>

    <h2 class="sec"><span class="n">15</span>Methodology</h2>
    <div class="method">{e(_fmt(report.get('methodology')))}</div>

    <h2 class="sec"><span class="n">16</span>Limitations</h2>
    <ul>{"".join(f"<li>{e(_fmt(l))}</li>" for l in limitations) or "<li class='muted'>None stated.</li>"}</ul>
    {f"<p class='small muted'><b>Disclaimer:</b> {e(_fmt(report.get('disclaimer')))}</p>" if report.get("disclaimer") else ""}

    <div class="footer">
      Generated {e(_fmt(generated))} · Rule version {e(_fmt(report.get('rule_version')))} ·
      Dataset SHA-256 <span class="hash">{e(_fmt(report.get('dataset_hash')))}</span>
    </div>
  </div>
</div></body></html>"""


# ---------------------------------------------------------------------------
# PDF rendering (ReportLab)
# ---------------------------------------------------------------------------

def _pdf_text(value: Any) -> str:
    """Coerce a value to a single line of PDF-safe text."""
    text = _fmt(value).replace("\n", " ").replace("\r", " ").strip()
    out = []
    for ch in text:
        if ord(ch) < 128:
            out.append(ch)
        elif ch in ("—", "–", "·", "•", "’", "‘", "“", "”", "…"):
            out.append({"—": "-", "–": "-", "·": ".", "•": "-", "’": "'", "‘": "'",
                        "“": '"', "”": '"', "…": "..."}[ch])
        else:
            out.append("?")
    return "".join(out)


def render_pdf(report: dict[str, Any]) -> bytes:
    """Render the report dict as a professional, paginated PDF (ReportLab)."""
    try:
        return _render_pdf_reportlab(report)
    except Exception:
        # Fallback for environments without ReportLab: minimal single-page PDF.
        return _render_pdf_minimal(report)


def _render_pdf_minimal(report: dict[str, Any]) -> bytes:
    lines = [
        _pdf_text(report.get("title")),
        "=" * 60,
        _pdf_text(report.get("executive_summary")),
        "",
        f"Assessment period: {_pdf_text((report.get('assessment_scope') or {}).get('period'))}",
        f"Entities assessed: {len(report.get('entities') or [])}",
        f"Critical findings: {len(report.get('critical_findings') or [])}",
        f"High findings: {len(report.get('high_findings') or [])}",
        f"Execution gaps: {len(report.get('execution_gaps') or [])}",
        f"Rule version: {_pdf_text(report.get('rule_version'))}",
        f"Dataset SHA-256: {_pdf_text((report.get('dataset') or {}).get('sha256'))}",
        f"Generated: {_pdf_text(report.get('assessment_timestamp'))}",
        "",
        "Methodology:",
        _pdf_text(report.get("methodology")),
    ]
    if report.get("limitations"):
        lines += ["", "Limitations:"] + [f"- {_pdf_text(l)}" for l in report["limitations"]]
    text = "\\n".join(lines)
    stream = f"BT /F1 9 Tf 50 770 Td ({text.replace('(', '[').replace(')', ']')}) Tj ET".encode()
    return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj\n"
            b"4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n5 0 obj<</Length " +
            str(len(stream)).encode() + b">>stream\n" + stream +
            b"\nendstream\nendobj\ntrailer<</Root 1 0 R>>\n%%EOF")


def _render_pdf_reportlab(report: dict[str, Any]) -> bytes:
    """ReportLab rendering — the professional, paginated PDF implementation."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (BaseDocTemplate, Frame, PageTemplate, Paragraph,
                                    Spacer, Table, TableStyle)

    NAVY = colors.HexColor("#0d2b45")
    BLUE = colors.HexColor("#1c5d8f")
    GREY = colors.HexColor("#5a6572")
    LIGHT = colors.HexColor("#f4f7fa")
    BORDER = colors.HexColor("#c9d3dd")
    RED = colors.HexColor("#b3261e")
    AMBER = colors.HexColor("#a06a12")
    GREEN = colors.HexColor("#1f7a56")

    def status_color(status: str):
        return {
            "COMPLIANT": GREEN, "PARTIALLY_COMPLIANT": AMBER,
            "NON_COMPLIANT": RED, "INSUFFICIENT_EVIDENCE": GREY,
        }.get(str(status).upper()[:20], GREY)

    def sev_color(sev: str):
        return {
            "critical": RED, "high": colors.HexColor("#d97a2b"),
            "medium": AMBER, "low": GREEN,
        }.get(str(sev).lower(), GREY)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CoverTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=20, leading=24, textColor=colors.white, spaceAfter=6)
    kicker_style = ParagraphStyle(
        "Kicker", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=9, leading=12, textColor=colors.HexColor("#9fc2dd"),
        spaceAfter=4)
    sub_style = ParagraphStyle(
        "CoverSub", parent=styles["Normal"], fontName="Helvetica",
        fontSize=10.5, leading=15, textColor=colors.HexColor("#cfe0ee"))
    cover_meta_style = ParagraphStyle(
        "CoverMeta", parent=styles["Normal"], fontName="Helvetica",
        fontSize=8.5, leading=12, textColor=colors.HexColor("#eaf1f8"))
    h_style = ParagraphStyle(
        "Section", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=13, leading=16, textColor=NAVY, spaceBefore=14, spaceAfter=5,
        borderWidth=0)
    body = ParagraphStyle(
        "Body", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=9.5, leading=13.5, textColor=colors.HexColor("#1a2332"))
    small = ParagraphStyle(
        "Small", parent=body, fontSize=8, leading=11, textColor=GREY)
    th = ParagraphStyle(
        "TH", parent=body, fontName="Helvetica-Bold", fontSize=8, leading=10,
        textColor=colors.white)
    cell = ParagraphStyle(
        "Cell", parent=body, fontSize=8, leading=10.5)
    cell_b = ParagraphStyle(
        "CellB", parent=cell, fontName="Helvetica-Bold")

    meta_line = "&nbsp;&nbsp;|&nbsp;&nbsp;".join(
        f"<b>{_pdf_text(k)}:</b> {_pdf_text(v)}" for k, v in [
            ("Period", (report.get("assessment_scope") or {}).get("period")),
            ("Entity filter", (report.get("assessment_scope") or {}).get("entity_filter") or "All"),
            ("Sector filter", (report.get("assessment_scope") or {}).get("sector_filter") or "All"),
            ("Generated", report.get("assessment_timestamp") or (report.get("dataset") or {}).get("generated_at")),
            ("Rule version", report.get("rule_version")),
            ("Alert records", (report.get("dataset") or {}).get("records")),
        ])

    def section_header(num: int, title: str) -> Paragraph:
        return Paragraph(f"{num}.&nbsp;&nbsp;{_pdf_text(title)}", h_style)

    def make_table(headers: list[str], rows: list[list[Any]],
                   col_widths: list[float] | None = None,
                   aligns: list[str | None] | None = None) -> Table:
        data = [[Paragraph(f"<b>{_pdf_text(h)}</b>", th) for h in headers]]
        for row in rows:
            data.append([p if isinstance(p, Paragraph) else Paragraph(_pdf_text(p), cell) for p in row])
        t = Table(data, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]
        if aligns:
            for i, a in enumerate(aligns):
                if a:
                    style.append(("ALIGN", (i, 0), (i, -1), a))
        t.setStyle(TableStyle(style))
        return t

    flow: list[Any] = []

    # ---- Cover header ----
    cover = Table(
        [[Paragraph("SUPERVISORY ASSESSMENT &nbsp;·&nbsp; REPORT", kicker_style)],
         [Paragraph(_pdf_text(report.get("title")), title_style)],
         [Paragraph(_pdf_text(report.get("executive_summary")), sub_style)],
         [Paragraph(meta_line, cover_meta_style)]],
        colWidths=[A4[0] - 2 * 14 * mm])
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 18),
        ("RIGHTPADDING", (0, 0), (-1, -1), 18),
        ("TOPPADDING", (0, 0), (0, 2), 6),
        ("BOTTOMPADDING", (0, 0), (0, 2), 8),
        ("TOPPADDING", (0, 3), (0, 3), 12),
        ("BOTTOMPADDING", (0, 3), (0, 3), 10),
    ]))
    flow.append(cover)
    flow.append(Spacer(1, 4))

    scope = report.get("assessment_scope", {})
    dataset = report.get("dataset", {})
    dist = report.get("compliance_distribution", {})
    entities = report.get("entities", [])

    # ---- 1 Executive summary ----
    flow.append(section_header(1, "Executive Summary"))
    flow.append(Paragraph(_pdf_text(report.get("executive_summary")), body))

    # ---- 2 Scope ----
    flow.append(section_header(2, "Assessment Scope"))
    flow.append(Paragraph(
        f"Assessment period: <b>{_pdf_text(scope.get('period'))}</b>. "
        f"Entity filter: <b>{_pdf_text(scope.get('entity_filter') or 'All')}</b>. "
        f"Sector filter: <b>{_pdf_text(scope.get('sector_filter') or 'All')}</b>.", body))

    # ---- 3 Dataset & integrity ----
    flow.append(section_header(3, "Dataset & Integrity"))
    flow.append(make_table(
        ["Property", "Value"],
        [[Paragraph(_pdf_text(v), cell_b), Paragraph(_pdf_text(val), cell)]
         for v, val in [
             ("Alert records assessed", dataset.get("records")),
             ("Dataset SHA-256", dataset.get("sha256")),
             ("Rule version", report.get("rule_version")),
             ("Generated (UTC)", report.get("assessment_timestamp") or dataset.get("generated_at")),
         ]],
        col_widths=[45 * mm, 130 * mm]))

    # ---- 4 Compliance distribution ----
    flow.append(section_header(4, "Compliance Distribution"))
    dist_rows = []
    for status in ("COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE"):
        count = dist.get(status, 0)
        dist_rows.append([
            Paragraph(f'<font color="{status_color(status).hexval()}"><b>{status.replace("_", " ")}</b></font>', cell),
            Paragraph(str(count), cell)])
    flow.append(make_table(["Status", "Count"], dist_rows, col_widths=[100 * mm, 75 * mm]))

    # ---- 5 Entity assessments ----
    flow.append(section_header(5, "Entity Assessments & Recommended Actions"))
    ent_data = [[
        Paragraph(f'<b>{_pdf_text(r.get("rank"))}</b>', cell),
        Paragraph(f'<b>{_pdf_text(r.get("entity_name"))}</b><br/><font size="6.5" color="#5a6572">{_pdf_text(r.get("entity_id"))}</font>', cell),
        Paragraph(_pdf_text(r.get("sector")), cell),
        Paragraph(f'<font color="{status_color(r.get("status")).hexval()}"><b>{_pdf_text(r.get("status"))}</b></font>', cell),
        Paragraph(f'{_pdf_text(r.get("compliance_score"))}%', cell),
        Paragraph(f'{_pdf_text(r.get("evidence_coverage"))}%', cell),
        Paragraph(_pdf_text(r.get("risk_score")), cell),
        Paragraph(f'{" / ".join(str(r.get(k) or 0) for k in ("critical", "high", "medium", "low"))}', cell),
        Paragraph(_pdf_text(r.get("recommended_action")), cell),
    ] for r in entities]
    flow.append(make_table(
        ["#", "Entity", "Sector", "Status", "Comp", "Evid", "Risk", "C/H/M/L", "Recommended action"],
        ent_data, col_widths=[8 * mm, 34 * mm, 22 * mm, 30 * mm, 12 * mm, 12 * mm, 12 * mm, 20 * mm, 25 * mm]))

    # ---- 6 Sector benchmark ----
    flow.append(section_header(6, "Sector Benchmark (Median Coverage %)"))
    bench = report.get("sector_benchmark", {}) or {}
    bench_rows = []
    for sector, metrics in sorted(bench.items()):
        for metric, stats in sorted(metrics.items()):
            bench_rows.append([Paragraph(sector, cell), Paragraph(_metric_label(metric), cell),
                               Paragraph(f"{_pdf_text(stats.get('median'))}%", cell),
                               Paragraph(f"{_pdf_text(stats.get('mean'))}%", cell),
                               Paragraph(f"{_pdf_text(stats.get('min'))}% - {_pdf_text(stats.get('max'))}%", cell)])
    if bench_rows:
        flow.append(make_table(["Sector", "Metric", "Median", "Mean", "Range"], bench_rows,
                               col_widths=[40 * mm, 55 * mm, 20 * mm, 20 * mm, 40 * mm]))
    else:
        flow.append(Paragraph("<i>No sector benchmark data available.</i>", small))

    # ---- 7/8 Findings ----
    for num, sec_title in ((7, "Critical Findings"), (8, "High Findings")):
        flow.append(section_header(num, sec_title))
        items = report.get("critical_findings" if sec_title.startswith("Critical") else "high_findings", [])[:100]
        rows = []
        for f in items:
            rows.append([
                Paragraph(f'<font color="{sev_color(f.get("severity")).hexval()}"><b>{_pdf_text(f.get("severity")).upper()}</b></font>', cell),
                Paragraph(f'<b>{_pdf_text(f.get("title"))}</b><br/><font size="7" color="#5a6572">{_pdf_text(f.get("description"))}</font>', cell),
                Paragraph(_pdf_text(f.get("entity_id")), cell),
                Paragraph(f'{_pdf_text(f.get("rule"))}<br/><font size="7" color="#5a6572">evidence records: {len(f.get("evidence") or [])}</font>', cell),
            ])
        if not rows:
            flow.append(Paragraph("<i>No findings in this category.</i>", small))
        else:
            flow.append(make_table(["Severity", "Finding", "Entity", "Rule / Evidence"], rows,
                                   col_widths=[18 * mm, 90 * mm, 25 * mm, 42 * mm]))

        extra = report.get("_findings") or []
        if sec_title.startswith("Critical") and extra:
            crit = {id(f) for f in items}
            high = {id(f) for f in report.get("high_findings", [])[:100]}
            extra = [f for f in extra if id(f) not in crit and id(f) not in high][:100]
            if extra:
                flow.append(section_header(8.1, "Other Findings (Medium / Low)"))
                rows = [[
                    Paragraph(f'<font color="{sev_color(f.get("severity")).hexval()}"><b>{_pdf_text(f.get("severity")).upper()}</b></font>', cell),
                    Paragraph(f'<b>{_pdf_text(f.get("title"))}</b><br/><font size="7" color="#5a6572">{_pdf_text(f.get("description"))}</font>', cell),
                    Paragraph(_pdf_text(f.get("entity_id")), cell),
                    Paragraph(f'{_pdf_text(f.get("rule"))}<br/><font size="7" color="#5a6572">evidence records: {len(f.get("evidence") or [])}</font>', cell),
                ] for f in extra]
                flow.append(make_table(["Severity", "Finding", "Entity", "Rule / Evidence"], rows,
                                       col_widths=[18 * mm, 90 * mm, 25 * mm, 42 * mm]))
            if report.get("_report_sha256"):
                flow.append(Paragraph(
                    f"Report SHA-256: <font size='7' color='#5a6572'>{_pdf_text(report.get('_report_sha256'))}</font> · "
                    f"Dataset hash verified: {'yes' if report.get('_hash_verified') else 'no'}", small))

    # ---- 9/10 Execution gaps / negative space ----
    for num, sec_title in ((9, "Execution Gaps"), (10, "Missing Evidence & Negative Space")):
        flow.append(section_header(num, sec_title))
        items = report.get("execution_gaps" if sec_title == "Execution Gaps" else "negative_space", [])[:100]
        rows = []
        for s in items:
            rows.append([
                Paragraph(f'<font color="{sev_color(s.get("severity")).hexval()}"><b>{_pdf_text(s.get("severity")).upper()}</b></font>', cell),
                Paragraph(f'<b>{_pdf_text(s.get("finding"))}</b><br/><font size="7" color="#5a6572">{_pdf_text(s.get("description"))}</font>', cell),
                Paragraph(_pdf_text(s.get("entity_name")), cell),
                Paragraph(_pdf_text(s.get("affected_count")), cell),
                Paragraph(_pdf_text(s.get("expected_behavior")), cell),
            ])
        if not rows:
            flow.append(Paragraph("<i>No items.</i>", small))
        else:
            flow.append(make_table(["Severity", "Signal", "Entity", "Affected", "Expected behaviour"], rows,
                                   col_widths=[17 * mm, 70 * mm, 28 * mm, 15 * mm, 45 * mm]))

    # ---- 11 Peer comparison ----
    flow.append(section_header(11, "Peer Comparison vs Sector Median"))
    peer = report.get("peer_benchmark", {}) or {}
    peer_rows = []
    for eid, em in sorted((peer.get("entities") or {}).items()):
        for metric, vals in sorted((em.get("peer_comparison") or {}).items()):
            peer_rows.append([Paragraph(_pdf_text(em.get("entity_name")), cell),
                              Paragraph(_metric_label(metric), cell),
                              Paragraph(_pdf_text(vals.get("value")), cell),
                              Paragraph(_pdf_text(vals.get("peer_median")), cell),
                              Paragraph(_pdf_text(vals.get("deviation")), cell),
                              Paragraph(f"{_pdf_text(vals.get('percentile'))}%", cell)])
    if peer_rows:
        flow.append(make_table(["Entity", "Metric", "Value", "Sector median", "Deviation", "Percentile"], peer_rows,
                               col_widths=[38 * mm, 40 * mm, 25 * mm, 30 * mm, 22 * mm, 20 * mm]))
    else:
        flow.append(Paragraph("<i>No peer comparison data in scope.</i>", small))

    # ---- 12 Data quality ----
    flow.append(section_header(12, "Data Quality"))
    dq = report.get("data_quality", {})
    flow.append(Paragraph(
        f"Overall score: <b>{_pdf_text(dq.get('overall'))}%</b> "
        f"(<font size=\"7.5\" color=\"#5a6572\">{_pdf_text(dq.get('formula'))}</font>)", body))
    flow.append(make_table(
        ["Dimension", "Score"],
        [[Paragraph(v, cell), Paragraph(f"{_pdf_text(dq.get(k))}%", cell)]
         for v, k in [("Completeness", "completeness"), ("Validity", "validity"),
                      ("Consistency", "consistency"), ("Uniqueness", "uniqueness"),
                      ("Timeliness", "timeliness")]],
        col_widths=[60 * mm, 60 * mm]))
    flow.append(Paragraph(
        f"Valid records {_pdf_text(dq.get('valid_records'))} · invalid {_pdf_text(dq.get('invalid_records'))} · "
        f"duplicates {_pdf_text(dq.get('duplicate_records'))} · missing mandatory {_pdf_text(dq.get('missing_mandatory'))}.", small))

    # ---- 13 Workflow funnel ----
    flow.append(section_header(13, "Workflow Funnel"))
    wf = report.get("workflow", [])
    wf_rows = [[Paragraph(_pdf_text(w.get("stage")), cell), Paragraph(_pdf_text(w.get("count")), cell),
                Paragraph(f"{_pdf_text(w.get('coverage_pct'))}%", cell),
                Paragraph(f"{_pdf_text(w.get('of_alerts_pct'))}%", cell)] for w in wf]
    if wf_rows:
        flow.append(make_table(["Stage", "Count", "Coverage (prev stage)", "Share of alerts"], wf_rows,
                               col_widths=[70 * mm, 30 * mm, 40 * mm, 35 * mm]))
    else:
        flow.append(Paragraph("<i>No workflow data.</i>", small))

    # ---- 14 Recommended actions ----
    flow.append(section_header(14, "Recommended Actions"))
    acts = report.get("recommended_actions", [])
    act_rows = [[Paragraph(f'<b>{_pdf_text(a.get("entity_name"))}</b><br/><font size="6.5" color="#5a6572">{_pdf_text(a.get("entity_id"))}</font>', cell),
                 Paragraph(f'<font color="{status_color(a.get("status")).hexval()}"><b>{_pdf_text(a.get("status"))}</b></font>', cell),
                 Paragraph(_pdf_text(a.get("risk")), cell),
                 Paragraph(_pdf_text(a.get("action")), cell)] for a in acts]
    if act_rows:
        flow.append(make_table(["Entity", "Status", "Risk", "Action"], act_rows,
                               col_widths=[60 * mm, 40 * mm, 15 * mm, 60 * mm]))
    else:
        flow.append(Paragraph("<i>No actions.</i>", small))

    # ---- 15 Methodology ----
    flow.append(section_header(15, "Methodology"))
    flow.append(make_table(["Methodology"], [[Paragraph(_pdf_text(report.get("methodology")), cell)]],
                           col_widths=[175 * mm]))

    # ---- 16 Limitations ----
    flow.append(section_header(16, "Limitations"))
    for l in report.get("limitations", []):
        flow.append(Paragraph(f"• {_pdf_text(l)}", body))

    disclaimer = report.get("disclaimer")
    if disclaimer:
        flow.append(Spacer(1, 6))
        flow.append(Paragraph(f"<i>{_pdf_text(disclaimer)}</i>", small))

    # ---- Footer callback ----
    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(GREY)
        canvas.drawString(14 * mm, 9 * mm, _pdf_text(report.get("title"))[:90])
        canvas.drawRightString(A4[0] - 14 * mm, 9 * mm,
                               f"Page {doc.page}")
        canvas.restoreState()

    buf = io.BytesIO()
    doc = BaseDocTemplate(buf, pagesize=A4,
                          leftMargin=14 * mm, rightMargin=14 * mm,
                          topMargin=12 * mm, bottomMargin=14 * mm,
                          title=report.get("title") or "Supervisory Assessment Report",
                          author="SAT-SA Supervisory Function")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="page", frames=[frame], onPage=on_page)])
    doc.build(flow)
    return buf.getvalue()


__all__ = ["render_html", "render_pdf", "render_soc_inspect_html", "render_soc_inspect_pdf"]


# ---------------------------------------------------------------------------
# SOC-Inspect assessment report (legacy /assessment/{id}/report endpoint)
# ---------------------------------------------------------------------------

def _soc_inspect_adapter(report: dict[str, Any], report_hash: str) -> dict[str, Any]:
    """Map the legacy assessment report dict onto the supervisory report shape."""
    assessment = report.get("assessment", {})
    summary = assessment.get("summary", {})
    findings = report.get("findings", [])
    by_sev = summary.get("by_severity", {})
    entity_risk = summary.get("entity_risk", [])
    submission = report.get("submission", {})
    revs = report.get("reviews", [])
    reviewed = sum(1 for r in revs if r.get("decision"))
    verified = bool(report.get("hash_verified"))

    def sev_count(sev: str) -> int:
        val = by_sev.get(sev, 0)
        return val if isinstance(val, int) else len(val or [])

    entities = [{
        "rank": i + 1,
        "entity_id": r.get("entity_id") or r.get("id"),
        "entity_name": r.get("entity_name") or r.get("entity_id") or "—",
        "sector": r.get("sector") or "—",
        "status": "NOT_ASSESSED",
        "compliance_score": None,
        "evidence_coverage": None,
        "risk_score": r.get("risk_score"),
        "critical": r.get("critical", 0) or r.get("critical_findings", 0),
        "high": r.get("high", 0) or r.get("high_findings", 0),
        "medium": 0, "low": 0,
        "recommended_action": r.get("tier") or "REVIEW",
    } for i, r in enumerate(entity_risk)]

    critical = [f for f in findings if str(f.get("severity", "")).lower() == "critical"]
    high = [f for f in findings if str(f.get("severity", "")).lower() == "high"]

    return {
        "title": f"SOC-Inspect Assessment Report — {assessment.get('id', '')}",
        "disclaimer": None,
        "executive_summary": (
            f"Assessment completed with {len(findings)} findings "
            f"({sev_count('critical')} critical, {sev_count('high')} high, "
            f"{sev_count('medium')} medium, {sev_count('low')} low) across "
            f"{len(entity_risk)} entities. Dataset integrity: "
            f"{'verified' if verified else 'not verified'}."
        ),
        "assessment_scope": {"entity_filter": "All", "sector_filter": "All",
                             "period": assessment.get("created_at", "").split("T")[0] or "—"},
        "dataset": {"records": summary.get("alerts") or summary.get("total_alerts"),
                    "sha256": submission.get("content_sha256"),
                    "rule_version": report.get("rule_version") or "—",
                    "generated_at": assessment.get("created_at")},
        "compliance_distribution": {},
        "entities": entities,
        "sector_benchmark": {},
        "critical_findings": critical[:100],
        "high_findings": high[:100],
        "execution_gaps": [],
        "negative_space": [],
        "peer_benchmark": {},
        "data_quality": {},
        "workflow": [],
        "recommended_actions": [],
        "methodology": ("Automated static rule evaluation over the submitted SOC evidence; "
                        "findings reference the exact source rows they were inferred from."),
        "rule_version": report.get("rule_version") or "—",
        "dataset_hash": submission.get("content_sha256"),
        "assessment_timestamp": assessment.get("created_at"),
        "limitations": ["Evidence-based rule evaluation; findings require supervisor validation.",
                        "Report SHA-256: " + (report_hash or "")],
        "findings": findings,
    }


def render_soc_inspect_html(report: dict[str, Any], report_hash: str) -> str:
    """Render the legacy assessment report into the professional HTML template."""
    adapted = _soc_inspect_adapter(report, report_hash)
    adapted["_findings"] = report.get("findings", [])
    adapted["_report_sha256"] = report.get("report_sha256")
    adapted["_hash_verified"] = report.get("hash_verified")
    return render_html(adapted)


def render_soc_inspect_pdf(report: dict[str, Any], report_hash: str) -> bytes:
    """Render the legacy assessment report into a professional PDF."""
    adapted = _soc_inspect_adapter(report, report_hash)
    adapted["_findings"] = report.get("findings", [])
    adapted["_report_sha256"] = report.get("report_sha256")
    adapted["_hash_verified"] = report.get("hash_verified")
    return render_pdf(adapted)