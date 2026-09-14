import { Link } from "react-router-dom";
import { useFetch, useFilters, Page, Panel, Card, Table, Badge, Disclaimer, FilterBar,
  Donut, Bars, Trend, ScatterPlot, FunnelView, SEV_COLORS, STATUS_COLORS, type AnyRecord } from "../ui";

export default function Overview() {
  const { f } = useFilters();
  const params = { sector: f.sector || undefined, severity: f.severity || undefined };
  const { data, loading, error } = useFetch<AnyRecord>("/analytics/overview", params);
  if (loading) return <Page title="Supervisory command overview"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Supervisory command overview"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;

  const k = data.kpis || {};
  const dist = (data.compliance_distribution || []).map((d: AnyRecord) => ({ name: d.status, value: d.count }));
  const sev = (data.severity || []).map((d: AnyRecord) => ({ name: d.severity, value: d.count }));
  const trend = data.alert_trend || [];
  const sectors = (data.sector_compliance || []).map((s: AnyRecord) => ({
    name: s.sector, compliant: s.compliant, partial: s.partially_compliant,
    nonCompliant: s.non_compliant, insufficient: s.insufficient_evidence,
  }));
  const scatter = (data.risk_vs_compliance || []).map((e: AnyRecord) => ({ x: e.compliance, y: e.risk, name: e.entity_name, status: e.status }));
  const ctrl = (data.control_performance || []).map((c: AnyRecord) => ({ name: c.domain, score: c.score }));
  const gaps = (data.execution_gaps || []).map((g: AnyRecord) => ({ name: g.rule, value: g.count }));
  const dq = (data.data_quality_issues || []).map((d: AnyRecord) => ({ name: d.issue, value: d.count }));
  const funnel = data.workflow_funnel || [];
  let matrix: AnyRecord[] = data.attention_matrix || [];
  if (f.status) matrix = matrix.filter((m) => m.status === f.status);
  const sectorNames = [...new Set((data.attention_matrix || []).map((m: AnyRecord) => m.sector).filter(Boolean))].sort() as string[];

  const attentionRows = matrix.map((m: AnyRecord) => ({
    ...m,
    entity: <Link to={`/entities/${encodeURIComponent(m.entity_id)}`}>{m.entity_name}</Link>,
    compliance: `${m.compliance_score}% (ev ${m.evidence_coverage}%)`,
    risk: m.risk_score,
  }));

  return (
    <Page title="Supervisory command overview" subtitle="Evidence-grounded assessment across critical-sector entities">
      <Disclaimer />
      <FilterBar showStatus sectors={sectorNames} />
      <Panel title="Executive summary" subtitle="Deterministic synthesis of the current assessment — no generated text">
        <p className="summary">{data.executive_summary}</p>
        <div className="meta-line">
          <span>Rule version <b>{data.rule_version}</b></span>
          <span>Dataset SHA-256 <code>{String(data.dataset_sha256 || "").slice(0, 16)}…</code></span>
        </div>
      </Panel>

      <div className="kpis">
        <Card label="Entities assessed" value={k.entities_assessed} to="/entities" />
        <Card label="Compliant" value={k.compliant} hint="≥85%, no critical" to="/entities" tone="green" />
        <Card label="Partially compliant" value={k.partially_compliant} to="/entities" tone="amber" />
        <Card label="Non-compliant" value={k.non_compliant} to="/entities" tone="red" />
        <Card label="Insufficient evidence" value={k.insufficient_evidence} to="/entities" tone="blue" />
        <Card label="Critical findings" value={k.critical_findings} to="/findings?severity=critical" tone="red" />
        <Card label="High findings" value={k.high_findings} to="/findings?severity=high" tone="amber" />
        <Card label="Overall compliance" value={`${k.overall_compliance_pct}%`} hint="weighted evidenced controls" />
        <Card label="Evidence completeness" value={`${k.evidence_completeness_pct}%`} hint="controls with evidence" />
        <Card label="Data quality" value={`${k.data_quality_pct}%`} hint="0.3C+0.25V+0.2C+0.15U+0.1T" to="/data-quality" />
      </div>

      <div className="chart-grid">
        <Panel title="Compliance status distribution" subtitle="Count and share per supervisory state"><Donut data={dist} colors={STATUS_COLORS} /></Panel>
        <Panel title="Findings by severity" subtitle="Critical / High / Medium / Low"><Donut data={sev} colors={SEV_COLORS} /></Panel>
      </div>

      <Panel title="Alerts over time" subtitle="Monthly volume: total, critical and high">
        <Trend data={trend} series={[
          { key: "total", name: "Total", color: "#2f7ea6", area: true },
          { key: "critical", name: "Critical", color: "#c0392b" },
          { key: "high", name: "High", color: "#d97a2b" },
        ]} />
      </Panel>

      <Panel title="Compliance by sector" subtitle="Stacked entity counts per sector">
        <Bars data={sectors} bars={[
          { key: "compliant", color: STATUS_COLORS.COMPLIANT, name: "Compliant" },
          { key: "partial", color: STATUS_COLORS.PARTIALLY_COMPLIANT, name: "Partial" },
          { key: "nonCompliant", color: STATUS_COLORS.NON_COMPLIANT, name: "Non-compliant" },
          { key: "insufficient", color: STATUS_COLORS.INSUFFICIENT_EVIDENCE, name: "Insufficient" },
        ]} />
      </Panel>

      <div className="chart-grid">
        <Panel title="Entity risk vs compliance" subtitle="Each point is an entity; top-left needs immediate review">
          <ScatterPlot data={scatter} />
        </Panel>
        <Panel title="Control performance" subtitle="Mean coverage per control domain (0–100)">
          <Bars data={ctrl} layout="vertical" bars={[{ key: "score", color: "#2f7ea6", name: "Coverage %" }]} />
        </Panel>
      </div>

      <div className="chart-grid">
        <Panel title="Execution gap distribution" subtitle="Gap signals by rule"><Bars data={gaps} bars={[{ key: "value", color: "#c0392b", name: "Gaps" }]} /></Panel>
        <Panel title="Data quality issues" subtitle="Issue counts by type"><Bars data={dq} bars={[{ key: "value", color: "#d79a4b", name: "Issues" }]} /></Panel>
      </div>

      <div className="two-col">
        <Panel title="Supervisory workflow funnel" subtitle="Alert → Case → Investigation → Escalation → Response → Closure">
          <FunnelView stages={funnel} />
        </Panel>
        <Panel title="Reporting coverage" subtitle="Expected vs received reporting periods">
          <Table
            rows={Object.entries((data.reporting?.by_entity || {}) as Record<string, AnyRecord>).map(([eid, r]) => ({ entity_id: eid, ...r, missing_periods: (r.missing || []).join(", ") || "—" }))}
            columns={[["entity_id", "Entity"], ["received", "Received"], ["expected", "Expected"], ["coverage_pct", "Coverage %"], ["missing_periods", "Missing periods"]]}
          />
        </Panel>
      </div>

      <Panel title="Supervisory attention matrix" subtitle="Ranked by status → risk → compliance; recommendation is deterministic">
        <Table
          rows={attentionRows}
          columns={[["rank", "#"], ["entity", "Entity"], ["sector", "Sector"], ["status", "Compliance"], ["compliance", "Score"], ["risk", "Risk"], ["critical", "Crit"], ["high", "High"], ["recommended_action", "Recommended action"]]}
        />
        <div className="method">NO ACTION · ROUTINE REVIEW · EVIDENCE REQUEST · SUPERVISORY REVIEW · IMMEDIATE REVIEW — from status, risk, critical findings and evidence coverage.</div>
      </Panel>
      <div style={{ display: "none" }}><Badge value="x" /></div>
    </Page>
  );
}
