import { Link, useParams } from "react-router-dom";
import { useFetch, useFilters, Page, Panel, Card, Table, FilterBar,
  Donut, Bars, Trend, RadarPlot, FunnelView, STATUS_COLORS, type AnyRecord } from "../ui";

export function Entities() {
  const { f } = useFilters();
  const { data, loading, error } = useFetch<AnyRecord>("/analytics/entities", { sector: f.sector || undefined });
  if (loading) return <Page title="Entities"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Entities"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  let items: AnyRecord[] = data.items || [];
  if (f.status) items = items.filter((x) => x.status === f.status);
  const sectors = [...new Set(((data.items || []) as AnyRecord[]).map((x) => x.sector).filter(Boolean))].sort() as string[];
  const rows = items.map((x: AnyRecord) => ({
    ...x,
    entity: <Link to={`/entities/${encodeURIComponent(x.entity_id)}`}>{x.entity_name}</Link>,
    compliance: `${x.compliance_score}%`,
    evidence: `${x.evidence_coverage}%`,
    findings: `${x.critical}/${x.high}/${x.medium}/${x.low}`,
  }));
  return (
    <Page title="Entities" subtitle="Compliance, risk and evidence coverage per assessed entity">
      <FilterBar showStatus sectors={sectors} />
      <Panel>
        <Table
          rows={rows}
          columns={[["rank", "#"], ["entity", "Entity"], ["sector", "Sector"], ["status", "Compliance"], ["compliance", "Score"], ["evidence", "Evidence"], ["risk_score", "Risk"], ["critical", "Crit"], ["high", "High"], ["recommended_action", "Action"]]}
        />
      </Panel>
      <div className="method">Compliance score = weighted average of sufficiently evidenced controls (COMPLIANT=100, PARTIAL=50, NON=0; INSUFFICIENT excluded). Evidence coverage = evidenced / expected controls.</div>
    </Page>
  );
}

export function EntityDetail() {
  const { id = "" } = useParams();
  const { data, loading, error } = useFetch<AnyRecord>(`/analytics/entities/${encodeURIComponent(id)}`);
  if (loading) return <Page title="Entity detail"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Entity detail"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const c: AnyRecord = data.compliance || {};
  const dq: AnyRecord = data.data_quality || {};
  const peer: AnyRecord = data.peer || {};
  const findings: AnyRecord[] = data.findings || [];
  const funnel: AnyRecord[] = data.funnel || [];
  const controls: AnyRecord[] = c.controls || [];

  const donut = ["COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE"].map((s) => ({
    name: s,
    value: s === "COMPLIANT" ? c.compliant : s === "PARTIALLY_COMPLIANT" ? c.partially_compliant : s === "NON_COMPLIANT" ? c.non_compliant : c.insufficient_evidence,
  }));
  const domains = [...new Set(controls.map((x) => x.domain))].map((d) => ({
    name: d,
    score: Math.round(controls.filter((x) => x.domain === d && x.coverage != null).reduce((s, x, _, arr) => s + x.coverage / arr.length, 0) || 0),
  }));
  const alerts = (data.detail?.alerts_by_month || data.detail?.by_month || {});
  const trend = Object.entries(alerts).map(([month, v]: [string, any]) => ({ month, alerts: typeof v === "number" ? v : v.total || 0 }));
  const pc = peer.peer_comparison || {};
  const radar = Object.entries(pc).map(([metric, v]: [string, any]) => ({ metric, entity: v.value, median: v.peer_median }));

  return (
    <Page title={c.entity_name || id} subtitle={`Entity ${id} · Sector ${c.sector || "—"} · Assessment period 2026-01 to 2026-09`} actions={<Link className="button" to="/entities">Back to entities</Link>}>
      <div className="kpis">
        <Card label="Overall status" value={c.status} tone={c.status === "COMPLIANT" ? "green" : c.status === "NON_COMPLIANT" ? "red" : "amber"} />
        <Card label="Compliance score" value={`${c.compliance_score}%`} hint={`${c.compliant}C/${c.partially_compliant}P/${c.non_compliant}N/${c.insufficient_evidence}I of ${c.controls_assessed}`} />
        <Card label="Risk score" value={c.risk_score} hint={(c.risk_drivers || []).slice(0, 2).map((d: AnyRecord) => d.driver).join("; ")} tone={Number(c.risk_score) >= 70 ? "red" : ""} />
        <Card label="Evidence coverage" value={`${c.evidence_coverage}%`} />
        <Card label="Recommended action" value={c.recommended_action} tone={c.recommended_action === "IMMEDIATE REVIEW" ? "red" : ""} />
      </div>

      <div className="chart-grid">
        <Panel title="Compliance summary" subtitle="Controls by supervisory state"><Donut data={donut} colors={STATUS_COLORS} /></Panel>
        <Panel title="Domain performance" subtitle="Mean coverage per control domain"><Bars data={domains} layout="vertical" bars={[{ key: "score", color: "#2f7ea6", name: "Coverage %" }]} /></Panel>
      </div>

      <Panel title="Alert analytics" subtitle="Volume and severity mix">
        {trend.length ? <Trend data={trend} series={[{ key: "alerts", color: "#2f7ea6", area: true }]} /> : <div className="state">No sufficient evidence for this analysis.</div>}
      </Panel>

      <Panel title="Supervisory workflow funnel" subtitle="Conversion at every workflow stage — drops reveal execution gaps">
        <FunnelView stages={funnel} />
      </Panel>

      <div className="two-col">
        <Panel title="Risk drivers" subtitle="Explainable contributions to the risk score">
          <Table rows={(c.risk_drivers || []) as AnyRecord[]} columns={[["driver", "Driver"], ["points", "Points"], ["detail", "Detail"]]} empty="No elevated risk drivers." />
          <div className="method">{c.risk_method || (data.compliance && "risk = escalation failures + monitoring gaps + SLA breaches + data quality + peer deviation + severity-weighted findings (capped 100)")}</div>
        </Panel>
        <Panel title="Data quality" subtitle={String(dq.formula || "")}>
          <div className="kpis">
            <Card label="Overall" value={`${dq.overall}%`} />
            <Card label="Completeness" value={`${dq.completeness}%`} />
            <Card label="Validity" value={`${dq.validity}%`} />
            <Card label="Consistency" value={`${dq.consistency}%`} />
            <Card label="Uniqueness" value={`${dq.uniqueness}%`} />
            <Card label="Timeliness" value={`${dq.timeliness}%`} />
          </div>
        </Panel>
      </div>

      <Panel title="Control assessments" subtitle="Every control with calculation and supporting evidence">
        <Table
          rows={controls.map((x: AnyRecord) => ({ ...x, coverage: x.coverage != null ? `${x.coverage}%` : "insufficient evidence" }))}
          columns={[["control_id", "ID"], ["control_name", "Control"], ["domain", "Domain"], ["status", "Status"], ["coverage", "Coverage"], ["calculation", "Calculation"]]}
        />
      </Panel>

      <Panel title="Peer comparison" subtitle={`Entity vs sector median · ${c.sector || ""}`}>
        {radar.length ? <RadarPlot data={radar} keys={[{ key: "entity", color: "#2f7ea6", name: c.entity_name }, { key: "median", color: "#d79a4b", name: "Sector median" }]} /> : <div className="state">No sufficient evidence for this analysis.</div>}
        <Table rows={radar.map((r: AnyRecord) => ({ ...r, deviation: Math.round(((r.entity || 0) - (r.median || 0)) * 10) / 10 }))} columns={[["metric", "Metric"], ["entity", "Entity"], ["median", "Sector median"], ["deviation", "Deviation"]]} />
      </Panel>

      <Panel title="Findings with evidence lineage" subtitle="Click a finding for source rows, rule and calculation">
        <Table
          rows={findings.map((x: AnyRecord) => ({ ...x, finding: <Link to={`/findings/${x.id}`}>{x.title}</Link>, affected: x.affected_record_count ?? (x.evidence_ids || x.evidence || []).length }))}
          columns={[["severity", "Severity"], ["finding", "Finding"], ["rule", "Rule"], ["affected", "Affected records"], ["calculation", "Calculation"]]}
          empty="No findings for this entity."
        />
      </Panel>
    </Page>
  );
}
