import { Link } from "react-router-dom";
import { useFetch, useFilters, Page, Panel, Card, Table, Disclaimer, FilterBar,
  Donut, Bars, Trend, FunnelView, SEV_COLORS, type AnyRecord } from "../ui";

function useSectors() {
  const { data } = useFetch<AnyRecord>("/analytics/sectors");
  return [...new Set(((data?.items || []) as AnyRecord[]).map((x) => x.sector).filter(Boolean))].sort() as string[];
}

export function Alerts() {
  const { f } = useFilters();
  const sectors = useSectors();
  const { data, loading, error } = useFetch<AnyRecord>("/analytics/alerts", {
    sector: f.sector || undefined, severity: f.severity || undefined, limit: 300,
  });
  if (loading) return <Page title="Alert analytics"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Alert analytics"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const sev = Object.entries((data.by_severity || {}) as Record<string, number>).map(([name, value]) => ({ name, value }));
  const trend = Object.entries((data.by_month || {}) as Record<string, number>).map(([month, total]) => ({
    month, total,
    ...(Object.fromEntries(Object.entries((data.severity_by_month || {})[month] || {}))),
  }));
  const byEntity = Object.entries((data.by_entity || {}) as Record<string, AnyRecord>)
    .map(([entity_id, v]) => ({ name: entity_id, total: v.total, critical: v.critical, high: v.high }))
    .sort((a, b) => b.total - a.total).slice(0, 12);
  const bySector = Object.entries((data.by_entity || {}) as Record<string, AnyRecord>);
  void bySector;
  const rows: AnyRecord[] = (data.items || []).map((r: AnyRecord) => ({
    ...r,
    entity: <Link to={`/entities/${encodeURIComponent(r.entity_id)}`}>{r.entity_id}</Link>,
  }));
  return (
    <Page title="Alert analytics" subtitle="Volume, severity, escalation coverage and case linkage">
      <Disclaimer />
      <FilterBar sectors={sectors} />
      <div className="kpis">
        <Card label="Alert volume" value={data.total} />
        <Card label="Critical alerts" value={data.by_severity?.critical || 0} tone="red" to="/alerts" />
        <Card label="High alerts" value={data.by_severity?.high || 0} tone="amber" />
        <Card label="Requiring escalation" value={data.alerts_requiring_escalation} to="/escalations" />
        <Card label="Without case" value={data.alerts_without_case} tone={data.alerts_without_case ? "amber" : ""} />
        <Card label="Without investigation" value={data.alerts_without_investigation} />
        <Card label="Without response" value={data.alerts_without_response} />
        <Card label="Critical share" value={`${data.critical_alert_pct}%`} />
      </div>
      <div className="chart-grid">
        <Panel title="Alert volume over time" subtitle="Total with critical/high overlays">
          <Trend data={trend} series={[{ key: "total", name: "Total", color: "#2f7ea6", area: true }, { key: "critical", name: "Critical", color: "#c0392b" }, { key: "high", name: "High", color: "#d97a2b" }]} />
        </Panel>
        <Panel title="Severity distribution" subtitle="Share by severity class"><Donut data={sev} colors={SEV_COLORS} /></Panel>
      </div>
      <Panel title="Alerts by entity (top 12)" subtitle="Total with critical/high overlays">
        <Bars data={byEntity} bars={[{ key: "total", color: "#2f7ea6", name: "Total" }, { key: "critical", color: "#c0392b", name: "Critical" }, { key: "high", color: "#d97a2b", name: "High" }]} />
      </Panel>
      <Panel title="Alert records" subtitle={`Showing ${data.returned} of ${data.total} — compliance state per alert`}>
        <Table rows={rows} columns={[["alert_id", "Alert"], ["timestamp", "Time"], ["entity", "Entity"], ["severity", "Severity"], ["status", "Status"], ["case_id", "Case"], ["investigation", "Investigation"], ["escalation", "Escalation"], ["response", "Response"], ["compliance_state", "Compliance"]]} />
      </Panel>
    </Page>
  );
}

export function Investigations() {
  const { f } = useFilters();
  const sectors = useSectors();
  const { data, loading, error } = useFetch<AnyRecord>("/analytics/investigations", { sector: f.sector || undefined, limit: 300 });
  if (loading) return <Page title="Investigation analytics"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Investigation analytics"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const statusData = [
    { name: "Completed", value: (data.cases_with_investigation || 0) - (data.missing_conclusion || 0) },
    { name: "Missing conclusion", value: data.missing_conclusion || 0 },
    { name: "No investigation", value: data.missing_investigation || 0 },
  ];
  const trend = Object.entries((data.by_month || {}) as Record<string, AnyRecord>).map(([month, v]) => ({ month, total: v.total, investigated: v.investigated }));
  const byEntity = Object.entries((data.by_entity || {}) as Record<string, AnyRecord>).map(([name, v]) => ({ name, coverage: v.coverage }));
  const dur = Object.entries((data.duration_distribution || {}) as Record<string, number>).map(([name, value]) => ({ name: `${name} min`, value }));
  return (
    <Page title="Investigation analytics" subtitle="Throughput, conclusions, timeliness and SLA discipline">
      <Disclaimer />
      <FilterBar sectors={sectors} />
      <div className="kpis">
        <Card label="Total investigations" value={data.cases_with_investigation} />
        <Card label="Coverage" value={`${data.investigation_coverage}%`} />
        <Card label="Missing conclusion" value={data.missing_conclusion} tone={data.missing_conclusion ? "amber" : ""} />
        <Card label="No investigation" value={data.missing_investigation} tone={data.missing_investigation ? "red" : ""} />
        <Card label="Avg duration" value={data.avg_investigation_minutes != null ? `${data.avg_investigation_minutes} min` : "—"} />
        <Card label="SLA breaches" value={data.sla_breach_count} hint=">240 min" tone={data.sla_breach_count ? "amber" : ""} />
      </div>
      <div className="chart-grid">
        <Panel title="Investigation status" subtitle="Completed vs missing conclusion vs missing"><Donut data={statusData} colors={{ Completed: "#3fa37c", "Missing conclusion": "#d9b02b", "No investigation": "#c0392b" }} /></Panel>
        <Panel title="Volume over time" subtitle="Cases vs investigated per month"><Trend data={trend} series={[{ key: "total", name: "Cases", color: "#7892b4" }, { key: "investigated", name: "Investigated", color: "#2f7ea6", area: true }]} /></Panel>
      </div>
      <div className="chart-grid">
        <Panel title="Completion by entity" subtitle="Investigation coverage %"><Bars data={byEntity} layout="vertical" bars={[{ key: "coverage", color: "#2f7ea6", name: "Coverage %" }]} /></Panel>
        <Panel title="Duration distribution" subtitle="Investigation time buckets"><Bars data={dur} bars={[{ key: "value", color: "#2f7ea6", name: "Count" }]} /></Panel>
      </div>
      <Panel title="Investigation records" subtitle="Missing conclusions and SLA breaches highlighted">
        <Table rows={(data.items || []) as AnyRecord[]} columns={[["investigation_id", "Investigation"], ["case_id", "Case"], ["entity_id", "Entity"], ["analyst_id", "Analyst"], ["duration_minutes", "Duration (min)"], ["conclusion", "Conclusion"], ["status", "Status"]]} />
      </Panel>
    </Page>
  );
}

export function Escalations() {
  const { f } = useFilters();
  const sectors = useSectors();
  const { data, loading, error } = useFetch<AnyRecord>("/analytics/escalations", { sector: f.sector || undefined, limit: 300 });
  if (loading) return <Page title="Escalation analytics"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Escalation analytics"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const cov = [
    { name: "Escalated", value: data.escalated || 0 },
    { name: "Not escalated", value: (data.requiring_escalation || 0) - (data.escalated || 0) },
  ];
  const bySev = Object.entries((data.by_severity || {}) as Record<string, AnyRecord>).map(([name, v]) => ({ name, requiring: v.requiring, escalated: v.escalated }));
  const byEntity = Object.entries((data.by_entity || {}) as Record<string, AnyRecord>).map(([name, v]) => ({ name, rate: v.rate, requiring: v.requiring }));
  return (
    <Page title="Escalation analytics" subtitle="The central supervisory control: did critical alerts reach the right owner?">
      <Disclaimer />
      <FilterBar sectors={sectors} />
      <div className="kpis">
        <Card label="Requiring escalation" value={data.requiring_escalation} />
        <Card label="Escalated" value={data.escalated} tone="green" />
        <Card label="Not escalated" value={data.not_escalated} tone={data.not_escalated ? "red" : ""} />
        <Card label="Coverage" value={`${data.escalation_rate}%`} tone={Number(data.escalation_rate) < 60 ? "red" : ""} />
        <Card label="Median latency" value={data.latency_median != null ? `${data.latency_median} min` : "—"} />
        <Card label="Escalation → response" value={`${data.escalation_to_response_rate}%`} />
      </div>
      <div className="chart-grid">
        <Panel title="Escalation coverage" subtitle="Required vs completed"><Donut data={cov} colors={{ Escalated: "#3fa37c", "Not escalated": "#c0392b" }} /></Panel>
        <Panel title="Critical alert funnel" subtitle="Critical → investigated → escalated → responded"><FunnelView stages={data.critical_alert_funnel || []} /></Panel>
      </div>
      <Panel title="Escalation by severity" subtitle="Required vs escalated per severity"><Bars data={bySev} bars={[{ key: "requiring", color: "#7892b4", name: "Required" }, { key: "escalated", color: "#3fa37c", name: "Escalated" }]} /></Panel>
      <Panel title="Escalation coverage by entity" subtitle="Rate % with required volume as context"><Bars data={byEntity} layout="vertical" bars={[{ key: "rate", color: "#c0392b", name: "Coverage %" }]} /></Panel>
      <Panel title="Critical alerts requiring escalation" subtitle="Every required escalation with evidence state">
        <Table rows={(data.items || []) as AnyRecord[]} columns={[["alert_id", "Alert"], ["timestamp", "Time"], ["entity_id", "Entity"], ["severity", "Severity"], ["case_id", "Case"], ["escalation_status", "Escalation"], ["escalation_timestamp", "Escalated at"], ["response", "Response"]]} />
      </Panel>
    </Page>
  );
}

export function Monitoring() {
  const { f } = useFilters();
  const sectors = useSectors();
  const { data, loading, error } = useFetch<AnyRecord>("/analytics/monitoring", { sector: f.sector || undefined });
  if (loading) return <Page title="Monitoring coverage"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Monitoring coverage"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const cov = [
    { name: "Monitored", value: data.assets_with_activity || 0 },
    { name: "Coverage gap", value: data.unmonitored_assets || 0 },
  ];
  const byEntity = Object.entries((data.by_entity || {}) as Record<string, AnyRecord>).map(([name, v]) => ({ name, coverage: v.coverage, critical: v.critical_coverage }));
  const crit = Object.entries((data.by_entity || {}) as Record<string, AnyRecord>).map(([name, v]) => ({ name, assets: v.total_assets, gap: v.zero_activity }));
  return (
    <Page title="Monitoring coverage" subtitle="Expected monitoring vs observed asset activity">
      <Disclaimer />
      <FilterBar sectors={sectors} />
      <div className="kpis">
        <Card label="Total assets" value={data.total_assets} />
        <Card label="Monitored" value={data.assets_with_activity} tone="green" />
        <Card label="Unmonitored" value={data.unmonitored_assets} tone={data.unmonitored_assets ? "red" : ""} />
        <Card label="Coverage" value={`${data.coverage}%`} />
        <Card label="Critical assets" value={data.critical_assets} />
        <Card label="Critical coverage" value={`${data.critical_coverage}%`} tone={Number(data.critical_coverage) < 85 ? "amber" : ""} />
      </div>
      <div className="chart-grid">
        <Panel title="Asset coverage" subtitle="Monitored vs gap"><Donut data={cov} colors={{ Monitored: "#3fa37c", "Coverage gap": "#c0392b" }} /></Panel>
        <Panel title="Coverage by entity" subtitle="Overall and critical-asset coverage %"><Bars data={byEntity} layout="vertical" bars={[{ key: "coverage", color: "#2f7ea6", name: "Coverage %" }, { key: "critical", color: "#c0392b", name: "Critical %" }]} /></Panel>
      </div>
      <Panel title="Coverage by asset criticality" subtitle="Assets vs gap per entity"><Bars data={crit} bars={[{ key: "assets", color: "#7892b4", name: "Assets" }, { key: "gap", color: "#c0392b", name: "Gap" }]} /></Panel>
      <Panel title="Assets with coverage gaps" subtitle="First 300 unmonitored assets">
        <Table rows={(data.items || []).filter((r: AnyRecord) => r.monitoring_status === "gap").slice(0, 300)} columns={[["asset_id", "Asset"], ["entity_id", "Entity"], ["criticality", "Criticality"], ["monitoring_status", "Status"]]} empty="No coverage gaps in scope." />
      </Panel>
    </Page>
  );
}

export function Gaps() {
  const { f } = useFilters();
  const sectors = useSectors();
  const { data, loading, error } = useFetch<AnyRecord>("/analytics/execution-gaps", {
    sector: f.sector || undefined, severity: f.severity || undefined,
  });
  if (loading) return <Page title="Execution gaps"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Execution gaps"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const items: AnyRecord[] = data.items || [];
  const sevCount = (s: string) => items.filter((x) => String(x.severity).toLowerCase() === s).length;
  return (
    <Page title="Execution gaps" subtitle="Breaks between supervisory expectation and operational action">
      <Disclaimer />
      <FilterBar sectors={sectors} />
      <div className="kpis">
        <Card label="Total gaps" value={data.total} />
        <Card label="Critical gaps" value={sevCount("critical")} tone="red" />
        <Card label="High gaps" value={sevCount("high")} tone="amber" />
        <Card label="Affected entities" value={data.affected_entities} />
        <Card label="Affected records" value={items.reduce((s, x) => s + (x.affected_records || x.count || 0), 0)} />
      </div>
      <div className="chart-grid">
        <Panel title="Gap count by rule" subtitle="Which expectations fail most"><Bars data={data.by_rule || []} bars={[{ key: "count", color: "#c0392b", name: "Gaps" }]} /></Panel>
        <Panel title="Gap count by severity" subtitle="Severity mix"><Donut data={(data.by_severity || []).map((d: AnyRecord) => ({ name: d.severity, value: d.count }))} colors={SEV_COLORS} /></Panel>
      </div>
      <Panel title="Gap count by entity" subtitle="Where gaps concentrate"><Bars data={data.by_entity || []} layout="vertical" bars={[{ key: "count", color: "#d79a4b", name: "Gaps" }]} /></Panel>
      <Panel title="Execution gap detail" subtitle="Rule, domain, affected records, evidence and action">
        <Table rows={items} columns={[["severity", "Severity"], ["rule", "Rule"], ["domain", "Domain"], ["entity_id", "Entity"], ["affected_records", "Records"], ["rate", "Rate"], ["description", "Description"]]} />
      </Panel>
    </Page>
  );
}
