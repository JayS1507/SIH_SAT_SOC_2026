import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useFetch, useFilters, Page, Panel, Card, Table, Badge, Disclaimer, FilterBar,
  Donut, Bars, RadarPlot, SEV_COLORS, type AnyRecord } from "../ui";
import { patch, downloadReport } from "../api";

function useSectors() {
  const { data } = useFetch<AnyRecord>("/analytics/sectors");
  return [...new Set(((data?.items || []) as AnyRecord[]).map((x) => x.sector).filter(Boolean))].sort() as string[];
}

export function Findings() {
  const { f } = useFilters();
  const [sp] = useSearchParams();
  const initSev = sp.get("severity") || "";
  const [sev, setSev] = useState(initSev);
  const sectors = useSectors();
  const { data, loading, error } = useFetch<AnyRecord>("/analytics/findings-grouped", {
    sector: f.sector || undefined, severity: sev || f.severity || undefined,
  });
  if (loading) return <Page title="Findings"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Findings"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const items: AnyRecord[] = data.items || [];
  const bySev = [...new Map(items.map((x) => [String(x.severity).toLowerCase(), 0])).keys()].map((s) => ({
    name: s, value: items.filter((x) => String(x.severity).toLowerCase() === s).reduce((n, x) => n + 1, 0),
  }));
  const byDomain: AnyRecord[] = [...new Map(items.map((x) => [x.domain || "—", 0])).keys()].map((d) => ({
    name: d, value: items.filter((x) => (x.domain || "—") === d).length,
  }));
  const byEntity = [...new Map(items.map((x) => [x.entity_id, 0])).keys()].map((e) => ({
    name: e, value: items.filter((x) => x.entity_id === e).length,
  })).sort((a, b) => b.value - a.value).slice(0, 12);
  const rows = items.map((x: AnyRecord) => ({
    ...x,
    finding: <Link to={`/findings/${x.primary_finding_id}`}>{x.title}</Link>,
    entity: <Link to={`/entities/${encodeURIComponent(x.entity_id)}`}>{x.entity_id}</Link>,
  }));
  return (
    <Page title="Findings" subtitle="Grouped by rule and entity — repeated signals collapsed with affected-record counts">
      <Disclaimer />
      <FilterBar sectors={sectors} />
      <div className="filters">
        <label>Severity
          <select value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="">All</option>{["critical", "high", "medium", "low"].map((x) => <option key={x} value={x}>{x}</option>)}
          </select>
        </label>
      </div>
      <div className="chart-grid">
        <Panel title="Findings by severity" subtitle="Grouped finding counts"><Donut data={bySev} colors={SEV_COLORS} /></Panel>
        <Panel title="Findings by domain" subtitle="Control domains affected"><Bars data={byDomain} bars={[{ key: "value", color: "#2f7ea6", name: "Findings" }]} /></Panel>
      </div>
      <Panel title="Findings by entity (top 12)" subtitle="Concentration of grouped findings"><Bars data={byEntity} layout="vertical" bars={[{ key: "value", color: "#d79a4b", name: "Findings" }]} /></Panel>
      <Panel title="Grouped findings" subtitle={`${data.total} groups — open a finding for evidence lineage`}>
        <Table rows={rows} columns={[["severity", "Severity"], ["finding", "Finding"], ["entity", "Entity"], ["domain", "Domain"], ["rule", "Rule"], ["affected_records", "Affected records"], ["affected_assets", "Assets"], ["calculation", "Calculation"]]} />
      </Panel>
    </Page>
  );
}

export function FindingDetail() {
  const { id = "" } = useParams();
  const { data, loading, error } = useFetch<AnyRecord>(`/analytics/finding-evidence/${encodeURIComponent(id)}`);
  if (loading) return <Page title="Finding evidence"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Finding evidence"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  return (
    <Page title={data.title || "Finding evidence"} subtitle={`${data.rule} · ${data.rule_version} · ${data.severity}`} actions={<Link className="button" to="/findings">Back to findings</Link>}>
      <Disclaimer />
      <div className="kpis">
        <Card label="Severity" value={data.severity} tone={data.severity === "critical" ? "red" : ""} />
        <Card label="Entity" value={data.entity_id} />
        <Card label="Domain" value={data.domain} />
        <Card label="Affected records" value={data.affected_record_count} />
        <Card label="Review status" value={data.review_status} />
      </div>
      <Panel title="Description"><p>{data.description}</p><div className="method">Calculation: {data.calculation}</div></Panel>
      <Panel title="Evidence records" subtitle="Source rows backing this finding (first 50)">
        <Table rows={(data.source_rows || []) as AnyRecord[]} columns={[["record_id", "Record"], ["alert_id", "Alert"], ["case_id", "Case"], ["timestamp", "Time"], ["entity_id", "Entity"], ["severity", "Severity"], ["asset_id", "Asset"], ["status", "Status"]]} />
        <div className="method">Evidence IDs: {(data.evidence_ids || []).slice(0, 10).join(", ")}{Number(data.affected_record_count) > 10 ? "…" : ""}</div>
      </Panel>
    </Page>
  );
}

const REVIEW_ACTIONS = ["IN_REVIEW", "VALIDATED", "REJECTED", "REQUIRES_EVIDENCE", "CLOSED"];

export function Review() {
  const [sev, setSev] = useState("");
  const [st, setSt] = useState("");
  const [msg, setMsg] = useState("");
  const { data, loading, error } = useFetch<AnyRecord>("/sat/review-queue", { severity: sev || undefined, status: st || undefined });
  async function act(id: string, status: string) {
    try {
      await patch(`/sat/review-queue/${id}`, { status, reviewer: "supervisor", annotation: "Updated in supervisory workspace" });
      setMsg(`Finding ${id.slice(0, 8)}… → ${status}. Audit event recorded.`);
    } catch (e) { setMsg(e instanceof Error ? e.message : "Update failed"); }
  }
  if (loading) return <Page title="Review queue"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Review queue"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const rows: AnyRecord[] = (data.items || []).map((x: AnyRecord) => ({
    ...x,
    finding: <Link to={`/findings/${x.id}`}>{x.title}</Link>,
    entity: <Link to={`/entities/${encodeURIComponent(x.entity_id)}`}>{x.entity_id}</Link>,
    priority: { critical: 100, high: 70, medium: 40, low: 10 }[String(x.severity).toLowerCase()] ?? 0,
    actions: (
      <span className="row-actions">
        {REVIEW_ACTIONS.map((s) => <button key={s} className="button xs" onClick={() => act(x.id, s)}>{s.replace("REQUIRES_EVIDENCE", "REQ EVIDENCE")}</button>)}
      </span>
    ),
  }));
  return (
    <Page title="Review queue" subtitle="Actionable supervisory workflow — every action is audit-logged">
      <Disclaimer />
      <div className="filters">
        <label>Severity<select value={sev} onChange={(e) => setSev(e.target.value)}><option value="">All</option>{["critical", "high", "medium", "low"].map((x) => <option key={x} value={x}>{x}</option>)}</select></label>
        <label>Status<select value={st} onChange={(e) => setSt(e.target.value)}><option value="">All</option>{["NEW", "IN_REVIEW", "VALIDATED", "REJECTED", "REQUIRES_EVIDENCE", "CLOSED"].map((x) => <option key={x} value={x}>{x}</option>)}</select></label>
      </div>
      {msg && <div className="notice">{msg} <Link to="/audit">View audit trail</Link></div>}
      <Panel>
        <Table rows={rows} columns={[["priority", "Priority"], ["severity", "Severity"], ["finding", "Finding"], ["entity", "Entity"], ["review_status", "Status"], ["actions", "Actions"]]} />
      </Panel>
      <div className="method">Statuses: NEW → IN_REVIEW → VALIDATED / REJECTED / REQUIRES_EVIDENCE → CLOSED. Findings never disappear from history; status changes append audit events.</div>
    </Page>
  );
}

export function Peer() {
  const [entity, setEntity] = useState("ntpc");
  const { data, loading, error } = useFetch<AnyRecord>("/analytics/peer-benchmark", {});
  const entList = data ? Object.keys((data.peer?.entities || {})) : [];
  const focus = entity && data ? data.peer?.entities?.[entity] : null;
  const comp = data?.compliance?.[entity];
  if (loading) return <Page title="Peer benchmark"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Peer benchmark"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const pc = focus?.peer_comparison || {};
  const radar = Object.entries(pc).map(([metric, v]: [string, any]) => ({ metric, entity: v.value, median: v.peer_median }));
  const pct = Object.entries(pc).map(([metric, v]: [string, any]) => ({ metric, percentile: v.percentile }));
  return (
    <Page title="Peer benchmark" subtitle="Entity vs sector median — deviation and percentile per metric">
      <Disclaimer />
      <div className="filters">
        <label>Entity<select value={entity} onChange={(e) => setEntity(e.target.value)}>{entList.map((e) => <option key={e} value={e}>{e}</option>)}</select></label>
        {focus && <span className="meta-line">Sector <b>{focus.sector}</b>{comp && <> · Compliance <b>{comp.compliance_score}%</b> · Risk <b>{comp.risk_score}</b> · {comp.status}</>}</span>}
      </div>
      <div className="chart-grid">
        <Panel title="Entity vs sector median" subtitle="Radar across supervisory metrics"><RadarPlot data={radar} keys={[{ key: "entity", color: "#2f7ea6", name: entity }, { key: "median", color: "#d79a4b", name: "Sector median" }]} /></Panel>
        <Panel title="Percentile ranking" subtitle="Entity percentile within its sector"><Bars data={pct} layout="vertical" bars={[{ key: "percentile", color: "#3fa37c", name: "Percentile" }]} /></Panel>
      </div>
      <Panel title="Metric comparison" subtitle="Value, peer median, deviation and percentile">
        <Table rows={radar.map((r: AnyRecord) => ({ ...r, deviation: Math.round(((r.entity || 0) - (r.median || 0)) * 10) / 10, percentile: (pc[r.metric] || {}).percentile }))} columns={[["metric", "Metric"], ["entity", "Entity"], ["median", "Sector median"], ["deviation", "Deviation"], ["percentile", "Percentile"]]} />
      </Panel>
      <div style={{ display: "none" }}><Badge value="x" /></div>
    </Page>
  );
}

export function Quality() {
  const { f } = useFilters();
  const sectors = useSectors();
  const { data, loading, error } = useFetch<AnyRecord>("/analytics/data-quality", { sector: f.sector || undefined });
  const rep = useFetch<AnyRecord>("/analytics/overview", { sector: f.sector || undefined });
  if (loading) return <Page title="Data quality & reporting"><div className="state">Loading supervisory data…</div></Page>;
  if (error || !data) return <Page title="Data quality & reporting"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const o: AnyRecord = data.overall || {};
  const byEntity = Object.entries((data.by_entity || {}) as Record<string, AnyRecord>).map(([name, v]) => ({
    name, overall: v.overall, completeness: v.completeness, validity: v.validity, consistency: v.consistency, uniqueness: v.uniqueness,
  }));
  return (
    <Page title="Data quality & reporting" subtitle="Schema completeness, validity, consistency, uniqueness, timeliness">
      <Disclaimer />
      <FilterBar sectors={sectors} />
      <div className="kpis">
        <Card label="Overall score" value={`${o.overall}%`} />
        <Card label="Completeness" value={`${o.completeness}%`} hint="mandatory fields populated" />
        <Card label="Validity" value={`${o.validity}%`} hint="schema/range checks" />
        <Card label="Consistency" value={`${o.consistency}%`} hint="cross-record references" />
        <Card label="Uniqueness" value={`${o.uniqueness}%`} hint="duplicate-free ratio" />
        <Card label="Timeliness" value={`${o.timeliness}%`} hint="periods submitted" />
        <Card label="Total records" value={o.total_records} />
        <Card label="Duplicates" value={o.duplicate_records} tone={o.duplicate_records ? "amber" : ""} />
        <Card label="Missing mandatory" value={o.missing_mandatory} tone={o.missing_mandatory ? "amber" : ""} />
      </div>
      <div className="method">Overall = 0.30×completeness + 0.25×validity + 0.20×consistency + 0.15×uniqueness + 0.10×timeliness. Optional fields never penalise the score.</div>
      <Panel title="Quality by entity" subtitle="Overall score per entity"><Bars data={byEntity} layout="vertical" bars={[{ key: "overall", color: "#2f7ea6", name: "Overall %" }]} /></Panel>
      <Panel title="Reporting coverage" subtitle="Expected vs received periods — gaps are insufficient evidence, not non-compliance">
        <Table
          rows={Object.entries(((rep.data?.reporting?.by_entity) || {}) as Record<string, AnyRecord>).map(([eid, r]) => ({ entity_id: eid, ...r, missing_periods: (r.missing || []).join(", ") || "—" }))}
          columns={[["entity_id", "Entity"], ["received", "Received"], ["expected", "Expected"], ["coverage_pct", "Coverage %"], ["missing_periods", "Missing periods"]]}
        />
      </Panel>
    </Page>
  );
}

export function Reports() {
  const [format, setFormat] = useState<"json" | "html" | "pdf">("json");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  async function generate() {
    setBusy(true); setMsg("");
    try { await downloadReport(format); setMsg(`Report generated (SAT-SA supervisory assessment, ${format.toUpperCase()}). Audit event recorded.`); }
    catch (e) { setMsg(e instanceof Error ? e.message : "Generation failed"); }
    finally { setBusy(false); }
  }
  return (
    <Page title="Reports" subtitle="Professional evidence-backed supervisory assessment">
      <Disclaimer />
      <Panel title="Generate report" subtitle="Executive summary · scope · dataset & hash · compliance · sectors · critical/high findings · gaps · data quality · entity assessments · actions · evidence references · methodology · rule version · limitations">
        <div className="report-options">
          <label>Output format
            <select value={format} onChange={(e) => setFormat(e.target.value as any)}>
              <option value="json">JSON</option><option value="html">HTML</option><option value="pdf">PDF</option>
            </select>
          </label>
          <button className="button primary" disabled={busy} onClick={generate}>{busy ? "Generating…" : "Generate report"}</button>
        </div>
        {msg && <div className="notice">{msg}</div>}
      </Panel>
    </Page>
  );
}

export function Audit() {
  const [actor, setActor] = useState("");
  const { data, loading, error } = useFetch<AnyRecord[]>("/audit-events", actor ? { actor } : {});
  if (loading) return <Page title="Audit trail"><div className="state">Loading supervisory data…</div></Page>;
  if (error) return <Page title="Audit trail"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const rows: AnyRecord[] = (data || []).map((e: AnyRecord) => ({
    ...e,
    event: e.event_type || e.type,
    action: typeof e.action === "string" ? e.action : e.details?.action || JSON.stringify(e.details || "").slice(0, 120),
    state: [e.previous_state, e.new_state].filter((x) => x != null).join(" → ") || "—",
    hash: String(e.event_hash || "").slice(0, 12),
  }));
  return (
    <Page title="Audit trail" subtitle="Immutable, hash-chained record of every supervisory action">
      <div className="filters">
        <label>Actor<input value={actor} placeholder="filter by actor" onChange={(e) => setActor(e.target.value)} /></label>
      </div>
      {rows.length === 0
        ? <Panel><div className="state">No supervisory actions have been recorded for this assessment.</div></Panel>
        : <Panel><Table rows={rows} columns={[["timestamp", "Time"], ["event", "Event"], ["actor", "Actor"], ["role", "Role"], ["target_id", "Target"], ["action", "Action"], ["state", "State change"], ["hash", "Hash"]]} /></Panel>}
    </Page>
  );
}
