import { useState } from "react";
import { Link } from "react-router-dom";
import { API } from "../api";
import { useFetch, Page, Panel, Card, Table, Trend, Badge, type AnyRecord } from "../ui";

const ent = (id: string) => <Link to={`/entities/${encodeURIComponent(id)}`}>{id}</Link>;

export function Validation() {
  const { data, loading, error } = useFetch<AnyRecord>("/validation/summary");
  if (loading) return <Page title="Validation"><div className="state">Measuring tool effectiveness…</div></Page>;
  if (error || !data) return <Page title="Validation"><div className="state error-state"><b>Unable to load this view</b><span>{error}</span></div></Page>;
  const gt: AnyRecord = data.ground_truth || {};
  const sm: AnyRecord = data.sampling || {};
  const ex: AnyRecord = data.examiner_agreement || {};
  const curve = (sm.curve || []).map((p: AnyRecord) => ({ month: `${p.budget}%`, tool: p.tool, random: p.random }));
  return (
    <Page title="Validation" subtitle="Is SAT-SA as effective as expert manual sampling? Measured, not claimed.">
      <div className="kpis">
        <Card label="Deficient cases in a 5% sample" value={sm.available ? `${sm.precision_at_5}%` : "—"} hint={`random sample: ${sm.random_precision_at_5}%`} tone="green" />
        <Card label="Lift over random sampling" value={sm.available ? `${sm.lift_at_5}×` : "—"} hint="at 5% review budget" />
        <Card label="Effort to find 50% of deficiencies" value={sm.available ? `${sm.effort_for_50pct.tool}%` : "—"} hint={`random sampling: ${sm.effort_for_50pct?.random}% of cases`} />
        <Card label="Entity ranking AUC" value={gt.available ? gt.auc : "n/a"} hint={gt.available ? `tier accuracy ${gt.tier_accuracy}%` : gt.reason} />
        <Card label="Planted behaviours detected" value={gt.available ? `${gt.behaviours_detected}/${gt.behaviours_total}` : "n/a"} />
        <Card label="Examiner precision" value={ex.precision != null ? `${ex.precision}%` : "awaiting reviews"} hint={`${ex.decisions || 0} decisions`} />
      </div>
      <Panel title="Review effort vs deficiencies found" subtitle={`${sm.cases} cases, ${sm.deficient_cases} deficient (${sm.base_rate}%). X: share of cases reviewed · Y: share of deficient cases found`}>
        {curve.length ? <Trend data={curve} series={[{ key: "tool", name: "SAT-SA prioritised review", color: "#1f8a5b", area: true }, { key: "random", name: "Random manual sampling", color: "#c0392b" }]} /> : <div className="state">No cases.</div>}
        <div className="method">{sm.method}</div>
      </Panel>
      {gt.available && (
        <>
          <Panel title="Planted behaviours vs detection" subtitle={gt.label}>
            <Table rows={(gt.behaviours || []).map((b: AnyRecord) => ({ ...b, entity: ent(b.entity_id), result: <Badge value={b.detected ? "DETECTED" : "MISSED"} /> }))}
              columns={[["entity", "Entity"], ["behaviour", "Planted behaviour"], ["expected_signal", "Expected signal"], ["result", "Result"], ["evidence", "Why"]]} />
          </Panel>
          <Panel title="Entity ranking vs ground truth" subtitle={gt.separated ? "Every weak entity scores above every strong entity" : "Ranking overlap present"}>
            <Table rows={(gt.entities || []).map((e: AnyRecord) => ({ ...e, entity: ent(e.entity_id), tier: <Badge value={e.risk_level} />, verdict: e.agrees == null ? "—" : e.agrees ? "✓ agrees" : "✗ disagrees" }))}
              columns={[["entity", "Entity"], ["truth", "Ground truth"], ["risk_score", "Risk"], ["tier", "Tier"], ["verdict", "Verdict"]]} />
          </Panel>
        </>
      )}
      <Panel title="Examiner agreement by rule" subtitle={ex.method}>
        <Table rows={ex.rules || []} columns={[["rule", "Rule"], ["validated", "Validated"], ["rejected", "Rejected"], ["open", "Open"], ["precision", "Precision %"]]} empty="No findings yet." />
      </Panel>
    </Page>
  );
}

export function PaperVsPractice() {
  const [version, setVersion] = useState(0);
  const { data, loading, error } = useFetch<AnyRecord>("/sat/declared-vs-observed", { v: version });
  const [msg, setMsg] = useState("");
  async function upload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const body = new FormData();
    body.append("file", file);
    const res = await fetch(`${API}/declarations`, { method: "POST", body });
    const json = await res.json().catch(() => ({}));
    setMsg(res.ok ? `Stored ${json.stored} declarations for ${json.entities.length} entities.` : json.error || "Upload failed");
    if (res.ok) setVersion((v) => v + 1);
  }
  const items: AnyRecord[] = data?.items || [];
  const overstated = items.filter((x) => x.verdict === "OVERSTATED");
  return (
    <Page title="Paper vs practice" subtitle="What each entity reports about its SOC, against what its own evidence shows">
      <Panel title="Self-assessment upload" subtitle="CSV/JSON/XLSX with entity_id, metric, declared_value">
        <input type="file" accept=".csv,.json,.xlsx" onChange={upload} />
        <small> Try examples/sat_sa_self_assessment.csv. Metrics: investigation_coverage, escalation_rate, response_coverage, monitoring_coverage, evidence_completeness.</small>
        {msg && <p className="summary">{msg}</p>}
      </Panel>
      {loading ? <div className="state">Loading…</div> : error ? <div className="state error-state">{error}</div> : (
        <>
          <div className="kpis">
            <Card label="Declarations" value={items.length} />
            <Card label="Overstated (≥15 pts)" value={overstated.length} tone={overstated.length ? "red" : ""} />
            <Card label="Entities overstating" value={new Set(overstated.map((x) => x.entity_id)).size} tone="amber" />
            <Card label="Largest gap" value={overstated.length ? `${overstated[0].gap} pts` : "—"} hint={overstated[0] ? `${overstated[0].entity_id} · ${overstated[0].label}` : ""} />
          </div>
          <Panel title="Declared vs evidenced" subtitle="Execution gap = reported capability not supported by operational evidence">
            <Table rows={items.map((x) => ({ ...x, entity: ent(x.entity_id), declared: `${x.declared}%`, observed: x.observed == null ? "no evidence" : `${x.observed}%`, gap: x.gap == null ? "—" : `${x.gap > 0 ? "+" : ""}${x.gap}`, verdict: <Badge value={x.verdict} /> }))}
              columns={[["entity", "Entity"], ["label", "Metric"], ["declared", "Declared"], ["observed", "Evidenced"], ["gap", "Gap (pts)"], ["verdict", "Verdict"]]}
              empty="No self-assessment uploaded yet." />
          </Panel>
        </>
      )}
    </Page>
  );
}

export function ExaminationPlan({ id }: { id: string }) {
  const { data, loading, error } = useFetch<AnyRecord>(`/sat/entities/${encodeURIComponent(id)}/examination-plan`);
  if (loading) return <Panel title="Examination plan"><div className="state">Preparing…</div></Panel>;
  if (error || !data) return null;
  const areas: AnyRecord[] = data.focus_areas || [];
  return (
    <Panel title="Examination plan" subtitle={`Auto-generated request list · risk ${data.risk_score} (${data.risk_level}) · ${data.note}`} className="exam-plan">
      <div className="actions-row"><button className="button" onClick={() => window.print()}>Print plan</button></div>
      <Table rows={areas.map((a, i) => ({ ...a, n: i + 1, sev: <Badge value={a.severity} />, ids: (a.sample_ids || []).slice(0, 5).join(", ") || "—" }))}
        columns={[["n", "#"], ["sev", "Severity"], ["question", "Ask the entity"], ["request", "Request"], ["evidence", "Why (evidence)"], ["ids", "Pull first"]]}
        empty="No supervisory signals — routine review." />
      {(data.declared_vs_observed || []).length > 0 && (
        <Table rows={data.declared_vs_observed.map((x: AnyRecord) => ({ ...x, verdict: <Badge value={x.verdict} /> }))}
          columns={[["label", "Declared metric"], ["declared", "Declared %"], ["observed", "Evidenced %"], ["gap", "Gap"], ["verdict", "Verdict"]]} />
      )}
      <div className="method">Case sample: {(data.case_sample || []).slice(0, 10).map((c: AnyRecord) => c.case_id).join(", ")} · plus {(data.control_sample || []).length} random control cases.</div>
    </Panel>
  );
}
