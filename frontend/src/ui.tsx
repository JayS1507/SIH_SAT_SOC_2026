import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Area, AreaChart,
  Pie, PieChart, Radar, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis, ZAxis,
} from "recharts";
import { get } from "./api";

export type AnyRecord = Record<string, any>;

// ---------------------------------------------------------------- filters
export interface Filters { sector: string; entity: string; severity: string; status: string; }
export const FilterCtx = createContext<{ f: Filters; set: (p: Partial<Filters>) => void }>({ f: { sector: "", entity: "", severity: "", status: "" }, set: () => {} });
export const useFilters = () => useContext(FilterCtx);

export function useFetch<T>(path: string, params?: Record<string, string | number | undefined>) {
  const [state, setState] = useState<{ data: T | null; loading: boolean; error: string }>({ data: null, loading: true, error: "" });
  useEffect(() => {
    let live = true;
    setState({ data: null, loading: true, error: "" });
    get<T>(path, params)
      .then((data) => live && setState({ data, loading: false, error: "" }))
      .catch((e) => live && setState({ data: null, loading: false, error: e.message }));
    return () => { live = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, JSON.stringify(params)]);
  return state;
}

// ---------------------------------------------------------------- primitives
export function Loading() { return <div className="state">Loading supervisory data…</div>; }
export function ErrorState({ message }: { message: string }) {
  return <div className="state error-state"><b>Unable to load this view</b><span>{message}</span></div>;
}
export function Empty({ message }: { message?: string }) {
  return <div className="state">{message || "No sufficient evidence for this analysis."}</div>;
}

const badgeClass = (v: unknown) => String(v ?? "—").toLowerCase().replace(/[^a-z0-9]+/g, "-");
export function Badge({ value }: { value?: string | number }) {
  const text = String(value ?? "—");
  return <span className={`badge b-${badgeClass(value)}`}>{text.replaceAll("_", " ")}</span>;
}

export function Card({ label, value, hint, tone = "", to }: { label: string; value: any; hint?: string; tone?: string; to?: string }) {
  const inner = (<><span>{label}</span><strong className={tone}>{value ?? "—"}</strong>{hint && <small>{hint}</small>}</>);
  return to ? <Link className="kpi kpi-link" to={to}>{inner}</Link> : <div className="kpi">{inner}</div>;
}

export function Page({ title, subtitle, children, actions }: { title: string; subtitle?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page">
      <div className="page-head">
        <div><div className="eyebrow">SUPERVISORY ANALYTICS · SAT-SA</div><h1>{title}</h1>{subtitle && <p>{subtitle}</p>}</div>
        {actions}
      </div>
      {children}
    </div>
  );
}

export function Panel({ title, subtitle, children, className = "" }: { title?: string; subtitle?: string; children: ReactNode; className?: string }) {
  return (
    <section className={`panel ${className}`}>
      {title && <div className="panel-title"><h2>{title}</h2>{subtitle && <small>{subtitle}</small>}</div>}
      {children}
    </section>
  );
}

export function Disclaimer() {
  return (
    <div className="notice warn">
      <b>SYNTHETIC DEMONSTRATION DATA.</b> Simulated SOC records created for demonstration and testing purposes.
      This does not represent the actual cybersecurity posture, compliance status, incidents, or performance of the named organizations.
    </div>
  );
}

export function Table({ rows, columns, empty }: { rows: AnyRecord[]; columns: [string, string][]; empty?: string }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{columns.map(([key, label]) => <th key={key}>{label}</th>)}</tr></thead>
        <tbody>
          {rows.length ? rows.map((row, i) => (
            <tr key={row.id || row.finding_id || row.alert_id || row.entity_id || i}>
              {columns.map(([key]) => {
                const value = row[key];
                const isBadge = ["severity", "status", "risk_level", "review_status", "compliance_state", "monitoring_status", "escalation_status", "action", "recommended_action"].includes(key);
                return (
                  <td key={key}>
                    {isBadge ? <Badge value={value} /> : value && typeof value === "object" ? (value.$$typeof ? value : <details><summary>{Array.isArray(value) ? `${value.length} items` : "detail"}</summary><pre>{JSON.stringify(value, null, 1).slice(0, 2000)}</pre></details>) : String(value ?? "—")}
                  </td>
                );
              })}
            </tr>
          )) : <tr><td colSpan={columns.length}>{empty || "No records match the current scope."}</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

export function FilterBar({ showStatus = false, sectors }: { showStatus?: boolean; sectors?: string[] }) {
  const { f, set } = useFilters();
  return (
    <div className="filters">
      <label>Sector
        <select value={f.sector} onChange={(e) => set({ sector: e.target.value })}>
          <option value="">All sectors</option>
          {(sectors || []).map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </label>
      <label>Severity
        <select value={f.severity} onChange={(e) => set({ severity: e.target.value })}>
          <option value="">All</option>
          {["critical", "high", "medium", "low"].map((x) => <option key={x} value={x}>{x}</option>)}
        </select>
      </label>
      {showStatus && (
        <label>Compliance
          <select value={f.status} onChange={(e) => set({ status: e.target.value })}>
            <option value="">All</option>
            {["COMPLIANT", "PARTIALLY_COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_EVIDENCE"].map((x) => <option key={x} value={x}>{x}</option>)}
          </select>
        </label>
      )}
      {(f.sector || f.severity || f.status) && <button className="button ghost" onClick={() => set({ sector: "", severity: "", status: "" })}>Clear</button>}
    </div>
  );
}

// ---------------------------------------------------------------- charts
export const COLORS = ["#2f7ea6", "#d79a4b", "#c0392b", "#7892b4", "#3fa37c", "#8e6fb8", "#c96a9b", "#5bb5ae", "#9b8b5f", "#60758a", "#e06c5b", "#4d9abb"];
export const SEV_COLORS: Record<string, string> = { critical: "#c0392b", high: "#d97a2b", medium: "#d9b02b", low: "#3fa37c", unknown: "#9099a3" };
export const STATUS_COLORS: Record<string, string> = { COMPLIANT: "#3fa37c", PARTIALLY_COMPLIANT: "#d9b02b", NON_COMPLIANT: "#c0392b", INSUFFICIENT_EVIDENCE: "#7892b4", NOT_ASSESSED: "#9099a3" };

function ChartShell({ children, data, height }: { children: ReactNode; data: unknown[]; height?: number }) {
  if (!data || data.length === 0) return <Empty />;
  return <ResponsiveContainer width="100%" height={height || 260}>{children as any}</ResponsiveContainer>;
}

export function Donut({ data, colors }: { data: { name: string; value: number; pct?: number }[]; colors?: Record<string, string> }) {
  const total = data.reduce((s, d) => s + (d.value || 0), 0);
  return (
    <ChartShell data={data}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" outerRadius={88} innerRadius={52} label={(e: any) => `${e.name}: ${e.value} (${total ? Math.round((e.value / total) * 100) : 0}%)`} labelLine={false}>
          {data.map((d, i) => <Cell key={i} fill={(colors && colors[d.name]) || COLORS[i % COLORS.length]} />)}
        </Pie>
        <Tooltip formatter={(v: any) => [v, "count"]} />
        <Legend />
      </PieChart>
    </ChartShell>
  );
}

export function Bars({ data, xKey = "name", bars, layout = "horizontal", height }: { data: AnyRecord[]; xKey?: string; bars: { key: string; color?: string; name?: string }[]; layout?: "horizontal" | "vertical"; height?: number }) {
  if (layout === "vertical") {
    return (
      <ChartShell data={data} height={height || Math.max(260, data.length * 34)}>
        <BarChart data={data} layout="vertical" margin={{ top: 8, right: 24, bottom: 4, left: 90 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#dce6ef" />
          <XAxis type="number" tick={{ fontSize: 11 }} />
          <YAxis type="category" dataKey={xKey} tick={{ fontSize: 11 }} width={120} />
          <Tooltip />
          <Legend />
          {bars.map((b, i) => <Bar key={b.key} dataKey={b.key} name={b.name || b.key} fill={b.color || COLORS[i % COLORS.length]} radius={[0, 4, 4, 0]} />)}
        </BarChart>
      </ChartShell>
    );
  }
  return (
    <ChartShell data={data} height={height}>
      <BarChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: -8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#dce6ef" />
        <XAxis dataKey={xKey} tick={{ fontSize: 11 }} interval={Math.max(0, Math.floor(data.length / 10) - 0)} angle={data.length > 8 ? -25 : 0} dy={data.length > 8 ? 8 : 0} height={data.length > 8 ? 52 : 30} />
        <YAxis tick={{ fontSize: 11 }} />
        <Tooltip />
        <Legend />
        {bars.map((b, i) => <Bar key={b.key} dataKey={b.key} name={b.name || b.key} fill={b.color || COLORS[i % COLORS.length]} radius={[4, 4, 0, 0]} />)}
      </BarChart>
    </ChartShell>
  );
}

export function Trend({ data, xKey = "month", series }: { data: AnyRecord[]; xKey?: string; series: { key: string; color?: string; name?: string; area?: boolean }[] }) {
  const C: any = series.some((s) => s.area) ? AreaChart : LineChart;
  return (
    <ChartShell data={data} height={280}>
      <C data={data} margin={{ top: 8, right: 12, bottom: 4, left: -8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#dce6ef" />
        <XAxis dataKey={xKey} tick={{ fontSize: 11 }} />
        <YAxis tick={{ fontSize: 11 }} />
        <Tooltip />
        <Legend />
        {series.map((s, i) =>
          s.area
            ? <Area key={s.key} type="monotone" dataKey={s.key} name={s.name || s.key} stroke={s.color || COLORS[i % COLORS.length]} fill={s.color || COLORS[i % COLORS.length]} fillOpacity={0.25} />
            : <Line key={s.key} type="monotone" dataKey={s.key} name={s.name || s.key} stroke={s.color || COLORS[i % COLORS.length]} strokeWidth={2.5} dot={false} />
        )}
      </C>
    </ChartShell>
  );
}

export function ScatterPlot({ data }: { data: { x: number; y: number; name: string; status: string }[] }) {
  const groups: Record<string, typeof data> = {};
  data.forEach((d) => { (groups[d.status] = groups[d.status] || []).push(d); });
  const entries = Object.entries(groups);
  if (!entries.length) return <Empty />;
  return (
    <ResponsiveContainer width="100%" height={300}>
      <ScatterChart margin={{ top: 8, right: 16, bottom: 8, left: -8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#dce6ef" />
        <XAxis type="number" dataKey="x" name="Compliance" unit="%" tick={{ fontSize: 11 }} domain={[0, 100]} label={{ value: "Compliance score →", position: "insideBottom", offset: -2, fontSize: 11 }} />
        <YAxis type="number" dataKey="y" name="Risk" tick={{ fontSize: 11 }} domain={[0, 100]} label={{ value: "Risk →", angle: -90, position: "insideLeft", fontSize: 11 }} />
        <ZAxis type="category" dataKey="name" name="Entity" />
        <Tooltip cursor={{ strokeDasharray: "3 3" }} />
        <Legend />
        {entries.map(([status, pts]) => <Scatter key={status} name={status.replaceAll("_", " ")} data={pts} fill={STATUS_COLORS[status] || "#60758a"} />)}
      </ScatterChart>
    </ResponsiveContainer>
  );
}

export function RadarPlot({ data, keys }: { data: AnyRecord[]; keys: { key: string; color: string; name: string }[] }) {
  if (!data.length) return <Empty />;
  return (
    <ResponsiveContainer width="100%" height={300}>
      <RadarChart data={data} outerRadius="70%">
        <PolarGrid />
        <PolarAngleAxis dataKey="metric" tick={{ fontSize: 10 }} />
        <PolarRadiusAxis domain={[0, 100]} tick={false} />
        {keys.map((k) => <Radar key={k.key} name={k.name} dataKey={k.key} stroke={k.color} fill={k.color} fillOpacity={0.25} />)}
        <Legend />
        <Tooltip />
      </RadarChart>
    </ResponsiveContainer>
  );
}

export function FunnelView({ stages }: { stages: { stage: string; count: number; coverage_pct?: number; conversion_pct?: number }[] }) {
  if (!stages.length) return <Empty />;
  const max = Math.max(1, ...stages.map((s) => s.count));
  return (
    <div className="funnel">
      {stages.map((s) => (
        <div className="funnel-row" key={s.stage}>
          <b>{s.stage}</b>
          <div className="funnel-bar"><em style={{ width: `${Math.max(2, Math.round((s.count / max) * 100))}%` }} /></div>
          <span>{s.count.toLocaleString()}{s.coverage_pct != null ? ` · ${s.coverage_pct}% of alerts` : ""}</span>
        </div>
      ))}
    </div>
  );
}
