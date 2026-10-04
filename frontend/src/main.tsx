import { useState } from "react";
import { BrowserRouter, Link, NavLink, Route, Routes } from "react-router-dom";
import "./styles.css";
import { API } from "./api";
import { FilterCtx, Page, Panel, type Filters } from "./ui";
import { SubmissionPanel } from "./components/SubmissionPanel";
import Overview from "./pages/Overview";
import { Entities, EntityDetail } from "./pages/Entities";
import { Alerts, Investigations, Escalations, Monitoring, Gaps } from "./pages/Ops";
import { Findings, FindingDetail, Review, Peer, Quality, Reports, Audit } from "./pages/Gov";
import { Validation, PaperVsPractice } from "./pages/Assurance";

const nav = [
  ["Overview", "/", "⌂"], ["Entities", "/entities", "◈"], ["Alerts", "/alerts", "◉"],
  ["Investigations", "/investigations", "⌕"], ["Escalations", "/escalations", "↗"],
  ["Monitoring", "/monitoring", "◌"], ["Execution gaps", "/execution-gaps", "△"],
  ["Paper vs practice", "/paper-vs-practice", "⇄"], ["Findings", "/findings", "▣"], ["Review queue", "/review", "✓"],
  ["Peer benchmark", "/peer-benchmark", "▥"], ["Data quality", "/data-quality", "◇"],
  ["Submissions", "/submissions", "⇧"], ["Reports", "/reports", "▤"], ["Audit trail", "/audit", "◫"],
  ["Validation", "/validation", "✔"],
];

function Submissions() {
  return (
    <Page title="Submissions" subtitle="Upload SOC evidence: CSV, JSON, XLSX, SQL export or pasted logs">
      <Panel><SubmissionPanel api={API} onSubmitted={() => window.location.reload()} /></Panel>
      <Panel title="Demonstration dataset" subtitle="Relational, internally consistent synthetic evidence">
        <p className="summary">Use <code>examples/sat_sa_demo_soc.csv</code> (21 entities, 40 columns) and <code>examples/sat_sa_self_assessment.csv</code> on the Paper vs practice page to demonstrate the full platform: compliant and non-compliant workflows, missing escalations, investigation gaps, duplicates and reporting gaps.</p>
      </Panel>
    </Page>
  );
}

function Shell() {
  const [f, setF] = useState<Filters>({ sector: "", entity: "", severity: "", status: "" });
  const set = (p: Partial<Filters>) => setF((prev) => ({ ...prev, ...p }));
  return (
    <FilterCtx.Provider value={{ f, set }}>
      <div className="app-shell">
        <aside>
          <Link to="/" className="brand"><span>SAT-SA</span><b>SOC-Inspect</b><small>Supervisory workspace</small></Link>
          <nav>{nav.map(([label, path, icon]) => <NavLink key={path} to={path} end={path === "/"}><i>{icon}</i>{label}</NavLink>)}</nav>
          <div className="side-foot">LOCAL API<br /><b>{API.replace(/^https?:\/\//, "")}</b></div>
        </aside>
        <main className="content">
          <header>
            <span>Evidence-grounded supervisory review · Synthetic demonstration data</span>
            <span className="connection"><i /> Offline-ready</span>
          </header>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/entities" element={<Entities />} />
            <Route path="/entities/:id" element={<EntityDetail />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/investigations" element={<Investigations />} />
            <Route path="/escalations" element={<Escalations />} />
            <Route path="/monitoring" element={<Monitoring />} />
            <Route path="/execution-gaps" element={<Gaps />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="/review" element={<Review />} />
            <Route path="/peer-benchmark" element={<Peer />} />
            <Route path="/data-quality" element={<Quality />} />
            <Route path="/submissions" element={<Submissions />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/validation" element={<Validation />} />
            <Route path="/paper-vs-practice" element={<PaperVsPractice />} />
          </Routes>
        </main>
      </div>
    </FilterCtx.Provider>
  );
}

function App() { return <BrowserRouter><Shell /></BrowserRouter>; }

import { createRoot } from "react-dom/client";
createRoot(document.getElementById("root")!).render(<App />);
