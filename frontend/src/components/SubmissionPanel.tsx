import { ChangeEvent, FormEvent, useState } from "react";

type SubmissionPanelProps = {
  api: string;
  onSubmitted: () => void;
};

type Mode = "file" | "paste";

export function SubmissionPanel({ api, onSubmitted }: SubmissionPanelProps) {
  const [mode, setMode] = useState<Mode>("file");
  const [file, setFile] = useState<File | null>(null);
  const [paste, setPaste] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  function selectFile(event: ChangeEvent<HTMLInputElement>) {
    setFile(event.target.files?.[0] || null);
    setMessage("");
    setError("");
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setMessage("");
    setError("");
    try {
      let response: Response;
      if (mode === "file") {
        if (!file) throw new Error("Choose a CSV, JSON, XLSX or SQL export first.");
        const form = new FormData();
        form.append("file", file);
        response = await fetch(`${api}/submissions`, { method: "POST", body: form });
      } else {
        if (!paste.trim()) throw new Error("Paste at least one JSON or key=value log row.");
        response = await fetch(`${api}/submissions/paste`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: name.trim() || "Pasted submission", text: paste }),
        });
      }
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || body.detail || `Submission failed (${response.status}).`);
      const assessment = await fetch(`${api}/assessments`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ submission_id: body.id, requested_by: "supervisor" }),
      });
      if (!assessment.ok) throw new Error("Submission saved, but assessment failed to start.");
      setMessage(`Added ${body.quality?.rows ?? body.records?.length ?? 0} records and started assessment. Dataset SHA-256: ${String(body.content_sha256 || "").slice(0, 16)}…`);
      setFile(null);
      setPaste("");
      onSubmitted();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Submission failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel submission-panel">
      <div className="panel-title">
        <h2>Upload submission</h2>
        <small>CSV · JSON · XLSX · SQL — hashed (SHA-256) and audit-logged</small>
      </div>
      <div className="filters" role="tablist" aria-label="Submission input type">
        <button className={mode === "file" ? "button primary" : "button"} onClick={() => setMode("file")} type="button">File upload</button>
        <button className={mode === "paste" ? "button primary" : "button"} onClick={() => setMode("paste")} type="button">Paste logs</button>
      </div>
      <form className="submission-form" onSubmit={submit}>
        <label>Submission name <input value={name} onChange={(event) => setName(event.target.value)} placeholder="e.g. September SOC export" /></label>
        {mode === "file" ? (
          <label>Data file
            <input type="file" accept=".csv,.json,.sql,.dump,.xlsx,.xlsm" onChange={selectFile} />
            <small>Try examples/sat_sa_demo_soc.csv — maximum 10 MB / 10,000 rows.</small>
          </label>
        ) : (
          <label>Paste one record per line
            <textarea value={paste} onChange={(event) => setPaste(event.target.value)}
              placeholder={'{"entity_id":"bel","severity":"high","timestamp":"2026-09-14T08:00:00Z"}\nentity_id=bel severity=critical alert_id=alert-7'} rows={3} />
          </label>
        )}
        <button className="button primary" type="submit" disabled={busy}>{busy ? "Adding..." : "Add submission + assess"}</button>
      </form>
      {message && <p className="notice">{message}</p>}
      {error && <p className="notice warn">{error}</p>}
    </section>
  );
}
