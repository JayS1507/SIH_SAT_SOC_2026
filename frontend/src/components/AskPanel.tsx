import { FormEvent, useState } from "react";

type AskPanelProps = {
  api: string;
  assessmentId: string;
};

export function AskPanel({ api, assessmentId }: AskPanelProps) {
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("");
  const [busy, setBusy] = useState(false);

  async function ask(event: FormEvent) {
    event.preventDefault();
    if (!question.trim()) return;
    setBusy(true);
    setAnswer("");
    try {
      const response = await fetch(`${api}/assessments/${assessmentId}/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Question failed");
      setAnswer(body.answer || JSON.stringify(body));
    } catch (reason) {
      setAnswer(reason instanceof Error ? reason.message : "Question failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel">
      <div className="panel-title"><h2>Ask the evidence</h2><small>Deterministic answers grounded in findings</small></div>
      <form onSubmit={ask} className="submission-form">
        <label>Question <input value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="Which entities missed required escalations?" /></label>
        <button className="button primary" disabled={busy}>{busy ? "Answering…" : "Ask"}</button>
      </form>
      {answer && <p>{answer}</p>}
    </section>
  );
}
