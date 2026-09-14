export const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000/api/v1";

export async function get<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
  const entries = Object.entries(params || {}).filter(([, value]) => value !== undefined && value !== "") as [string, string][];
  const query = entries.length ? `?${new URLSearchParams(entries.map(([k, v]) => [k, String(v)])).toString()}` : "";
  const response = await fetch(`${API}${path}${query}`);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || body.detail || `Request failed (${response.status})`);
  return body as T;
}

export async function post<T>(path: string, payload: unknown): Promise<T> {
  const response = await fetch(`${API}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || body.detail || `Request failed (${response.status})`);
  return body as T;
}

export async function patch<T>(path: string, payload: unknown): Promise<T> {
  const response = await fetch(`${API}${path}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || body.detail || `Request failed (${response.status})`);
  return body as T;
}

export async function downloadReport(format: "json" | "html" | "pdf", params?: Record<string, string | undefined>): Promise<void> {
  const entries = Object.entries({ format, ...(params || {}) }).filter(([, v]) => v) as [string, string][];
  const res = await fetch(`${API}/sat/report?${new URLSearchParams(entries).toString()}`);
  if (!res.ok) throw new Error("Report generation failed");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sat-sa-report.${format === "pdf" ? "pdf" : format === "html" ? "html" : "json"}`;
  a.click();
  URL.revokeObjectURL(url);
}
