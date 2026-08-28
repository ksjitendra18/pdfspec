import { useState } from "react";

interface PdfFinding {
  rule: string;
  severity: string;
  detail: string;
}

interface ScanResult {
  allowed: boolean;
  isValidPdf: boolean;
  fileName: string | null;
  sizeBytes: number;
  summary: string;
  reasons: string[];
  findings: PdfFinding[];
}

// Use the same-origin Vite proxy in development and the deployed origin in production.
// An explicit URL can still be supplied for split deployments.
const API_URL = import.meta.env.VITE_API_URL?.trim() || "/api/pdf/validate";
const MAX_FILE_BYTES = Number(import.meta.env.VITE_MAX_PDF_BYTES) || 10 * 1024 * 1024;

const severityColor = (severity: string) =>
  severity.toLowerCase() === "high" ? "var(--danger)" : "var(--warn)";

function isScanResult(value: unknown): value is ScanResult {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<ScanResult>;
  return (
    typeof candidate.allowed === "boolean" &&
    typeof candidate.isValidPdf === "boolean" &&
    typeof candidate.summary === "string" &&
    typeof candidate.sizeBytes === "number" &&
    Array.isArray(candidate.reasons) &&
    Array.isArray(candidate.findings)
  );
}

function apiErrorMessage(payload: unknown, status: number): string {
  if (typeof payload === "object" && payload !== null) {
    const problem = payload as { title?: unknown; detail?: unknown; errors?: unknown };
    if (typeof problem.detail === "string") return problem.detail;
    if (typeof problem.title === "string") return problem.title;
    if (typeof problem.errors === "object" && problem.errors !== null) {
      const messages = Object.values(problem.errors)
        .flatMap((value) => (Array.isArray(value) ? value : []))
        .filter((value): value is string => typeof value === "string");
      if (messages.length > 0) return messages.join(" ");
    }
  }
  return `Server responded with HTTP ${status}.`;
}

export default function App() {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [transportError, setTransportError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!file) {
      setTransportError("Please choose a PDF file first.");
      setResult(null);
      return;
    }

    setBusy(true);
    setTransportError(null);
    setResult(null);

    try {
      const form = new FormData();
      form.append("file", file);

      const res = await fetch(API_URL, { method: "POST", body: form });
      const responseText = await res.text();
      let payload: unknown = null;
      if (responseText) {
        try {
          payload = JSON.parse(responseText);
        } catch {
          throw new Error(`The server returned an invalid response (HTTP ${res.status}).`);
        }
      }

      if (isScanResult(payload)) {
        setResult(payload);
      } else if (!res.ok) {
        throw new Error(apiErrorMessage(payload, res.status));
      } else {
        throw new Error("The server response did not match the PDF scan contract.");
      }
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Network error reaching the API.";
      setTransportError(message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card">
      <h1>PDF Security Uploader</h1>
      <p className="muted">
        Upload a PDF. The server scans it for embedded scripts, dangerous links
        and file payloads, and rejects anything suspicious.
      </p>

      <form onSubmit={handleSubmit}>
        <input
          type="file"
          accept="application/pdf,.pdf"
          onChange={(e) => {
            const selected = e.target.files?.[0] ?? null;
            if (selected && selected.size > MAX_FILE_BYTES) {
              setFile(null);
              setTransportError(
                `The selected file exceeds the ${Math.floor(MAX_FILE_BYTES / 1024 / 1024)} MB limit.`,
              );
              e.target.value = "";
              setResult(null);
              return;
            }
            setFile(selected);
            setResult(null);
            setTransportError(null);
          }}
        />
        <button type="submit" disabled={busy || !file}>
          {busy ? "Scanning…" : "Scan PDF"}
        </button>
      </form>

      {transportError && <div className="banner error">{transportError}</div>}

      {result && (
        <div className={result.allowed ? "banner ok" : "banner danger"}>
          <strong>
            {result.allowed ? "✅ PDF allowed" : "⛔ PDF not allowed"}
          </strong>
          <p>{result.summary}</p>
          {!result.allowed && (
            <ul>
              {result.reasons.map((reason, i) => (
                <li key={i}>{reason}</li>
              ))}
            </ul>
          )}
          {result.findings.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Rule</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {result.findings.map((f, i) => (
                  <tr key={i}>
                    <td>
                      <span
                        className="pill"
                        style={{ color: severityColor(f.severity) }}
                      >
                        {f.severity}
                      </span>
                    </td>
                    <td>{f.rule}</td>
                    <td className="small">{f.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
