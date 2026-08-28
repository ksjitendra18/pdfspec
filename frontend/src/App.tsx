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

// The Vite dev server proxies /api -> http://localhost:5111 (see vite.config.ts)
// so the browser never needs to know the absolute backend URL.
const API_URL = "http://localhost:5111/api/pdf/validate";

const severityColor = (severity: string) =>
  severity.toLowerCase() === "high" ? "var(--danger)" : "var(--warn)";

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
      const payload = (await res.json()) as ScanResult;

      // The API returns HTTP 200 with allowed=false for blocked files.
      // Treat an HTTP error only as a transport/protocol failure below.
      if (!res.ok && payload == null) {
        throw new Error(`Server responded with ${res.status}`);
      }

      setResult(payload);
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
            setFile(e.target.files?.[0] ?? null);
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
