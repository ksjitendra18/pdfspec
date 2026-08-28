# PDF Security — Upload Scanner

A `.NET` **ASP.NET Core Web API** that validates PDF uploads and rejects dangerous files, plus a
**React + TypeScript** frontend that calls it and shows an error when a PDF is not allowed.

> The endpoint was validated against the real malicious PDFs in [`payloads/`](payloads/) (the
> [`PayloadsAllThePDFs`](https://github.com/luigigubello/PayloadsAllThePDFs) GitHub repo, which
> Windows Defender quarantines on read). **All 11 payloads are blocked; a clean PDF is accepted.**

## What the scanner catches

`backend/Security/PdfSecurity.cs` inspects the raw bytes *and* any decompressed `FlateDecode`
streams, flagging:

- **Embedded JavaScript** — Acrobat `/JS`, `/JavaScript`, `app.alert/launchURL/openDoc`, `document.write`,
  `eval`, `new Function`, XFA `/XFA`, `/OpenAction`.
- **Dangerous / external links** — `/URI` actions, `data:`, `javascript:`, `vbscript:`, `file:`, `http(s)://`.
- **OS command execution** — `calc.exe`, `cmd.exe`, `powershell`, `rundll32`, `certutil`, `START C:\…`.
- **Embedded / attached files** — `/EmbeddedFile`, `/Filespec`, `/Launch`.
- **HTML / XSS injection** inside annotations — `<script>`, `<iframe>`, `<details ontoggle=…>`,
  `onload/onerror/…=` event handlers.
- **`/FontMatrix` JS injection** — e.g. the PDF.js CVE-2024-4367 PoC (`payload8.pdf`).

Rules are driven by the `PdfSecurity` configuration section in `appsettings.json`.

## Project layout

```
backend/        ASP.NET Core Web API (net10.0)
  Security/
    PdfSecurity.cs              # the validation engine
    PdfSecurityOptions.cs       # configurable toggles / limits
    PdfValidationResult.cs      # verdict DTO
  Controllers/PdfController.cs  # POST /api/pdf/validate + GET /api/pdf/health
  Models/PdfScanResponse.cs     # API response
frontend/       React 18 + TypeScript + Vite
  src/App.tsx                   # file upload -> POST form -> show pass/error
benign.pdf      a clean sample PDF for testing the "allowed" path
test-client.mjs a browser-like Node client that exercises the API contract
```

## Run the API

```powershell
cd backend
dotnet run -c Release --urls http://localhost:5111
```

Health probe: `GET http://localhost:5111/api/pdf/health`

## Run the frontend

```powershell
cd frontend
npm install
npm run dev        # http://localhost:5173  (proxies /api -> :5111)
```

Pick any PDF. The Vite dev server doesn't bundle a sample, so use `benign.pdf` (allowed) or a file
from `payloads/pdf-payloads/` (blocked — though Windows Defender may quarantine those on disk).

### API contract
`POST /api/pdf/validate` (multipart/form-data, field `file`):

```jsonc
{
  "allowed": false,            // ← false => NOT allowed, show the error
  "isValidPdf": true,
  "fileName": "payload5.pdf",
  "sizeBytes": 8687,
  "summary": "Blocked: 14 dangerous construct(s) detected.",
  "reasons": [ "Acrobat JavaScript API: …", "javascript: URI: …" ],
  "findings": [ { "rule": "Acrobat JavaScript API", "severity": "High", "detail": "…" } ]
}
```

HTTP 200 is returned for both verdicts (`allowed` tells you which). HTTP 400 is used for a missing
file or a non-PDF extension/content-type.

## Notes

- `dotnet run` was started with console-only logging. The default Windows EventLog logging provider
  threw `Access is denied` on this machine and aborted requests that logged a rejection, so
  `Program.cs` calls `builder.Logging.ClearProviders()` + `AddConsole()`.
- The malicious payloads in `payloads/` are quarantined by Windows Defender and cannot be read from
  disk by .NET/Node; the tests extract them from the git pack in memory to stay AV-safe.
