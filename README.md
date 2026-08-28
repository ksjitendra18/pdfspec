# PDF Security — Upload Scanner

A `.NET` **ASP.NET Core Web API** that validates PDF uploads and rejects dangerous or unscannable
files, plus a **React + TypeScript** frontend that calls it and shows the verdict.

> The endpoint was validated against the real malicious PDFs in [`payloads/`](payloads/) (the
> [`PayloadsAllThePDFs`](https://github.com/luigigubello/PayloadsAllThePDFs) GitHub repo, which
> Windows Defender quarantines on read). **All 11 payloads are blocked; a clean PDF is accepted.**

## What the scanner catches

`backend/Security/PdfSecurity.cs` normalizes PDF name and string encodings and inspects raw bytes
plus bounded, decoded general-purpose streams, flagging:

- **Embedded JavaScript** — Acrobat `/JS`, `/JavaScript`, `app.alert/launchURL/openDoc`, `document.write`,
  `eval`, `new Function`, and XFA `/XFA`.
- **Dangerous / external links** — `/URI` actions, `data:`, `javascript:`, `vbscript:`, `file:`, `http(s)://`.
- **OS command execution** — `calc.exe`, `cmd.exe`, `powershell`, `rundll32`, `certutil`, `START C:\…`.
- **Embedded / attached files** — `/EmbeddedFile`, `/Filespec`, `/Launch`.
- **HTML / XSS injection** inside annotations — `<script>`, `<iframe>`, `<details ontoggle=…>`,
  `onload/onerror/…=` event handlers.
- **`/FontMatrix` JS injection** — e.g. the PDF.js CVE-2024-4367 PoC (`payload8.pdf`).

Rules are driven by the `PdfSecurity` configuration section in `appsettings.json`.

The validator also fails closed for malformed structure, encryption, unsupported non-image stream
filters, corrupt streams, excessive stream counts, and per-stream/global decompression limits.
Name escapes such as `/J#61vaScript` and hexadecimal strings are decoded before matching.

> This gate reports whether configured dangerous constructs were detected; it does not prove that
> an arbitrary PDF viewer has no parsing vulnerability. In a high-assurance production workflow,
> keep uploads quarantined and add a maintained malware scanner and/or content-disarm-and-rebuild
> worker before making files available.

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
backend.tests/  dependency-free security regression test executable
PdfSecurity.slnx one .NET solution for the API and security tests
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

The browser calls the relative `/api/pdf/validate` path. For a split deployment, set
`VITE_API_URL` when building the frontend. Allowed cross-origin development hosts are configured in
the backend's `FrontendOrigins` array; the default is only `http://localhost:5173`.

## Run security regression tests

```powershell
dotnet run --project backend.tests/PdfSecurityApi.SecurityTests.csproj
```

The suite covers a clean document, fake structure, plaintext JavaScript, PDF name escapes,
hexadecimal JavaScript strings, encryption, unsupported filters, decoded ASCIIHex content, and a
decompression-limit bypass.

### API contract
`POST /api/pdf/validate` (multipart/form-data, field `file`):

```jsonc
{
  "allowed": false,            // ← false => NOT allowed, show the error
  "isValidPdf": true,
  "fileName": "payload5.pdf",
  "sizeBytes": 8687,
  "summary": "Blocked: 14 dangerous or unscannable construct(s) detected.",
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
- Some malicious fixtures in `payloads/` may be quarantined by endpoint security software when read.
  The automated regression suite creates its adversarial documents in memory instead.
- Upload scanning is rate- and concurrency-limited, has a request deadline, propagates cancellation,
  and uses bounded per-stream and total decode budgets. Encrypted or incompletely decoded PDFs are
  rejected rather than silently skipped.
