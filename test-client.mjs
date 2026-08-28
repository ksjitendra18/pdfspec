// Browser-like integration test that mirrors exactly what src/App.tsx does:
// POST a FormData with a 'file' field to /api/pdf/validate and read the verdict.
import { readFileSync } from 'node:fs'

const API = 'http://localhost:5111/api/pdf/validate'

async function scan(name, data) {
  const form = new FormData()
  form.append('file', new Blob([data], { type: 'application/pdf' }), name)

  const res = await fetch(API, { method: 'POST', body: form })
  const json = await res.json()
  console.log(`\n=== ${name} (${data.length} bytes) ===`)
  console.log(`HTTP ${res.status}  allowed=${json.allowed}  validPdf=${json.isValidPdf}`)
  console.log(`summary: ${json.summary}`)
  for (const r of json.reasons ?? []) console.log(`  reason: ${r}`)
  return json.allowed
}

async function main() {
  // 1. Benign PDF -> expected allowed=true
  const benign = readFileSync('D:/pdfsecurity/benign.pdf')
  const allowedBenign = await scan('benign.pdf', benign)

  // 2. Malicious PDF built in memory (matches the GitHub payloads' technique) -> allowed=false
  const malicious = Buffer.from(
    `%PDF-1.5\n` +
    `1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n` +
    `2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n` +
    `3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >> endobj\n` +
    `4 0 obj << /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /JavaScript /JS (app.alert(1); app.launchURL("file:///C:/Windows/system32/calc.exe", true);) >> >> endobj\n` +
    `%%EOF`,
    'latin1'
  )
  const allowedMalicious = await scan('payload-malicious.pdf', malicious)

  console.log('\n===================== RESULT =====================')
  console.log(`benign allowed    : ${allowedBenign}   (expect true)`)
  console.log(`malicious allowed : ${allowedMalicious}   (expect false)`)

  if (allowedBenign !== true || allowedMalicious !== false) {
    console.log('FAIL: expected benign=true and malicious=false')
    process.exit(1)
  }
  console.log('PASS: frontend request contract works as expected.')
}

main().catch((e) => {
  console.error('ERROR:', e)
  process.exit(1)
})
