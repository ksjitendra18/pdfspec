// Browser-like integration test that mirrors exactly what src/App.tsx does:
// POST a FormData with a 'file' field to /api/pdf/validate and read the verdict.
import { readFileSync } from 'node:fs'

const API = process.env.PDF_SECURITY_API ?? 'http://localhost:5111/api/pdf/validate'

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
  const benign = readFileSync(new URL('./benign.pdf', import.meta.url))
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

  // 3. Standard PDF name escapes and a hexadecimal JavaScript string must not bypass scanning.
  const escaped = buildPdf([
    '<< /Type /Catalog /Pages 2 0 R /Open#41ction 4 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>',
    '<< /S /J#61vaScript /J#53 <6170702e616c657274283129> >>'
  ])
  const allowedEscaped = await scan('payload-escaped.pdf', escaped)

  console.log('\n===================== RESULT =====================')
  console.log(`benign allowed    : ${allowedBenign}   (expect true)`)
  console.log(`malicious allowed : ${allowedMalicious}   (expect false)`)
  console.log(`escaped allowed   : ${allowedEscaped}   (expect false)`)

  if (allowedBenign !== true || allowedMalicious !== false || allowedEscaped !== false) {
    console.log('FAIL: one or more API contract checks did not match')
    process.exit(1)
  }
  console.log('PASS: frontend request contract works as expected.')
}

function buildPdf(objects) {
  let document = '%PDF-1.7\n'
  const offsets = [0]
  for (let index = 0; index < objects.length; index++) {
    offsets.push(Buffer.byteLength(document, 'latin1'))
    document += `${index + 1} 0 obj\n${objects[index]}\nendobj\n`
  }
  const xrefOffset = Buffer.byteLength(document, 'latin1')
  document += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  for (const offset of offsets.slice(1)) {
    document += `${String(offset).padStart(10, '0')} 00000 n \n`
  }
  document += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n`
  document += `startxref\n${xrefOffset}\n%%EOF\n`
  return Buffer.from(document, 'latin1')
}

main().catch((e) => {
  console.error('ERROR:', e)
  process.exit(1)
})
