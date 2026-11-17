// DIVISION T82 — native PDF report generation (server-only, pdf-lib).
// Produces a self-contained executive posture report: host, score/coverage,
// status + severity breakdown, category bars, control results, limitations.
// Standard fonts only (no external assets); WinAnsi-safe text sanitization.
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib'
import type { ControlStatus, Severity } from '@/lib/engine/types'
import { computeScore } from '@/lib/engine/types'

// ─── Text sanitization (WinAnsi-safe) ────────────────────────────────────────

const CHAR_MAP: Record<string, string> = {
  '≥': '>=',
  '≤': '<=',
  '→': '->',
  '←': '<-',
  '·': '·',
  '—': '-',
  '–': '-',
  '…': '...',
  '«': '"',
  '»': '"',
  '\u2018': "'",
  '\u2019': "'",
  '\u201c': '"',
  '\u201d': '"',
  '⌘': 'Cmd',
  '⨯': 'x',
  '×': 'x',
}

function safeText(input: string | null | undefined): string {
  if (!input) return ''
  let out = ''
  for (const ch of input) {
    if (CHAR_MAP[ch] !== undefined) {
      out += CHAR_MAP[ch]
      continue
    }
    const code = ch.codePointAt(0) ?? 0
    out += code <= 0xff || code === 0x2022 ? ch : '?' // keep latin-1 + bullet
  }
  return out
}

// ─── Layout constants ────────────────────────────────────────────────────────

const PAGE_W = 595.28
const PAGE_H = 841.89
const MARGIN = 44
const CONTENT_W = PAGE_W - MARGIN * 2

const INK = rgb(0.09, 0.11, 0.14)
const MUTED = rgb(0.45, 0.48, 0.52)
const LINE = rgb(0.82, 0.84, 0.86)
const ACCENT = rgb(0.05, 0.45, 0.35) // T82 green
const ACCENT_BG = rgb(0.93, 0.97, 0.95)
const WARN = rgb(0.72, 0.15, 0.15)
const WARN_BG = rgb(0.98, 0.94, 0.94)
const HEAD_BG = rgb(0.94, 0.95, 0.96)

const STATUS_COLOR: Record<string, ReturnType<typeof rgb>> = {
  PASS: rgb(0.05, 0.5, 0.3),
  FAIL: WARN,
  WARNING: rgb(0.75, 0.55, 0.05),
  NOT_ASSESSED: MUTED,
  NOT_APPLICABLE: MUTED,
  ERROR: WARN,
}

// ─── Types ───────────────────────────────────────────────────────────────────

export interface PdfReportInput {
  scanId: string
  engineVersion: string
  startedAt: Date
  finishedAt: Date | null
  host: {
    hostname: string
    os: string
    osVersion: string
    kernel: string
    arch: string
    user: string
    isRoot: boolean
  }
  results: {
    controlId: string
    controlVersion: string
    controlName: string // JSON {en,es}
    category: string
    severity: string
    status: string
    reason: string | null
    detail: string | null
  }[]
  scope: string[]
  limitations: string
  lang?: 'es' | 'en'
}

interface TextWriter {
  text: (value: string, x: number, y: number, size: number, font: 'regular' | 'bold', color?: ReturnType<typeof rgb>) => number
  width: (value: string, size: number, font: 'regular' | 'bold') => number
}

// ─── Builder ─────────────────────────────────────────────────────────────────

export async function buildPdfReport(input: PdfReportInput): Promise<Uint8Array> {
  const pdf = await PDFDocument.create()
  const regular = await pdf.embedFont(StandardFonts.Helvetica)
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold)
  const mono = await pdf.embedFont(StandardFonts.Courier)
  const monoBold = await pdf.embedFont(StandardFonts.CourierBold)
  const lang = input.lang ?? 'es'

  const score = computeScore(
    input.results.map((r) => ({
      controlId: r.controlId,
      severity: r.severity as Severity,
      status: r.status as ControlStatus,
      category: r.category,
    })),
  )

  let page = pdf.addPage([PAGE_W, PAGE_H])
  let y = PAGE_H - MARGIN
  let pageNo = 1

  const writer: TextWriter = {
    text: (value, x, yy, size, font, color) => {
      page.drawText(safeText(value), {
        x,
        y: yy,
        size,
        font: font === 'bold' ? bold : regular,
        color: color ?? INK,
      })
      return size
    },
    width: (value, size, font) => (font === 'bold' ? bold : regular).widthOfTextAtSize(safeText(value), size),
  }

  const newPage = () => {
    page = pdf.addPage([PAGE_W, PAGE_H])
    pageNo += 1
    y = PAGE_H - MARGIN
    drawPageFooter()
  }

  const ensure = (needed: number) => {
    if (y - needed < MARGIN + 26) newPage()
  }

  const wrap = (value: string, size: number, font: 'regular' | 'bold', maxWidth: number): string[] => {
    const words = safeText(value).split(/\s+/)
    const lines: string[] = []
    let current = ''
    for (const w of words) {
      const candidate = current ? `${current} ${w}` : w
      if (writer.width(candidate, size, font) <= maxWidth || !current) {
        current = candidate
      } else {
        lines.push(current)
        current = w
      }
    }
    if (current) lines.push(current)
    return lines
  }

  const drawPageFooter = () => {
    const footerY = MARGIN - 14
    writer.text(
      lang === 'es'
        ? 'DIVISION T82 - Motor de solo lectura · evidencia trazable · sin telemetría'
        : 'DIVISION T82 - Read-only engine · traceable evidence · no telemetry',
      MARGIN,
      footerY,
      7.5,
      'regular',
      MUTED,
    )
    const pn = `${pageNo}`
    writer.text(pn, PAGE_W - MARGIN - writer.width(pn, 7.5, 'regular'), footerY, 7.5, 'regular', MUTED)
  }

  // ─── Header band ──────────────────────────────────────────────────────────
  page.drawRectangle({ x: MARGIN, y: y - 6, width: CONTENT_W, height: 58, color: ACCENT_BG })
  page.drawRectangle({ x: MARGIN, y: y - 6, width: 5, height: 58, color: ACCENT })
  writer.text('DIVISION T82', MARGIN + 16, y + 28, 9, 'bold', ACCENT)
  writer.text(
    lang === 'es' ? 'Informe de Postura de Seguridad' : 'Security Posture Report',
    MARGIN + 16,
    y + 8,
    16,
    'bold',
    INK,
  )
  writer.text(
    `engine ${input.engineVersion} · ${new Date().toISOString().slice(0, 16).replace('T', ' ')} UTC`,
    MARGIN + 16,
    y - 12,
    8,
    'regular',
    MUTED,
  )
  const authorLine =
    lang === 'es'
      ? 'Creado por Ramón Taboada Olivella · RTO Studio'
      : 'Created by Ramón Taboada Olivella · RTO Studio'
  writer.text(
    authorLine,
    PAGE_W - MARGIN - writer.width(authorLine, 7.5, 'regular'),
    y + 30,
    7.5,
    'regular',
    MUTED,
  )
  y -= 66

  // ─── Host block ───────────────────────────────────────────────────────────
  const hostPairs: [string, string][] = [
    ['host', `${input.host.hostname}`],
    ['os', `${input.host.os} ${input.host.osVersion}`],
    ['kernel', input.host.kernel],
    ['arch', input.host.arch],
    ['assessed as', `${input.host.user}${input.host.isRoot ? ' (root)' : ''}`],
    ['scan id', input.scanId],
  ]
  const colW = CONTENT_W / 2
  const hostStartY = y
  hostPairs.forEach(([k, v], i) => {
    const col = i % 2
    const rowIdx = Math.floor(i / 2)
    const yy = hostStartY - rowIdx * 13
    writer.text(`${k}:`, MARGIN + col * colW, yy, 8, 'bold', MUTED)
    writer.text(v.slice(0, 60), MARGIN + col * colW + 62, yy, 8, 'regular', INK)
  })
  y = hostStartY - Math.ceil(hostPairs.length / 2) * 13 - 10

  // ─── Score band ───────────────────────────────────────────────────────────
  page.drawRectangle({ x: MARGIN, y: y - 48, width: 120, height: 58, color: score.overall != null && score.overall < 50 ? WARN_BG : ACCENT_BG })
  const scoreText = score.overall != null ? `${score.overall.toFixed(1)}` : 'n/a'
  writer.text(scoreText, MARGIN + 14, y - 8, 26, 'bold', score.overall != null && score.overall < 50 ? WARN : ACCENT)
  writer.text(lang === 'es' ? 'PUNTUACIÓN' : 'SCORE', MARGIN + 14, y - 38, 7, 'bold', MUTED)

  page.drawRectangle({ x: MARGIN + 130, y: y - 48, width: 120, height: 58, color: HEAD_BG })
  writer.text(`${score.coverage.toFixed(1)}%`, MARGIN + 144, y - 8, 26, 'bold', INK)
  writer.text(lang === 'es' ? 'COBERTURA' : 'COVERAGE', MARGIN + 144, y - 38, 7, 'bold', MUTED)

  // counts summary to the right of score/coverage
  const countsX = MARGIN + 264
  const statusEntries = Object.entries(score.counts).filter(([, n]) => n > 0)
  statusEntries.forEach(([status, n], i) => {
    const yy = y + 6 - i * 12
    page.drawCircle({ x: countsX + 4, y: yy + 3, size: 3, color: STATUS_COLOR[status] ?? MUTED })
    writer.text(`${status}`, countsX + 12, yy, 8, 'regular', INK)
    writer.text(`${n}`, countsX + 110, yy, 8, 'bold', INK)
  })
  y -= 62

  // ─── Severity breakdown ───────────────────────────────────────────────────
  const sevEntries = Object.entries(score.severityCounts)
  const cellW = CONTENT_W / sevEntries.length
  page.drawRectangle({ x: MARGIN, y: y - 20, width: CONTENT_W, height: 24, color: HEAD_BG })
  sevEntries.forEach(([sev, n], i) => {
    writer.text(sev, MARGIN + i * cellW + 10, y - 12, 7.5, 'bold', MUTED)
    writer.text(`${n}`, MARGIN + i * cellW + cellW - 24, y - 12, 8, 'bold', STATUS_COLOR[sev] ?? INK)
  })
  y -= 34

  // ─── Category bars ────────────────────────────────────────────────────────
  const sectionTitle = (title: string) => {
    ensure(30)
    writer.text(title.toUpperCase(), MARGIN, y, 9.5, 'bold', ACCENT)
    page.drawLine({
      start: { x: MARGIN, y: y - 4 },
      end: { x: PAGE_W - MARGIN, y: y - 4 },
      thickness: 0.7,
      color: LINE,
    })
    y -= 18
  }

  sectionTitle(lang === 'es' ? 'Puntuación por categoría' : 'Category scores')
  const trackEnd = CONTENT_W - 40 // leave room for the % label outside the bar
  for (const cat of score.categories) {
    ensure(16)
    const barX = MARGIN
    const barW = CONTENT_W - 90
    writer.text(cat.category.slice(0, 22), barX, y, 7.5, 'bold', INK)
    // track
    page.drawRectangle({ x: barX + 90, y: y - 1, width: trackEnd - 90, height: 7, color: HEAD_BG })
    if (cat.score != null) {
      page.drawRectangle({
        x: barX + 90,
        y: y - 1,
        width: ((trackEnd - 90) * cat.score) / 100,
        height: 7,
        color: cat.score >= 80 ? ACCENT : cat.score >= 50 ? rgb(0.75, 0.55, 0.05) : WARN,
      })
    }
    writer.text(cat.score != null ? `${cat.score.toFixed(0)}%` : 'n/a', barX + trackEnd + 6, y, 7.5, 'regular', MUTED)
    y -= 14
  }
  y -= 6

  // ─── Control results ──────────────────────────────────────────────────────
  sectionTitle(
    lang === 'es'
      ? `Resultados de controles (${input.results.length})`
      : `Control results (${input.results.length})`,
  )
  // header row
  page.drawRectangle({ x: MARGIN, y: y - 12, width: CONTENT_W, height: 15, color: HEAD_BG })
  writer.text('ID', MARGIN + 6, y - 8, 7.5, 'bold', MUTED)
  writer.text('SEV', MARGIN + 92, y - 8, 7.5, 'bold', MUTED)
  writer.text('STATUS', MARGIN + 140, y - 8, 7.5, 'bold', MUTED)
  writer.text(lang === 'es' ? 'DETALLE' : 'DETAIL', MARGIN + 228, y - 8, 7.5, 'bold', MUTED)
  y -= 20

  for (const r of input.results) {
    const detail = (r.detail ?? r.reason ?? '').slice(0, 220)
    const detailLines = wrap(detail, 7, 'regular', CONTENT_W - 236)
    const rowH = Math.max(detailLines.length * 9, 12)
    ensure(rowH + 4)
    // zebra background
    if (pageNo % 1 === 0 && input.results.indexOf(r) % 2 === 1) {
      page.drawRectangle({ x: MARGIN, y: y - rowH, width: CONTENT_W, height: rowH, color: rgb(0.975, 0.98, 0.98) })
    }
    writer.text(r.controlId, MARGIN + 6, y - 9, 7, 'bold', INK)
    writer.text(r.severity.slice(0, 8), MARGIN + 92, y - 9, 7, 'regular', STATUS_COLOR[r.severity] ?? MUTED)
    writer.text(r.status, MARGIN + 140, y - 9, 7, 'bold', STATUS_COLOR[r.status] ?? MUTED)
    detailLines.forEach((line, i) => {
      writer.text(line, MARGIN + 228, y - 9 - i * 9, 7, 'regular', rgb(0.25, 0.28, 0.31))
    })
    y -= rowH + 3
  }

  // ─── Limitations ──────────────────────────────────────────────────────────
  y -= 8
  sectionTitle(lang === 'es' ? 'Limitaciones' : 'Limitations')
  const limLines = wrap(input.limitations, 7.5, 'regular', CONTENT_W)
  ensure(limLines.length * 10 + 14)
  limLines.forEach((line, i) => {
    writer.text(line, MARGIN, y - i * 10, 7.5, 'regular', MUTED)
  })
  y -= limLines.length * 10 + 8

  // formula footer block
  ensure(30)
  const formulaLines = wrap(score.formula, 6.5, 'regular', CONTENT_W)
  page.drawRectangle({ x: MARGIN, y: y - formulaLines.length * 9 - 8, width: CONTENT_W, height: formulaLines.length * 9 + 10, color: HEAD_BG })
  formulaLines.forEach((line, i) => {
    writer.text(line, MARGIN + 6, y - 6 - i * 9, 6.5, 'regular', MUTED)
  })

  drawPageFooter()

  const pdfBytes = await pdf.save()
  return pdfBytes
}
