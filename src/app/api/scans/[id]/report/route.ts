import { NextResponse } from 'next/server'
import { db } from '@/lib/db'
import { computeScore } from '@/lib/engine/types'
import type { ControlStatus, Severity } from '@/lib/engine/types'
import { buildPdfReport } from '@/lib/report/pdf'

export const dynamic = 'force-dynamic'

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params
  if (!/^[\w-]{1,64}$/.test(id)) {
    return NextResponse.json({ error: 'invalid scan id' }, { status: 400 })
  }
  const format = new URL(request.url).searchParams.get('format') ?? 'json'
  const scan = await db.scanJob.findUnique({
    where: { id },
    include: { host: true, results: { orderBy: [{ category: 'asc' }, { controlId: 'asc' }] } },
  })
  if (!scan) return NextResponse.json({ error: 'scan not found' }, { status: 404 })

  const scoreInputs = scan.results.map((r) => ({
    controlId: r.controlId,
    severity: r.severity as Severity,
    status: r.status as ControlStatus,
    category: r.category,
  }))
  const score = computeScore(scoreInputs)
  const stamp = scan.finishedAt?.toISOString() ?? scan.startedAt.toISOString()

  if (format === 'pdf') {
    const nameOf = (json: string): string => {
      try {
        const loc = JSON.parse(json) as { en: string; es: string }
        return loc.es ?? loc.en
      } catch {
        return json
      }
    }
    const bytes = await buildPdfReport({
      scanId: scan.id,
      engineVersion: scan.engineVersion,
      startedAt: scan.startedAt,
      finishedAt: scan.finishedAt,
      host: {
        hostname: scan.host.hostname,
        os: scan.host.os,
        osVersion: scan.host.osVersion,
        kernel: scan.host.kernel,
        arch: scan.host.arch,
        user: scan.host.user,
        isRoot: scan.host.isRoot,
      },
      results: scan.results.map((r) => ({
        controlId: r.controlId,
        controlVersion: r.controlVersion,
        controlName: nameOf(r.controlName),
        category: r.category,
        severity: r.severity,
        status: r.status,
        reason: r.reason,
        detail: r.detail,
      })),
      scope: JSON.parse(scan.scopeJson),
      limitations:
        'Auditoría de solo lectura. Los controles que requieren privilegios elevados se reportan NOT_ASSESSED. Los entornos contenedorizados comparten el kernel con el host. La puntuación es expllicable y su fórmula se incluye al final del informe.',
      lang: 'es',
    })
    await db.auditHistory.create({
      data: { action: 'report.export', target: scan.id, detail: 'pdf' },
    })
    return new NextResponse(Buffer.from(bytes), {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename="t82-posture-${stamp.slice(0, 10)}.pdf"`,
      },
    })
  }

  if (format === 'csv') {
    const header = 'control_id,version,category,severity,status,reason,detail'
    const rows = scan.results.map((r) =>
      [
        r.controlId, r.controlVersion, r.category, r.severity, r.status,
        r.reason ?? '', (r.detail ?? '').replace(/[\r\n"]+/g, ' ').slice(0, 400),
      ]
        .map((v) => `"${String(v).replace(/"/g, '""')}"`)
        .join(','),
    )
    const csv = [header, ...rows].join('\n')
    await db.auditHistory.create({
      data: { action: 'report.export', target: scan.id, detail: `csv controls=${scan.results.length}` },
    })
    return new NextResponse(csv, {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="t82-posture-${stamp.slice(0, 10)}.csv"`,
      },
    })
  }

  // JSON report: executive summary + results + evidence counts + limitations
  const evidenceCount = await db.evidence.count({ where: { scanId: scan.id } })
  await db.auditHistory.create({
    data: { action: 'report.export', target: scan.id, detail: 'json' },
  })
  return new NextResponse(
    JSON.stringify(
      {
        report: 'DIVISION T82 — Security Posture Report',
        reportVersion: '1.0.0',
        engine: scan.engineVersion,
        generatedAtUTC: new Date().toISOString(),
        scope: JSON.parse(scan.scopeJson),
        host: {
          hostname: scan.host.hostname, os: scan.host.os, osVersion: scan.host.osVersion,
          kernel: scan.host.kernel, arch: scan.host.arch, assessedAsUser: scan.host.user,
          rootPrivileges: scan.host.isRoot,
        },
        executiveSummary: {
          score: score.overall,
          coverage: score.coverage,
          scoringFormula: score.formula,
          counts: score.counts,
          severityCounts: score.severityCounts,
          coverageNote:
            'Coverage reflects assessed/applicable controls. NOT_ASSESSED and NOT_APPLICABLE controls are listed explicitly and never silently omitted.',
        },
        categories: score.categories,
        results: scan.results.map((r) => ({
          controlId: r.controlId,
          version: r.controlVersion,
          category: r.category,
          severity: r.severity,
          status: r.status,
          reason: r.reason ?? null,
          detail: r.detail ?? null,
          evidenceId: r.evidenceId,
        })),
        evidenceRecords: evidenceCount,
        limitations:
          'Read-only audit. Controls requiring elevated privileges are reported NOT_ASSESSED. Containerized environments share the kernel with the host.',
      },
      null,
      2,
    ),
    {
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="t82-posture-${stamp.slice(0, 10)}.json"`,
      },
    },
  )
}
