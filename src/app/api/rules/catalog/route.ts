import { NextResponse } from 'next/server'
import { allRules } from '@/lib/engine/rules'
import { CATEGORY_LABELS } from '@/lib/engine/types'

export const dynamic = 'force-dynamic'

// Read-only rule catalog (implemented + designed). No evaluation happens here.
export async function GET() {
  const rules = allRules()
  return NextResponse.json({
    categories: Object.entries(CATEGORY_LABELS).map(([key, value]) => ({ key, ...value })),
    rules: rules.map((r) => ({
      id: r.id,
      version: r.version,
      name: r.name,
      description: r.description,
      category: r.category,
      severity: r.severity,
      platforms: r.platforms,
      distros: r.distros ?? null,
      implemented: r.implemented,
      evidenceSource: r.evidenceSource,
      explanation: r.explanation,
      references: r.references,
      limitations: r.limitations ?? null,
    })),
  })
}
