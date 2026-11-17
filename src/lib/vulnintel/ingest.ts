// DIVISION T82 — vulnerability ingestion core (server-only).
// Sources:
//   OSV (api.osv.dev) — exact-version matching against the scan package inventory.
//     A match is recorded ONLY when OSV's matcher confirms the installed version
//     falls inside the advisory's affected ranges (never name-only guessing).
//   NVD recent (services.nvd.nist.gov) — recently-modified CVE catalog.
//   NVD KEV sweep — the full CISA Known Exploited Vulnerabilities set via NVD's
//     `hasKev` filter (paginated). Runs independent of the recent-CVE window so
//     KEV flags survive NVD throttling of the large 3-day queries.
// Honesty rules: every source failure is reported, never fabricated; OSV advisories
// without a fixed version in the suite (Debian may mark them postponed/ignored) are
// included as CONFIRMED per OSV data and the UI discloses this nuance.
import { db } from '@/lib/db'
import { Agent, fetch as undiciFetch } from 'undici'

// ─── Public types ────────────────────────────────────────────────────────────

export interface IngestSourceResult {
  ok: boolean
  skipped?: string // honest reason when the step did not run
  packagesQueried?: number
  matchedPackages?: number
  matches?: number
  recordsUpserted?: number
  kevMarked?: number
  error?: string
}

export interface IngestResult {
  at: string
  osv: IngestSourceResult
  nvd: IngestSourceResult
  cisa: IngestSourceResult
}

// ─── CVSS v3.0/v3.1 base score from vector ───────────────────────────────────

const SEV_WEIGHTS_AV: Record<string, number> = { N: 0.85, A: 0.77, L: 0.62, P: 0.55 }
const SEV_WEIGHTS_AC: Record<string, number> = { L: 0.77, H: 0.44 }
const SEV_WEIGHTS_UI: Record<string, number> = { N: 0.85, R: 0.62 }
const SEV_WEIGHTS_CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 }

export function severityFromScore(score: number): string {
  if (score >= 9) return 'CRITICAL'
  if (score >= 7) return 'HIGH'
  if (score >= 4) return 'MEDIUM'
  if (score > 0) return 'LOW'
  return 'UNKNOWN'
}

export function cvss31Base(vector: string): { score: number; severity: string } | null {
  const m = vector.match(/^CVSS:3\.[01]\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[HLN]\/I:[HLN]\/A:[HLN]$/)
  if (!m) return null
  const p: Record<string, string> = {}
  for (const kv of vector.split('/').slice(1)) {
    const idx = kv.indexOf(':')
    if (idx > 0) p[kv.slice(0, idx)] = kv.slice(idx + 1)
  }
  const AV = SEV_WEIGHTS_AV[p.AV]
  const AC = SEV_WEIGHTS_AC[p.AC]
  const UI = SEV_WEIGHTS_UI[p.UI]
  const scope = p.S === 'C'
  const PR = scope
    ? ({ N: 0.85, L: 0.68, H: 0.5 } as Record<string, number>)[p.PR]
    : ({ N: 0.85, L: 0.62, H: 0.27 } as Record<string, number>)[p.PR]
  const C = SEV_WEIGHTS_CIA[p.C]
  const I = SEV_WEIGHTS_CIA[p.I]
  const A = SEV_WEIGHTS_CIA[p.A]
  if ([AV, AC, PR, UI, C, I, A].some((x) => x === undefined)) return null
  const isc = 1 - (1 - C) * (1 - I) * (1 - A)
  const impact = scope
    ? 7.52 * (isc - 0.029) - 3.25 * Math.pow(isc - 0.02, 15)
    : 6.42 * isc
  if (impact <= 0) return { score: 0, severity: 'UNKNOWN' }
  const exploitability = 8.22 * AV * AC * PR * UI
  const score = Math.min(10, Math.ceil((impact + exploitability) * 10) / 10)
  return { score, severity: severityFromScore(score) }
}

// ─── HTTP helpers ────────────────────────────────────────────────────────────

// NVD's edge filters UAs: long/descriptive or browser-like UAs get 503/522 or
// soft-throttled empty pages. A simple product token completes reliably.
const UA = 'VulnCheckUniversal/1.1'

// Dedicated dispatcher: fresh TCP/TLS session per request (keep-alive off).
// Next.js patches global fetch and its connection pooling behaved badly against
// NVD's edge (persistent 200-empty/503 for pooled sessions while identical
// fresh-session requests succeeded) — undici's own fetch bypasses that patch.
const externalAgent = new Agent({
  keepAliveTimeout: 1,
  keepAliveMaxTimeout: 1,
  connections: 8,
})

async function fetchJson(url: string, init?: RequestInit, timeoutMs = 25000): Promise<unknown> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), timeoutMs)
  try {
    const res = await undiciFetch(url, {
      method: init?.method ?? 'GET',
      body: init?.body as never,
      headers: { 'User-Agent': UA, ...(init?.headers as Record<string, string> | undefined) },
      signal: ctrl.signal as never,
      dispatcher: externalAgent,
    })
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`)
    return await res.json()
  } finally {
    clearTimeout(timer)
  }
}

// ─── OSV (Google Open Source Vulnerabilities) ────────────────────────────────

interface OsvMinimal {
  id: string
  modified?: string
}

interface OsvVuln {
  id: string
  summary?: string
  details?: string
  aliases?: string[]
  withdrawn?: string
  severity?: { type: string; score: string }[]
  references?: { type: string; url: string }[]
  database_specific?: { severity?: string; cwe_ids?: string[] }
  modified?: string
  published?: string
}

const OSV_BASE = 'https://api.osv.dev'
const MAX_PACKAGES = 1200
const MAX_MATCHED_PACKAGES_FULL = 100
const MAX_VULNS_PER_PACKAGE = 40

function ecosystemFor(inventory: { os: { id: string; versionId: string } | null }): { ecosystem: string | null; reason?: string } {
  const os = inventory.os
  if (!os) return { ecosystem: null, reason: 'inventory has no os-release data' }
  const id = os.id.toLowerCase()
  const v = os.versionId
  if (id === 'debian' && /^\d+$/.test(v)) return { ecosystem: `Debian:${v}` }
  if (id === 'ubuntu' && /^\d+\.\d+$/.test(v)) return { ecosystem: `Ubuntu:${v}:LTS` }
  return { ecosystem: null, reason: `no OSV ecosystem mapping for distro "${id} ${v}"` }
}

function cveIdOf(v: OsvVuln): string | null {
  const fromAlias = (v.aliases ?? []).find((a) => /^CVE-\d{4}-\d{4,}$/.test(a))
  if (fromAlias) return fromAlias
  const fromId = v.id.match(/CVE-\d{4}-\d{4,}/)
  return fromId ? fromId[0] : null
}

async function osvMatchPackages(
  packages: { name: string; version: string }[],
  ecosystem: string,
): Promise<{ perPackage: Map<string, string[]>; errors: string[] }> {
  const perPackage = new Map<string, string[]>()
  const errors: string[] = []
  const CHUNK = 400
  for (let i = 0; i < packages.length; i += CHUNK) {
    const chunk = packages.slice(i, i + CHUNK)
    try {
      const body = {
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem },
          version: p.version,
        })),
      }
      const data = (await fetchJson(`${OSV_BASE}/v1/querybatch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })) as { results: { vulns?: OsvMinimal[] }[] }
      chunk.forEach((p, idx) => {
        const r = data.results?.[idx]
        const ids = (r?.vulns ?? []).map((v) => v.id).filter(Boolean)
        if (ids.length > 0) perPackage.set(p.name, ids)
      })
    } catch (e) {
      errors.push(`querybatch chunk ${Math.floor(i / CHUNK) + 1}: ${String((e as Error).message).slice(0, 160)}`)
    }
  }
  return { perPackage, errors }
}

async function osvFullForPackage(
  name: string,
  version: string,
  ecosystem: string,
): Promise<OsvVuln[]> {
  const data = (await fetchJson(`${OSV_BASE}/v1/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package: { name, ecosystem }, version }),
  })) as { vulns?: OsvVuln[] }
  return (data.vulns ?? []).filter((v) => !v.withdrawn).slice(0, MAX_VULNS_PER_PACKAGE)
}

// ─── NVD ─────────────────────────────────────────────────────────────────────

interface NvdCveItem {
  cve: {
    id: string
    descriptions: { lang: string; value: string }[]
    published?: string
    lastModified?: string
    metrics?: {
      cvssMetricV31?: { cvssData: { baseScore: number; vectorString: string; baseSeverity?: string } }[]
      cvssMetricV30?: { cvssData: { baseScore: number; vectorString: string; baseSeverity?: string } }[]
      cvssMetricV2?: { cvssData: { baseScore: number; baseSeverity?: string } }[]
    }
    weaknesses?: { description: { lang: string; value: string }[] }[]
    references?: { url: string }[]
    cisaExploitAdd?: string
    cisaVulnerabilityName?: string
  }
}

async function nvdFetchRecent(days: number): Promise<NvdCveItem[]> {
  const end = new Date()
  const start = new Date(end.getTime() - days * 24 * 3600 * 1000)
  const iso = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, '.000')
  const url =
    `https://services.nvd.nist.gov/rest/json/cves/2.0` +
    `?lastModStartDate=${iso(start)}&lastModEndDate=${iso(end)}&resultsPerPage=2000`
  // NVD free tier throttles aggressively: 503s AND "200-with-empty-page" soft
  // throttling. Both are retried with growing backoff before giving up.
  let lastError = ''
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      await nvdPace()
      // NVD CVE API 2.0 returns results under `vulnerabilities` (NOT `vulns`).
      const data = (await fetchJson(url, {}, 45000)) as { totalResults?: number; vulnerabilities?: NvdCveItem[] }
      const vulns = data.vulnerabilities ?? []
      if ((data.totalResults ?? 0) > 0 && vulns.length === 0) {
        throw new Error('NVD soft-throttle: HTTP 200 with empty result page')
      }
      return vulns
    } catch (e) {
      lastError = String((e as Error).message)
      if (attempt < 2) await new Promise((r) => setTimeout(r, 6000 * (attempt + 1)))
    }
  }
  throw new Error(lastError)
}

// Full CISA KEV catalog via NVD's `hasKev` filter. The catalog fits in ONE page
// (≈1.8k records ≤ the 2000 per-page cap), so the sweep normally costs a single
// request — kind to the 5-req/30s free-tier quota. Empty/503 pages are retried.
const MAX_KEV_PAGES = 2
const NVD_PAGE = 2000

// NVD free tier: 5 requests per rolling 30 s (no API key). Pace requests so the
// whole run (KEV sweep + recent window, incl. retries) stays inside the quota.
const NVD_MIN_GAP_MS = 7500
let lastNvdRequestAt = 0

async function nvdPace(): Promise<void> {
  const now = Date.now()
  const wait = lastNvdRequestAt + NVD_MIN_GAP_MS - now
  if (wait > 0) await new Promise((r) => setTimeout(r, wait))
  lastNvdRequestAt = Date.now()
}

async function nvdFetchKevAll(): Promise<NvdCveItem[]> {
  const items: NvdCveItem[] = []
  let startIndex = 0
  for (let page = 0; page < MAX_KEV_PAGES; page++) {
    const url =
      `https://services.nvd.nist.gov/rest/json/cves/2.0` +
      `?hasKev&resultsPerPage=${NVD_PAGE}&startIndex=${startIndex}`
    let data: { totalResults?: number; vulnerabilities?: NvdCveItem[] } | null = null
    let lastError = ''
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await nvdPace()
        // NVD CVE API 2.0 returns results under `vulnerabilities` (NOT `vulns`).
        const d = (await fetchJson(url, {}, 45000)) as { totalResults?: number; vulnerabilities?: NvdCveItem[] }
        const vulns = d.vulnerabilities ?? []
        // "200 with empty page while totalResults > 0" is NVD soft-throttling — retry.
        if ((d.totalResults ?? 0) > 0 && vulns.length === 0) {
          throw new Error('NVD soft-throttle: HTTP 200 with empty result page')
        }
        data = d
        break
      } catch (e) {
        lastError = String((e as Error).message)
        if (attempt < 2) await new Promise((r) => setTimeout(r, 6000 * (attempt + 1)))
      }
    }
    if (!data) throw new Error(lastError || 'KEV page fetch failed')
    const vulns = data.vulnerabilities ?? []
    items.push(...vulns)
    const total = data.totalResults ?? items.length
    startIndex += vulns.length
    if (vulns.length === 0 || startIndex >= total) break
  }
  return items
}

// ─── Persistence helpers ─────────────────────────────────────────────────────

interface RecordUpsert {
  cveId: string
  title: string
  cvssScore: number | null
  cvssVector: string | null
  cwes: string[]
  kev: boolean
  source: string
  description: string | null
  references: string[]
  publishedAt: Date | null
  modifiedAt: Date | null
}

async function upsertRecord(r: RecordUpsert): Promise<void> {
  await db.vulnerabilityRecord.upsert({
    where: { cveId: r.cveId },
    create: {
      cveId: r.cveId,
      title: r.title.slice(0, 300),
      cvssScore: r.cvssScore,
      cvssVector: r.cvssVector,
      cwesJson: r.cwes.length > 0 ? JSON.stringify(r.cwes) : null,
      kev: r.kev,
      source: r.source,
      confidence: 'UNVERIFIED',
      description: r.description?.slice(0, 4000) ?? null,
      referencesJson: r.references.length > 0 ? JSON.stringify(r.references.slice(0, 12)) : null,
      publishedAt: r.publishedAt,
      modifiedAt: r.modifiedAt,
      fetchedAt: new Date(),
    },
    update: {
      title: r.title.slice(0, 300),
      cvssScore: r.cvssScore ?? undefined,
      cvssVector: r.cvssVector ?? undefined,
      cwesJson: r.cwes.length > 0 ? JSON.stringify(r.cwes) : undefined,
      kev: r.kev || undefined,
      source: r.source,
      description: r.description?.slice(0, 4000) ?? undefined,
      referencesJson: r.references.length > 0 ? JSON.stringify(r.references.slice(0, 12)) : undefined,
      publishedAt: r.publishedAt ?? undefined,
      modifiedAt: r.modifiedAt ?? undefined,
      fetchedAt: new Date(),
    },
  })
}

// ─── Main ingestion ──────────────────────────────────────────────────────────

export async function ingestVulnerabilities(): Promise<IngestResult> {
  const at = new Date().toISOString()

  // Source result declarations hoisted so the phase wrappers below share them.
  const osvResult: IngestSourceResult = { ok: false }
  let osvUpserts = 0
  let osvMatchRows = 0
  const cisaResult: IngestSourceResult = { ok: false }
  let cisaKev = 0
  const nvdResult: IngestSourceResult = { ok: false }
  let nvdUpserts = 0
  let nvdKev = 0

  // Phase execution order (value-first): CISA KEV sweep + NVD recent run FIRST,
  // while the handler's outbound connections are fresh — the OSV phase fires
  // ~300 rapid requests to api.osv.dev and the egress/edge degrades briefly
  // after that burst (NVD answers 503 / 200-empty right afterwards). OSV last:
  // it succeeded in 100% of observed runs regardless of position.
  const runOsv = async (): Promise<void> => {
  // ── OSV: exact-version matching against the latest completed scan inventory
  try {
    const latestScan = await db.scanJob.findFirst({
      where: { status: 'completed' },
      orderBy: { startedAt: 'desc' },
    })
    if (!latestScan?.inventoryJson) {
      osvResult.ok = true
      osvResult.skipped = 'no completed scan with inventory yet — run a scan first'
    } else {
      const inventory = JSON.parse(latestScan.inventoryJson) as {
        os: { id: string; versionId: string } | null
        packages: { count: number | null; list: { name: string; version: string }[] | null }
      }
      const list = inventory.packages?.list ?? []
      const { ecosystem, reason } = ecosystemFor(inventory)
      if (!ecosystem) {
        osvResult.ok = true
        osvResult.skipped = reason
      } else if (list.length === 0) {
        osvResult.ok = true
        osvResult.skipped = 'inventory has no package list'
      } else {
        const packages = list
          .filter((p) => p.name && p.version)
          .slice(0, MAX_PACKAGES)
        const { perPackage, errors } = await osvMatchPackages(packages, ecosystem)
        if (errors.length > 0 && perPackage.size === 0) {
          throw new Error(errors[0])
        }

        // full details per matched package (bounded, batches of 5)
        const enrichedCves = new Set<string>()
        const matchedNames = [...perPackage.keys()].slice(0, MAX_MATCHED_PACKAGES_FULL)
        const byName = new Map(packages.map((p) => [p.name, p]))
        for (let i = 0; i < matchedNames.length; i += 5) {
          const slice = matchedNames.slice(i, i + 5)
          const fulls = await Promise.all(
            slice.map(async (name) => {
              const p = byName.get(name)
              if (!p) return { name, version: '', vulns: [] as OsvVuln[] }
              try {
                return { name, version: p.version, vulns: await osvFullForPackage(name, p.version, ecosystem) }
              } catch {
                return { name, version: p.version, vulns: [] as OsvVuln[] }
              }
            }),
          )
          for (const { name, version, vulns } of fulls) {
            for (const v of vulns) {
              const cveId = cveIdOf(v)
              if (!cveId) continue
              let vector = v.severity?.find((s) => s.type === 'CVSS_V3')?.score ?? null
              let dbSev = v.database_specific?.severity
              let cwes = v.database_specific?.cwe_ids ?? []
              let title = v.summary ?? v.details?.slice(0, 200) ?? cveId
              let description = v.details ?? v.summary ?? null
              let refs = (v.references ?? []).map((r) => r.url).filter((u) => /^https?:\/\//.test(u))
              // Debian tracker advisories (DEBIAN-CVE-*) carry no CVSS — enrich from
              // OSV's NVD-sourced CVE record (single GET, deduped per run).
              if (vector == null && !enrichedCves.has(cveId)) {
                enrichedCves.add(cveId)
                try {
                  const nvdRecord = (await fetchJson(`${OSV_BASE}/v1/vulns/${encodeURIComponent(cveId)}`, undefined, 12000)) as OsvVuln
                  if (!nvdRecord.withdrawn) {
                    vector = nvdRecord.severity?.find((s) => s.type === 'CVSS_V3')?.score ?? vector
                    dbSev = dbSev ?? nvdRecord.database_specific?.severity
                    cwes = cwes.length > 0 ? cwes : nvdRecord.database_specific?.cwe_ids ?? []
                    if (!description) description = nvdRecord.details ?? nvdRecord.summary ?? null
                    if (title === cveId && nvdRecord.summary) title = nvdRecord.summary
                    if (refs.length === 0) {
                      refs = (nvdRecord.references ?? []).map((r) => r.url).filter((u) => /^https?:\/\//.test(u))
                    }
                  }
                } catch {
                  // no NVD-sourced record for this id in OSV — keep Debian data as-is
                }
              }
              const computed = vector ? cvss31Base(vector) : null
              const score = computed?.score ?? null
              const severity = computed?.severity ?? (dbSev ? dbSev.toUpperCase() : 'UNKNOWN')
              await upsertRecord({
                cveId,
                title,
                cvssScore: score,
                cvssVector: vector,
                cwes,
                kev: false, // KEV flag comes from NVD ingestion (authoritative)
                source: 'osv',
                description,
                references: refs,
                publishedAt: v.published ? new Date(v.published) : null,
                modifiedAt: v.modified ? new Date(v.modified) : null,
              })
              osvUpserts += 1
              await db.vulnerabilityMatch.upsert({
                where: {
                  cveId_scanId_packageName: {
                    cveId,
                    scanId: latestScan.id,
                    packageName: name,
                  },
                },
                create: {
                  cveId,
                  scanId: latestScan.id,
                  packageName: name,
                  packageVersion: version,
                  ecosystem,
                  confidence: 'CONFIRMED',
                  severity,
                },
                update: {
                  packageVersion: version,
                  severity,
                },
              })
              osvMatchRows += 1
            }
          }
        }
        osvResult.ok = true
        osvResult.packagesQueried = packages.length
        osvResult.matchedPackages = matchedNames.length
        osvResult.matches = osvMatchRows
        osvResult.recordsUpserted = osvUpserts
        if (errors.length > 0) {
          osvResult.error = `partial: ${errors[0]}`
        }
      }
    }
  } catch (e) {
    osvResult.ok = false
    osvResult.error = String((e as Error).message).slice(0, 300)
  }
  } // end runOsv

  const runKev = async (): Promise<void> => {
  // ── CISA KEV: full Known-Exploited sweep via NVD `hasKev` (independent of the
  // recent-CVE window, so KEV flags survive throttling of the big window query).
  // Runs FIRST: highest-value source; if NVD throttles later, KEV data is in.
  // Existing records keep their provenance source — only the kev flag + KEV
  // metadata are updated; brand-new records are created with source 'nvd-kev'.
  try {
    const items = await nvdFetchKevAll()
    for (const item of items) {
      const c = item.cve
      const desc = c.descriptions?.find((d) => d.lang === 'en')?.value ?? null
      const v31 = c.metrics?.cvssMetricV31?.[0]?.cvssData
      const v30 = c.metrics?.cvssMetricV30?.[0]?.cvssData
      const v2 = c.metrics?.cvssMetricV2?.[0]?.cvssData
      const score = v31?.baseScore ?? v30?.baseScore ?? v2?.baseScore ?? null
      const vector = v31?.vectorString ?? v30?.vectorString ?? null
      const cwes = [...new Set((c.weaknesses ?? []).flatMap((w) => w.description.map((d) => d.value)).filter((x) => /^CWE-\d+/.test(x)))]
      await db.vulnerabilityRecord.upsert({
        where: { cveId: c.id },
        create: {
          cveId: c.id,
          title: (c.cisaVulnerabilityName ?? desc?.slice(0, 200) ?? c.id).slice(0, 300),
          cvssScore: score,
          cvssVector: vector,
          cwesJson: cwes.length > 0 ? JSON.stringify(cwes) : null,
          kev: true,
          source: 'nvd-kev',
          confidence: 'UNVERIFIED',
          description: desc?.slice(0, 4000) ?? null,
          referencesJson: (c.references ?? []).length > 0 ? JSON.stringify((c.references ?? []).map((r) => r.url).filter((u) => /^https?:\/\//.test(u)).slice(0, 12)) : null,
          publishedAt: c.published ? new Date(c.published) : null,
          modifiedAt: c.lastModified ? new Date(c.lastModified) : null,
          fetchedAt: new Date(),
        },
        // Provenance preserved: OSV/NVD-recent records keep their `source`.
        update: {
          title: (c.cisaVulnerabilityName ?? c.id).slice(0, 300),
          kev: true,
          modifiedAt: c.lastModified ? new Date(c.lastModified) : undefined,
          fetchedAt: new Date(),
        },
      })
      cisaKev += 1
    }
    cisaResult.ok = true
    cisaResult.recordsUpserted = cisaKev
    cisaResult.kevMarked = cisaKev
  } catch (e) {
    cisaResult.ok = false
    cisaResult.error = String((e as Error).message).slice(0, 300)
  }
  } // end runKev

  const runNvd = async (): Promise<void> => {
  // ── NVD recent: recently-modified CVE catalog (3-day window)
  try {
    const items = await nvdFetchRecent(3)
    for (const item of items) {
      const c = item.cve
      const desc = c.descriptions?.find((d) => d.lang === 'en')?.value ?? null
      const v31 = c.metrics?.cvssMetricV31?.[0]?.cvssData
      const v30 = c.metrics?.cvssMetricV30?.[0]?.cvssData
      const v2 = c.metrics?.cvssMetricV2?.[0]?.cvssData
      const score = v31?.baseScore ?? v30?.baseScore ?? v2?.baseScore ?? null
      const vector = v31?.vectorString ?? v30?.vectorString ?? null
      const cwes = [...new Set((c.weaknesses ?? []).flatMap((w) => w.description.map((d) => d.value)).filter((x) => /^CWE-\d+/.test(x)))]
      const isKev = typeof c.cisaExploitAdd === 'string' && c.cisaExploitAdd.length > 0
      await upsertRecord({
        cveId: c.id,
        title: c.cisaVulnerabilityName ?? (desc ? desc.slice(0, 200) : c.id),
        cvssScore: score,
        cvssVector: vector,
        cwes,
        kev: isKev,
        source: 'nvd',
        description: desc,
        references: (c.references ?? []).map((r) => r.url).filter((u) => /^https?:\/\//.test(u)),
        publishedAt: c.published ? new Date(c.published) : null,
        modifiedAt: c.lastModified ? new Date(c.lastModified) : null,
      })
      nvdUpserts += 1
      if (isKev) nvdKev += 1
    }
    nvdResult.ok = true
    nvdResult.recordsUpserted = nvdUpserts
    nvdResult.kevMarked = nvdKev
  } catch (e) {
    nvdResult.ok = false
    nvdResult.error = String((e as Error).message).slice(0, 300)
  }
  } // end runNvd

  await runKev()
  await runNvd()
  await runOsv()

  const result: IngestResult = { at, osv: osvResult, nvd: nvdResult, cisa: cisaResult }
  await db.applicationSetting.upsert({
    where: { key: 'vulnintel.lastIngest' },
    create: { key: 'vulnintel.lastIngest', value: JSON.stringify(result) },
    update: { value: JSON.stringify(result) },
  })
  await db.auditHistory.create({
    data: {
      action: 'vuln.ingest',
      detail: `osv: ${osvResult.skipped ?? `matches=${osvResult.matches ?? 0} records=${osvResult.recordsUpserted ?? 0}`} | nvd: ${nvdResult.recordsUpserted ?? 0} kev=${nvdResult.kevMarked ?? 0} | cisa-kev: ${cisaResult.ok ? cisaKev : cisaResult.error ?? 'failed'}`,
    },
  })
  return result
}
