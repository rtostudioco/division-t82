// DIVISION T82 — engine contract (v1).
// SecurityControl v1, ControlEvaluation, Evidence v1 (fragments), Remediation (§8.7),
// statuses, categories, Loc bilingual strings, scoring (public formula).
// NOTE: reconstructed verbatim from docs/ARCHITECTURE_PROPOSAL.md §3 + master prompt §6/§8.3/§8.7
// and the existing import sites (runner, platform, bag, rules, API routes, shared UI).

import type { LinuxEvidenceBag } from './collectors/linux/bag'

// ─── Primitives ──────────────────────────────────────────────────────────────

/** Bilingual string (EN primary technical, ES secondary). */
export interface Loc {
  en: string
  es: string
}

export type Platform = 'linux' | 'windows' | 'macos'

export type Confidence = 'HIGH' | 'MEDIUM' | 'LOW'

/** Honest evaluation states (never PASS without evidence). */
export type ControlStatus =
  | 'PASS'
  | 'FAIL'
  | 'WARNING'
  | 'NOT_APPLICABLE'
  | 'NOT_ASSESSED'
  | 'ERROR'

/** 11 control categories (master prompt §8.3). */
export type ControlCategory =
  | 'IDENTITY_ACCESS'
  | 'SYSTEM_CONFIG'
  | 'NETWORK_SECURITY'
  | 'FIREWALL'
  | 'ENDPOINT_PROTECTION'
  | 'ENCRYPTION'
  | 'PATCH_MANAGEMENT'
  | 'SERVICES_PROCESSES'
  | 'DATA_PROTECTION'
  | 'APPLICATION_SECURITY'
  | 'OS_SECURITY'

export const CONTROL_CATEGORIES: readonly ControlCategory[] = [
  'IDENTITY_ACCESS',
  'SYSTEM_CONFIG',
  'NETWORK_SECURITY',
  'FIREWALL',
  'ENDPOINT_PROTECTION',
  'ENCRYPTION',
  'PATCH_MANAGEMENT',
  'SERVICES_PROCESSES',
  'DATA_PROTECTION',
  'APPLICATION_SECURITY',
  'OS_SECURITY',
]

export const CATEGORY_LABELS: Record<ControlCategory, Loc> = {
  IDENTITY_ACCESS: { en: 'Identity & Access', es: 'Identidad y Acceso' },
  SYSTEM_CONFIG: { en: 'System Configuration', es: 'Configuración del Sistema' },
  NETWORK_SECURITY: { en: 'Network Security', es: 'Seguridad de Red' },
  FIREWALL: { en: 'Firewall', es: 'Firewall' },
  ENDPOINT_PROTECTION: { en: 'Endpoint Protection', es: 'Protección de Endpoint' },
  ENCRYPTION: { en: 'Encryption', es: 'Cifrado' },
  PATCH_MANAGEMENT: { en: 'Patch Management', es: 'Gestión de Parches' },
  SERVICES_PROCESSES: { en: 'Services & Processes', es: 'Servicios y Procesos' },
  DATA_PROTECTION: { en: 'Data Protection', es: 'Protección de Datos' },
  APPLICATION_SECURITY: { en: 'Application Security', es: 'Seguridad de Aplicaciones' },
  OS_SECURITY: { en: 'Operating System Security', es: 'Seguridad del Sistema Operativo' },
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

// ─── Evidence (schema v1 — fragment form used inside evaluations) ────────────

/**
 * Evidence collection method. Convention: `file-read` (allowlisted /etc files),
 * `proc-read` (/proc, /sys), `os-api` (node:os), `execFile:<binary>` (allowlisted
 * binaries from util/exec.ts, e.g. `execFile:ss`).
 */
export type EvidenceMethod =
  | 'file-read'
  | 'proc-read'
  | 'os-api'
  | 'execFile:ss'
  | 'execFile:stat'
  | 'execFile:dpkg-query'
  | 'execFile:apt-get'
  | 'execFile:systemctl'
  | 'execFile:uname'
  | 'execFile:ps'
  | 'execFile:lsblk'

export interface SecurityReference {
  label: string
  url: string
}

/**
 * Evidence fragment attached to an evaluation. Payloads must be redacted by
 * construction: user names/statuses only — NEVER password hashes, keys or secrets.
 */
export interface EvidenceFragment {
  method: EvidenceMethod
  /** Real source reference, e.g. "/etc/ssh/sshd_config" or "ss -tulnH". */
  source: string
  payload: unknown
  confidence: Confidence
  /** Elevation required to collect this evidence, e.g. "root". */
  privilegesRequired?: string
  /** True when payload was redacted (default assumption for persistence). */
  redacted?: boolean
}

// ─── Evaluation ──────────────────────────────────────────────────────────────

export interface ControlEvaluation {
  status: ControlStatus
  /** Mandatory for NOT_ASSESSED and NOT_APPLICABLE (human-readable why). */
  reason?: string
  /** Technical detail of the observation (short, safe to persist). */
  detail?: string
  /** 1-3 evidence fragments referencing real sources. */
  evidence?: EvidenceFragment[]
}

// ─── Remediation (12 fields per master prompt §8.7 — advisory only) ──────────

export interface RemediationStep {
  title: Loc
  /** Realistic command for the operator to run MANUALLY (engine never executes). */
  command?: string
  note?: Loc
}

export interface Remediation {
  /** 1. Description of the problem. */
  problemSummary: Loc
  /** 2. Probable cause. */
  rootCause: Loc
  /** 3. Risk. */
  risk: Loc
  /** 4. Priority. */
  priority: Severity
  /** 5. Current state (as observed by the engine). */
  currentStateNote: Loc
  /** 6. Recommended state. */
  recommendedState: Loc
  /** 7. Manual commands/steps. */
  steps: RemediationStep[]
  /** 8. Affected files. */
  affectedFiles?: string[]
  /** 9. Possible side effects. */
  sideEffects: Loc
  /** 10. Prerequisites. */
  prerequisites: Loc
  /** 11. Rollback procedure. */
  rollback: Loc
  /** 12. How to verify the fix. */
  verify: Loc
  /** Always true in this build: guidance is never auto-executed. */
  advisoryOnly: boolean
}

// ─── SecurityControl (rule contract, docs/ARCHITECTURE_PROPOSAL.md §3) ───────

/**
 * Union of implemented platform evidence bags (v1: Linux only).
 * Type-only import — no runtime cycle with the collectors.
 */
export type EvidenceBag = LinuxEvidenceBag

export interface SecurityControl {
  id: string // "VC-LNX-0101"
  version: string // "1.0.0"
  name: Loc
  description: Loc
  category: ControlCategory
  severity: Severity
  platforms: Platform[]
  distros?: string[] // ["debian","ubuntu"]
  implemented: boolean // designed-only catalogs => false
  evidenceSource: string // e.g. "/etc/ssh/sshd_config"
  /** PURE function of the evidence bag — no I/O inside evaluate(). */
  evaluate(bag: EvidenceBag): ControlEvaluation
  explanation: Loc // why it matters
  references: SecurityReference[]
  remediation: Remediation
  limitations?: Loc
}

// ─── Scoring (public, explainable — docs/ARCHITECTURE_PROPOSAL.md §3) ────────

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 8,
  MEDIUM: 5,
  LOW: 3,
  INFO: 1,
}

export const STATUS_CREDIT: Record<ControlStatus, number> = {
  PASS: 1.0,
  WARNING: 0.5,
  FAIL: 0.0,
  NOT_APPLICABLE: 0.0,
  NOT_ASSESSED: 0.0,
  ERROR: 0.0,
}

export const ENGINE_VERSION = '1.1.0'

export const SCORING_FORMULA =
  'category = sum(credit*weight)/sum(weight)*100 over scored controls (PASS/WARNING/FAIL) ' +
  '| global = mean of category scores that have >=1 scored control ' +
  '| weights CRITICAL=10 HIGH=8 MEDIUM=5 LOW=3 INFO=1 ' +
  '| credits PASS=1.0 WARNING=0.5 FAIL=0.0 ' +
  '| coverage = scored/applicable (NOT_APPLICABLE excluded)'

export interface ScoreInput {
  controlId: string
  severity: Severity
  status: ControlStatus
  category: string
}

export interface CategoryScore {
  category: string
  score: number | null
  scored: number
  total: number
  /** Controls that did not receive credit (listed explicitly, never hidden). */
  notScored: string[]
}

export interface ScoreResult {
  overall: number | null
  coverage: number
  counts: Record<ControlStatus, number>
  severityCounts: Record<Severity, number>
  categories: CategoryScore[]
  formula: string
}

function isScored(status: ControlStatus): boolean {
  return status === 'PASS' || status === 'WARNING' || status === 'FAIL'
}

function round1(n: number): number {
  return Math.round(n * 10) / 10
}

export function computeScore(inputs: ScoreInput[]): ScoreResult {
  const counts: Record<ControlStatus, number> = {
    PASS: 0,
    FAIL: 0,
    WARNING: 0,
    NOT_APPLICABLE: 0,
    NOT_ASSESSED: 0,
    ERROR: 0,
  }
  const severityCounts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  }
  for (const i of inputs) {
    counts[i.status] += 1
    severityCounts[i.severity] += 1
  }

  const byCategory = new Map<string, ScoreInput[]>()
  for (const i of inputs) {
    const arr = byCategory.get(i.category) ?? []
    arr.push(i)
    byCategory.set(i.category, arr)
  }

  const categories: CategoryScore[] = [...byCategory.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([category, items]) => {
      const scoredItems = items.filter((i) => isScored(i.status))
      const notScored = items.filter((i) => !isScored(i.status)).map((i) => i.controlId)
      const totalWeight = scoredItems.reduce((s, i) => s + SEVERITY_WEIGHT[i.severity], 0)
      const weightedCredit = scoredItems.reduce(
        (s, i) => s + STATUS_CREDIT[i.status] * SEVERITY_WEIGHT[i.severity],
        0,
      )
      const score =
        scoredItems.length > 0 && totalWeight > 0 ? round1((weightedCredit / totalWeight) * 100) : null
      return { category, score, scored: scoredItems.length, total: items.length, notScored }
    })

  const withScore = categories.filter((c) => c.score !== null)
  const overall =
    withScore.length > 0
      ? round1(withScore.reduce((s, c) => s + (c.score as number), 0) / withScore.length)
      : null

  const applicable = inputs.filter((i) => i.status !== 'NOT_APPLICABLE').length
  const scoredCount = inputs.filter((i) => isScored(i.status)).length
  const coverage = applicable > 0 ? round1((scoredCount / applicable) * 100) : 0

  return { overall, coverage, counts, severityCounts, categories, formula: SCORING_FORMULA }
}

// ─── Knowledge Center types (used by knowledge.ts + articles data) ───────────

export type ArticleLevel = 'BEGINNER' | 'INTERMEDIATE' | 'ADVANCED'

export interface KnowledgeArticleData {
  slug: string
  title: Loc
  summary: Loc
  level: ArticleLevel
  category: ControlCategory
  platforms: Platform[]
  relatedControls: string[]
  mitre: { id: string; name: string }[]
  technicalDescription: Loc
  rootCause: Loc
  howItHappens: Loc
  threatContext: Loc
  cve?: string[]
  cwe?: string[]
  indicators: Loc
  detection: Loc
  prevention: Loc
  mitigation: Loc
  verification: Loc
  secureConfigExample?: { label: string; language: string; code: string }
  defensiveCodeExample?: { label: string; language: string; code: string }
  labScenario?: { title: Loc; steps: string[]; safetyNote: Loc }
  references: SecurityReference[]
  reviewedAt: string
}
