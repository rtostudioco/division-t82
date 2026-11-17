// DIVISION T82 — Linux rule shared helpers (single source for core + extended catalogs).
// Keeps evidence/fragment/remediation construction consistent across all rules.
import type {
  EvidenceFragment,
  EvidenceMethod,
  Confidence,
  Severity,
  Loc,
  Remediation,
  RemediationStep,
  SecurityReference,
} from '../../types'

// ─── Shared constants ────────────────────────────────────────────────────────

export const NO_SSHD = 'OpenSSH server not installed (no /etc/ssh/sshd_config)'
export const SHADOW_NO_ROOT = 'permission denied — /etc/shadow requires root (privilegesRequired: root)'
export const SUDOERS_NO_ROOT = 'permission denied — /etc/sudoers requires root'

export const MANUAL: Loc = {
  en: 'MANUAL step — the engine NEVER executes commands. Review, adapt and run it yourself with appropriate privileges.',
  es: 'Paso MANUAL — el motor NUNCA ejecuta comandos. Revísalo, adáptalo y ejecútalo tú con los privilegios adecuados.',
}

export const REF_DEBIAN: SecurityReference = {
  label: 'Securing Debian Manual',
  url: 'https://www.debian.org/doc/manuals/securing-debian-manual/',
}
export const REF_UBUNTU: SecurityReference = {
  label: 'Ubuntu Server Security',
  url: 'https://ubuntu.com/server/docs/how-to/security/',
}
export const REF_OPENSSH: SecurityReference = {
  label: 'OpenSSH Manual',
  url: 'https://www.openssh.com/manual.html',
}
export const REF_CIS: SecurityReference = {
  label: 'CIS Benchmarks',
  url: 'https://www.cisecurity.org/cis-benchmarks',
}
export const REF_NIST: SecurityReference = {
  label: 'NIST Cybersecurity',
  url: 'https://www.nist.gov/cybersecurity',
}
export const REF_MITRE: SecurityReference = {
  label: 'MITRE ATT&CK',
  url: 'https://attack.mitre.org/',
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

export function frag(
  method: EvidenceMethod,
  source: string,
  payload: unknown,
  confidence: Confidence,
  privilegesRequired?: string,
): EvidenceFragment {
  return privilegesRequired
    ? { method, source, payload, confidence, privilegesRequired, redacted: true }
    : { method, source, payload, confidence, redacted: true }
}

export function rem(
  priority: Severity,
  problemSummary: Loc,
  rootCause: Loc,
  risk: Loc,
  currentStateNote: Loc,
  recommendedState: Loc,
  steps: RemediationStep[],
  affectedFiles: string[],
  sideEffects: Loc,
  prerequisites: Loc,
  rollback: Loc,
  verify: Loc,
): Remediation {
  return {
    problemSummary,
    rootCause,
    risk,
    priority,
    currentStateNote,
    recommendedState,
    steps,
    affectedFiles,
    sideEffects,
    prerequisites,
    rollback,
    verify,
    advisoryOnly: true,
  }
}

/** mode (octal string) has no permission bit outside `mask` → "no more permissive". */
export function modeWithin(mode: string, mask: number): boolean {
  const m = parseInt(mode, 8)
  if (!Number.isFinite(m) || Number.isNaN(m)) return false
  return (m & ~mask) === 0
}

export const GENERIC_STATE: Loc = {
  en: 'Review the current evaluation detail of the latest scan for this host; this guidance is advisory only.',
  es: 'Revise el detalle de evaluación actual del último escaneo para este host; esta guía es solo orientativa.',
}

export const GENERIC_PREREQ: Loc = {
  en: 'Shell access on the target host with the privileges indicated per step (root/sudo).',
  es: 'Acceso por shell al host objetivo con los privilegios indicados en cada paso (root/sudo).',
}

export const GENERIC_SIDE_EFFECTS: Loc = {
  en: 'Depends on the step: config edits can lock out sessions if syntax is wrong; always validate before reloading services.',
  es: 'Depende del paso: editar configuraciones puede bloquear sesiones si la sintaxis es incorrecta; valide siempre antes de recargar servicios.',
}
