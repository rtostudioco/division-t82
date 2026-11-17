// DIVISION T82 — scan runner: orchestrates collection → evaluation → persistence.
// Server-side only. Read-only evidence; no user input reaches collectors.
import { db } from '@/lib/db'
import { detectPlatform } from './platform'
import { rulesFor } from './rules'
import { computeScore, ENGINE_VERSION } from './types'
import type { ScoreInput, SecurityControl } from './types'
import type { LinuxEvidenceBag, PlatformInfo } from './collectors/linux/bag'
import type { EvidenceFragment } from './types'
import { collectLinuxEvidence } from './collectors/linux'
import { CONTROL_CATEGORIES, type ControlCategory, type ControlStatus, type Severity } from './types'

interface RunOptions {
  scope?: string[]
}

export interface RunScanResult {
  scanId: string
  score: number | null
  coverage: number
}

export async function runScan(options: RunOptions = {}): Promise<RunScanResult> {
  const platformInfo: PlatformInfo = await detectPlatform()
  if (platformInfo.platform !== 'linux') {
    throw new Error(`Platform "${platformInfo.platform}" has no implemented adapter in this build (Linux only)`)
  }

  const startedAt = new Date()
  const scope = (options.scope ?? []).filter((s) => (CONTROL_CATEGORIES as readonly string[]).includes(s))

  // 1) collect evidence (single pass)
  const bag: LinuxEvidenceBag = await collectLinuxEvidence(platformInfo)

  // 2) host upsert (hostname as stable natural key)
  const host = await db.host.upsert({
    where: { id: platformInfo.hostname },
    update: {
      os: platformInfo.os,
      osVersion: platformInfo.osVersion,
      distro: platformInfo.distro,
      distroFamily: platformInfo.distroFamily,
      kernel: platformInfo.kernel,
      arch: platformInfo.arch,
      user: platformInfo.user,
      isRoot: platformInfo.isRoot,
    },
    create: {
      id: platformInfo.hostname,
      hostname: platformInfo.hostname,
      os: platformInfo.os,
      osVersion: platformInfo.osVersion,
      distro: platformInfo.distro,
      distroFamily: platformInfo.distroFamily,
      kernel: platformInfo.kernel,
      arch: platformInfo.arch,
      user: platformInfo.user,
      isRoot: platformInfo.isRoot,
    },
  })

  // 3) scan job
  const scan = await db.scanJob.create({
    data: {
      hostId: host.id,
      platform: platformInfo.platform,
      engineVersion: ENGINE_VERSION,
      status: 'running',
      scopeJson: JSON.stringify(scope),
    },
  })

  // 4) evaluate implemented rules
  const rules: SecurityControl[] = rulesFor(platformInfo.platform, scope)
  const scoreInputs: ScoreInput[] = []
  const inventoryNotes: string[] = []
  const t0 = Date.now()

  for (const rule of rules) {
    let evaluation
    const ruleStart = Date.now()
    try {
      evaluation = rule.evaluate(bag)
    } catch (e) {
      evaluation = {
        status: 'ERROR' as ControlStatus,
        detail: `evaluator exception: ${String((e as Error).message).slice(0, 300)}`,
      }
    }
    const durationMs = Date.now() - ruleStart
    scoreInputs.push({
      controlId: rule.id,
      severity: rule.severity,
      status: evaluation.status,
      category: rule.category,
    })

    // persist evidence fragments (traceability)
    let firstEvidenceId: string | null = null
    if (evaluation.evidence && evaluation.evidence.length > 0) {
      for (const frag of evaluation.evidence.slice(0, 6)) {
        const ev = await db.evidence.create({
          data: {
            scanId: scan.id,
            controlId: rule.id,
            schemaVersion: 'vc.evidence/v1',
            method: frag.method,
            source: frag.source,
            payloadJson: JSON.stringify(sanitizePayload(frag.payload)).slice(0, 200000),
            confidence: frag.confidence,
            privilegesRequired: frag.privilegesRequired ?? null,
            redacted: frag.redacted ?? true,
          },
        })
        if (!firstEvidenceId) firstEvidenceId = ev.id
      }
    }

    await db.controlResult.create({
      data: {
        scanId: scan.id,
        controlId: rule.id,
        controlVersion: rule.version,
        controlName: JSON.stringify(rule.name),
        category: rule.category,
        severity: rule.severity,
        status: evaluation.status,
        reason: evaluation.reason ?? null,
        detail: evaluation.detail ?? null,
        explanation: JSON.stringify(rule.explanation),
        limitations: rule.limitations ? JSON.stringify(rule.limitations) : null,
        evidenceId: firstEvidenceId,
        privilegesRequired: evaluation.evidence?.[0]?.privilegesRequired ?? null,
        durationMs,
      },
    })

    if (evaluation.status === 'FAIL' || evaluation.status === 'WARNING') {
      await db.finding.create({
        data: {
          scanId: scan.id,
          controlId: rule.id,
          controlName: JSON.stringify(rule.name),
          category: rule.category,
          severity: rule.severity,
          status: evaluation.status,
          detail: evaluation.detail ?? evaluation.reason ?? null,
        },
      })
      await db.remediationPreview.create({
        data: {
          controlId: rule.id,
          scanId: scan.id,
          payloadJson: JSON.stringify(rule.remediation),
          advisoryOnly: true,
        },
      })
    }

    if (evaluation.status === 'ERROR') {
      inventoryNotes.push(`${rule.id}: ${evaluation.detail ?? 'error'}`)
    }
  }

  // 5) scoring + inventory snapshot
  const score = computeScore(scoreInputs)
  const inventory = buildInventory(bag, inventoryNotes)

  await db.scanJob.update({
    where: { id: scan.id },
    data: {
      status: 'completed',
      finishedAt: new Date(),
      score: score.overall,
      coverage: score.coverage,
      countsJson: JSON.stringify(score.counts),
      severityJson: JSON.stringify(score.severityCounts),
      inventoryJson: JSON.stringify(inventory),
      durationMs: Date.now() - t0,
    },
  })

  await db.auditHistory.create({
    data: {
      action: 'scan.run',
      target: scan.id,
      detail: `score=${score.overall ?? 'n/a'} coverage=${score.coverage}% controls=${scoreInputs.length}`,
    },
  })

  return { scanId: scan.id, score: score.overall, coverage: score.coverage }
}

function sanitizePayload(payload: unknown): unknown {
  // redaction boundary: strip obvious secrets if ever present
  if (typeof payload === 'string') {
    return payload.length > 20000 ? payload.slice(0, 20000) + '…[truncated]' : payload
  }
  return payload
}

function buildInventory(bag: LinuxEvidenceBag, notes: string[]) {
  const humans = (bag.passwd ?? []).filter((u) => u.uid >= 1000 && u.uid !== 65534)
  const systemUsers = (bag.passwd ?? []).filter((u) => u.uid < 1000).length
  return {
    os: bag.osRelease
      ? { prettyName: bag.osRelease.prettyName, id: bag.osRelease.id, versionId: bag.osRelease.versionId }
      : null,
    kernel: bag.kernelRelease,
    platform: bag.platform,
    hardware: {
      cpuModel: bag.cpuModel,
      cpuCores: bag.cpuCores,
      memoryTotalMB: bag.memoryTotalMB,
      uptimeHours: bag.uptimeHours,
    },
    packages: { count: bag.packagesCount, list: bag.packages },
    users: {
      human: humans.map((u) => ({ name: u.name, uid: u.uid, shell: u.shell, home: u.home })),
      systemCount: systemUsers,
      rootOnlyUid0: (bag.passwd ?? []).filter((u) => u.uid === 0).map((u) => u.name),
    },
    network: {
      interfaces: bag.interfaces,
      listeners: bag.listeners,
      ipForward: bag.ipForward,
      firewall: bag.firewall,
    },
    identity: {
      shadowReadable: bag.shadowReadable,
      sudoersReadable: bag.sudoersReadable,
      sudoersFiles: bag.sudoersFiles,
      passwordMaxDays: bag.loginDefs?.PASS_MAX_DAYS ?? null,
      sshdPresent: bag.sshdConfigPresent,
    },
    hardening: {
      sysctls: bag.sysctls,
      sysctlsNet: bag.sysctlsNet,
      systemdRunning: bag.systemdRunning,
      runningServices: bag.runningServices?.slice(0, 60) ?? null,
      initComm: bag.initComm,
      apparmorLsmActive: bag.apparmorLsmActive,
      filePerms: bag.filePerms,
    },
    encryption: { crypttabExists: bag.crypttabExists, cryptsetupInstalled: bag.cryptsetupInstalled },
    endpoint: { clamavInstalled: bag.clamavInstalled, gccInstalled: bag.gccInstalled },
    swap: { devices: bag.swapDevices },
    updates: {
      aptCacheFresh: bag.aptCacheFresh,
      pendingUpdates: bag.pendingUpdates,
      pendingSecurityUpdates: bag.pendingSecurityUpdates,
      unattendedUpgradesEnabled: bag.unattendedUpgradesEnabled,
      unattendedInstalled: bag.unattendedInstalled,
    },
    evidenceNotes: notes,
    collectedAt: new Date().toISOString(),
  }
}

export type { ControlCategory, Severity }
