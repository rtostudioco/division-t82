# ARCHITECTURE PROPOSAL — DIVISION T82

Adaptación honesta del master prompt al entorno real (Next.js 16 sandbox + Debian host). El objetivo final (Tauri 2 + Python sidecar) se mantiene como roadmap de distribución; la arquitectura aquí propuesta es **portable a ese destino** porque replica el patrón ya probado en el repo base: frontend sin lógica del motor + contratos versionados.

## 1. Principios → decisiones

| Principio del prompt | Decisión técnica |
|---|---|
| Local-first / Privacy-first | Todo en el equipo: SQLite local, sin telemetría, sin llamadas externas por defecto |
| Read-only by default | Colectores 100% lectura; `execFile` sin shell; **cero** endpoints de modificación |
| Evidence-based | Cada control produce `Evidence` (schema v1) persistida con método, fuente y trazabilidad |
| Explainable | Score con fórmula pública + cobertura separada; cada hallazgo explica causa/riesgo/remediación |
| Human-controlled remediation | Hardening Studio solo advisory (pasos, riesgos, rollback); sin ejecución |
| Cross-platform adapters | `PlatformAdapter` común; Linux implementado; Windows/macOS diseñados con catálogo reservado |
| Estados honestos | Sin permisos → `NOT_ASSESSED`; función inexistente → `NOT_APPLICABLE`; nunca PASS sin evidencia |

## 2. Capas

```
src/lib/engine/            ← motor (servidor; el cliente jamás ejecuta comandos)
  types.ts                 ← SecurityControl v1, Evidence v1, estados, categorías, Loc
  util/exec.ts             ← allowlist estricta, execFile sin shell, timeout, límite de salida
  util/paths.ts            ← rutas fijas permitidas (anti path-traversal), lecturas acotadas
  platform.ts              ← detección de plataforma/distro (os.release + /etc/os-release)
  collectors/linux/**      ← colectores reales read-only (una función por dominio)
  rules/linux/**           ← controles VC-LNX-xxxx (evaluación pura sobre Evidence Bag)
  rules/designed.ts        ← catálogos diseñados VC-WIN-xxxx / VC-MAC-xxxx (no implementados)
  scoring.ts               ← scoring explicable + cobertura
  runner.ts                ← orquestador: inventario → evidencia → controles → persistencia → auditoría
  knowledge.ts             ← índice/búsqueda del Knowledge Center
src/app/api/**             ← frontera IPC (route handlers tipados, solo lectura salvo POST scan)
src/components/views/**    ← 13 módulos UI (shadcn/ui + recharts)
src/lib/i18n.tsx           ← EN/ES (UI); contenido técnico EN + artículos ES
prisma/schema.prisma       ← Host, ScanJob, ControlResult, Evidence, Finding, KnowledgeArticle,
                             RemediationPreview, AuditHistory, ApplicationSetting, SourceReference
```

## 3. Contratos (v1)

### SecurityControl (regla)

```ts
interface SecurityControl {
  id: string                    // "VC-LNX-0101"
  version: string               // "1.0.0"
  name: Loc                     // bilingual {en, es}
  description: Loc
  category: ControlCategory     // 11 categorías del prompt §8.3
  severity: Severity            // CRITICAL|HIGH|MEDIUM|LOW|INFO
  platforms: Platform[]         // linux|windows|macos
  distros?: string[]            // ["debian","ubuntu"]
  implemented: boolean          // designed-only catalogs => false
  evidenceSource: string        // p.ej. "/etc/ssh/sshd_config"
  evaluate(bag: EvidenceBag): ControlEvaluation
  explanation: Loc              // por qué importa
  references: { label: string; url: string }[]
  remediation: Remediation      // §8.7: pasos, riesgos, rollback, verificación
  limitations?: Loc
}
```

### ControlEvaluation y estados obligatorios

`PASS | FAIL | WARNING | NOT_APPLICABLE | NOT_ASSESSED | ERROR`

- `NOT_ASSESSED` exige `reason` (p.ej. permisos insuficientes: `/etc/shadow` legible solo por root).
- `NOT_APPLICABLE` exige `reason` (p.ej. sshd no instalado).
- `ERROR` captura fallos del colector con el error técnico.

### Evidence Schema v1 (16 campos del prompt §6)

```ts
interface EvidenceRecordV1 {
  schema: "vc.evidence/v1"; recordId; hostId; os; osVersion; distro?;
  controlId; status; severity; payload (JSON); method; source; collectedAtUTC;
  confidence; privilegesRequired; reference?; limitations?; recommendation?
}
```

### Scoring explicable (público y verificable)

- Peso por severidad: CRITICAL=10, HIGH=8, MEDIUM=5, LOW=3, INFO=1.
- Crédito por estado: PASS=1.0, WARNING=0.5, FAIL=0.0.
- Score de categoría = Σ(credit×peso) / Σ(peso) × 100 **solo** sobre controles con estado puntuado.
- Score global = media de categorías con ≥1 control puntuado.
- **Cobertura = puntuados / aplicables**, mostrada SIEMPRE junto al score. Un score 100 con cobertura 40% se presenta como "score 100 · cobertura 40%" + lista explícita de no evaluados. Nunca se disimula.

## 4. Seguridad interna de la aplicación

1. Allowlist cerrada de comandos (`ss`, `dpkg-query`, `apt-get -s`, `systemctl`…) y rutas fijas (`/etc/*`, `/proc/sys/*`) — sin shell, sin interpolación de usuario.
2. `execFile` con timeout (≤6 s) y límite de salida (256 KB).
3. Sin endpoints administrativos; sin ejecución de comandos del usuario o de un LLM.
4. Evidencia redactada: usuarios listados sin hashes; nunca se leen/almacenan secretos.
5. Auditoría de operaciones en `AuditHistory` (scan.run, scan.reset, settings.update).
6. El frontend solo habla HTTP con `/api/**` (frontera idéntica al patrón que permitió el port Tauri del repo base).

## 5. Adaptadores

| Plataforma | Estado | Fuentes |
|---|---|---|
| Linux (Debian 13 sandbox) | **IMPLEMENTADO** (read-only real) | /etc/os-release, /etc/passwd, /etc/login.defs, /proc/sys, `ss`, `dpkg-query`, `apt-get -s upgrade`, /etc/apt/*, /etc/apparmor.d, /etc/crypttab, stat() de archivos sensibles |
| Windows 10/11 | DISEÑADO (catálogo VC-WIN, colectores documentados) | WMI/CIM, `Get-MpComputerStatus`, `Get-NetFirewallProfile`, BitLocker/TPM/SecureBoot, registro lectura |
| macOS | DISEÑADO (catálogo VC-MAC) | FileVault, Gatekeeper, SIP, firewall pf, launchd, APIs Apple oficiales |

El runtime detecta la plataforma y ejecuta solo el adaptador correspondiente; los demás catálogos aparecen en la UI como **Diseñado — no implementado en este entorno** (honestidad §16).

## 6. Módulos universales → implementación

Los 13 ítems del sidebar del prompt (§10) se implementan como vistas de un shell único (ruta `/`), con datos reales del último escaneo. Vulnerability/Threat Intelligence quedan como **módulos estructurados honestos**: modelo de datos, UI y contratos listos; ingesta NVD/CISA KEV requiere conectividad estable y queda señalada como pendiente (sin datos inventados).
