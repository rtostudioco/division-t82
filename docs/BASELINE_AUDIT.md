# BASELINE AUDIT — DIVISION T82

Fecha: 2026-11-13 · Auditoría FASE 0 (real, verificable, sin suposiciones).

## 1. Metodología

- Inspección remota del repositorio `rtostudioco/vulncheck-local` vía `raw.githubusercontent.com` (la API de GitHub está rate-limitada en este entorno; el acceso raw y el scraping del árbol HTML sí funcionaron).
- Archivos revisados directamente: `README.md`, `README.es.md`, `package.json`, `prisma/schema.prisma`, `src/lib/engine/rules.ts`, `docs/ARCHITECTURE.md`, `docs/DETECTION-RULES.md`, `docs/LIMITATIONS.md`, `desktop/docs/IMPLEMENTATION-STATUS.md`, árbol de `src/`, `desktop/`.
- El sandbox de trabajo **no contiene el código del repositorio** (es una plantilla Next.js 16 nueva con tooling idéntico). Ninguna funcionalidad del repo se "conserva" localmente; se conservan sus **convenciones y contratos**, y se documenta la decisión.

## 2. Producto existente identificado

**Sentinel Desk 1.0.0** (MIT, RTO Studio) — "Personal SOC & Threat Detection Platform", orientado a Windows 10/11. Fuente de eventos sintética y etiquetada (`synthetic=true`) en el build web; puerto de escritorio Tauri 2 + Rust con colector EVTX real en `desktop/`.

### Funcionalidades verificadas (no inventadas)

| Capacidad | Estado en el repo |
|---|---|
| Pipeline collector → normalizer → detection → correlation → incidents | Implementado, con PipelineRun por etapa |
| 10 reglas versionadas `SD-001…SD-010` (Sigma-inspired JSON logic, MITRE ATT&CK, falsePositives, limitations) | Implementado |
| Correlación por ventana temporal + incidentes con máquina de estados | Implementado |
| Threat intelligence (validación de IOCs, lookup consent-gated, deshabilitado por diseño) | Implementado (parcial) |
| AI analyst con redacción + auditoría (provider/model/promptVersion) | Web verificado |
| Reportes JSON (SHA-256), CSV, print-to-PDF | Implementado |
| i18n EN/ES | Completo en web |
| Desktop Tauri 2 + Rust (EVTX real, `overview_stats`, reportes) | Backend OK; timeline/graph/TI/AI pendientes en desktop |
| Instalador MSI/NSIS vía GitHub Actions (windows-latest) | CI sin firma (documentado) |

### Modelo de datos existente (SQLite/Prisma)

`Event`, `EventSource` (estados honestos: `active|demo|permission_required|unavailable`), `DetectionRule`, `Alert` + `AlertEvent` (join de evidencia), `Incident`, `IncidentNote`, `AiAnalysis`, `Indicator`, `Setting`, `AuditLog`.

### Decisiones arquitectónicas valiosas (se heredan)

1. **El frontend no contiene lógica del motor** — solo consume la API; hace que el port a Rust/Tauri sea mecánico.
2. **Reglas portables en formato JSON-logic versionado** (reimplementables 1:1 en Rust).
3. **Estados de fuente honestos** y etiquetas `synthetic`/`sourceRef` — nada se presenta como telemetría real si no lo es.
4. **Límites/falsePositives declarados por regla** — ausencia de alertas ≠ ausencia de ataques.

## 3. Gap hacia la plataforma DIVISION T82

El repo cubre **detección orientada a eventos (SOC)**. El master prompt exige además **evaluación de postura (controles PASS/FAIL con evidencia local real)**, inventario, Hardening Studio, Knowledge Center y adaptadores por plataforma. No cubierto por el repo:

- Motor de controles de postura con estados `PASS|FAIL|WARNING|NOT_APPLICABLE|NOT_ASSESSED|ERROR`.
- Colecta real read-only (Linux: /proc, /etc, ss, dpkg, apt; Windows: WMI/CIM/PowerShell; macOS: APIs Apple).
- Scoring explicable con **cobertura separada del score**.
- Hardening Studio (solo advisory, sin ejecución).
- Knowledge Center estructurado (21 campos/artículo) enlazado a controles.

**Decisión:** el dominio de eventos (Alert/Incident) es distinto del dominio de postura (Control/Evidence). Se conserva el estilo de IDs versionados (nuevos namespaces `VC-LNX-…`, `VC-WIN-…`, `VC-MAC-…` junto al concepto `SD-…`), los estados honestos y el patrón API-boundary. El esquema de eventos NO se reutiliza: el nuevo esquema (ver `prisma/schema.prisma`) modela controles/evidencia/hallazgos.

## 4. Entorno sandbox (capacidades reales verificadas)

| Elemento | Resultado |
|---|---|
| OS | Debian GNU/Linux 13 (trixie), kernel 5.10 x86_64 |
| Usuario | `z` uid 1001 — **sin root**; `sudo` presente pero no usable sin TTY/password |
| Rust/Cargo | **Ausente** → Tauri 2 no empaquetable aquí (documentado; el port de escritorio se ejecuta fuera del sandbox) |
| Docker/Podman | Ausentes |
| systemd | `systemctl is-system-running` → `offline` (contenedor) → controles de servicios → `NOT_ASSESSED` |
| Herramientas presentes | `ss`, `dpkg`, `apt`, `python3`, `node` 24, `bun` 1.3.14 |
| Ausentes | `ufw`, `nft`, `iptables`, `cryptsetup`, `aa-status`, `lsb_release` |
| Legible sin root | `/etc/passwd`, `/etc/login.defs`, `/etc/os-release`, `/proc/sys/*`, `/etc/apparmor.d` |
| No legible | `/etc/shadow`, `/etc/sudoers` (→ `NOT_ASSESSED`, nunca PASS) |
| sshd | `/etc/ssh/sshd_config` ausente → controles SSH → `NOT_APPLICABLE` (no es un fallo) |
| Red | `ss -tulnH` funcional (puertos reales observables) |
| GitHub | API 403 (rate-limit); raw 200 |

## 5. Riesgos previos detectados

1. Sin toolchain Rust → builds/instaladores de escritorio imposibles en este entorno (riesgo documentado, no bloqueante para el motor/UI).
2. Kernel compartido de contenedor → sysctls y LSM reflejan el host; se marca `limitations` en cada control afectado.
3. Caché APT posiblemente vacía → el control de actualizaciones debe verificar la frescura de `/var/lib/apt/lists` o degradar a `NOT_ASSESSED` (evita PASS falsos).
4. Inspección del repo parcial (rate-limit) → basada en los archivos clave enumerados; ningún archivo central del motor quedó sin revisar.

## 6. Conclusión

Base sólida de convenciones y un target claro. Se construye el motor de postura nuevo (contratos `VC-*`), sobre el patrón probado del repo: **contratos versionados + estados honestos + evidencia trazable + frontend sin lógica del motor**.
