# IMPLEMENTATION ROADMAP — DIVISION T82 (entorno sandbox)

Estado por fase (FASE 0 del master prompt → este sandbox). Las fases que requieren toolchain fuera del sandbox (Tauri/Rust, firmado, instaladores) quedan definidas con criterios de aceptación para ejecutarse en hosts nativos.

| Fase | Alcance | Estado en este build |
|---|---|---|
| 0 — Repository audit | Inspección real del repo + entorno; docs de línea base | ✅ Hecho (ver BASELINE_AUDIT) |
| 1 — Foundation | Contratos v1, esquema SQLite, motor de reglas, API local, detección de plataforma | ✅ Hecho en este build |
| 2 — Linux Security Engine | Colectores reales + 20 controles + evidencia + scoring + informes | ✅ Hecho (Debian 13 real) |
| 3 — Windows Adapter | Colectores WMI/CIM/PowerShell + catálogo VC-WIN | 🔶 Diseñado (catálogo + contratos); requiere host Windows/Tauri |
| 4 — macOS Adapter | FileVault/Gatekeeper/SIP + catálogo VC-MAC | 🔶 Diseñado; requiere host macOS |
| 5 — Universal modules | 13 módulos UI con datos reales | ✅ Hecho (single-page shell) |
| 6 — Hardening Studio | Remediation previews advisory-only (pasos/riesgos/rollback/verificación) | ✅ Hecho (sin ejecución, por diseño) |
| 7 — Vuln & Threat Intelligence | Modelo + UI + estado honesto; NVD/CISA KEV con caché | 🔶 Estructura lista; ingesta externa pendiente (conectividad) |
| 8 — Knowledge Center | Artículos estructurados (21 campos), búsqueda, enlaces a controles | ✅ Hecho (10 artículos ES, referencias oficiales) |
| 9 — UX/UI Polish | Temas NEO dark/light, i18n EN/ES, WCAG AA, estados | ✅ Hecho en este build |
| 10 — Quality & Release | Lint + verificación de navegador aquí; SBOM, firmado, instaladores | ✅ (sandbox) / 🔶 release real fuera del sandbox |

## Criterios de aceptación (aplicables al build sandbox)

1. Motor ejecuta auditoría real read-only y persiste evidencia trazable.
2. Estados obligatorios y razones (`NOT_ASSESSED`/`NOT_APPLICABLE`) visibles en UI.
3. Score + cobertura explicados con la fórmula pública.
4. Hallazgos con explicación, referencias oficiales y remediación advisory.
5. Informes exportables JSON/CSV + print-to-PDF.
6. Knowledge Center consultable (categoría/nivel/plataforma/búsqueda) enlazado a controles.
7. Dos temas completos NEO + i18n EN/ES.
8. Sin ejecución de comandos arbitrarios; allowlist verificable en `util/exec.ts`.
9. Lint limpio + verificación end-to-end en navegador.
10. Limitaciones y cobertura transparentes en la propia UI.

## Pendientes declarados (honestidad)

- Port de escritorio Tauri 2 + Rust (colectores nativos por plataforma) — fuera del sandbox.
- Ingesta NVD/CISA KEV con caché y límites — requiere red saliente estable; módulo preparado.
- Artículos del Knowledge Center en inglés (hoy ES con título/resumen EN).
- Firma/notarización e instaladores — proceso de release en hosts nativos.
