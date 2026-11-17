# 🌐 Wiki · DIVISION T82

> Página de inicio de la wiki del proyecto.
> **By: Ramón Taboada Olivella — RTO Studio**

## 🗺 Navegación

| Sección | Enlace | Qué encontrarás |
|---|---|---|
| 🏠 Portada | [README](../README.md) | Vistazo, instalación de los 3 SO, arquitectura |
| 📘 Especificación | [ARCHITECTURE_PROPOSAL](ARCHITECTURE_PROPOSAL.md) | Diseño del motor, catálogo, scoring, evidencia |
| 📡 Contrato de API | [API_CONTRACT](API_CONTRACT.md) | Endpoints, esquemas, errores |
| 🛠 Guías | [HOW-TO](HOW-TO.md) | Paso a paso: auditoría, informes, MCP, backups |
| 🗺 Roadmap | [IMPLEMENTATION_ROADMAP](IMPLEMENTATION_ROADMAP.md) | Fases del catálogo diseñado y estado |
| 🧩 Compatibilidad | [PLATFORM_COMPATIBILITY_MATRIX](PLATFORM_COMPATIBILITY_MATRIX.md) | Linux / Windows / macOS hoy |
| 📦 Despliegue | [deploy/README](../deploy/README.md) | Docker, systemd, .deb, .exe, .dmg, Tauri |
| 🔏 Seguridad | [SECURITY](../SECURITY.md) | Reporte responsable de vulnerabilidades |
| 📋 Changelog | [CHANGELOG](../CHANGELOG.md) | Historial de versiones |

## 📖 Glosario

| Término | Definición |
|---|---|
| **Control** | Comprobación individual del catálogo (`VC-LNX-xxxx`) con severidad, categoría y evidencia. |
| **Cobertura** | % de controles aplicables que el motor pudo evaluar en esta máquina (`puntuados/aplicables`). |
| **Puntuación** | 0–100 con fórmula pública: `Σ(crédito·peso)/Σ(peso)×100`. Pesos `CRITICAL=10…INFO=1`; créditos `PASS=1.0 · WARNING=0.5 · FAIL=0.0`. |
| **Evidencia** | Dato crudo que justifica un resultado, versionado como `vc_evidence/v1`. Toda conclusión enlaza a ella. |
| **PASS / WARNING / FAIL** | Cumple · cumple parcialmente o con matices (medio crédito) · no cumple. |
| **NOT_EVALUATED** | No se pudo evaluar en esta máquina (falta privilegio, binario ausente…). No penaliza: se lista explícitamente. |
| **CVE** | Identificador público de vulnerabilidad (Common Vulnerabilities and Exposures). |
| **KEV** | *Known Exploited Vulnerabilities* — catálogo CISA de CVE **explotadas activamente**; prioridad máxima en T82. |
| **CVSS** | Puntuación base de severidad de una CVE (0–10). |
| **OSV / NVD** | Bases de datos públicas de vulnerabilidades (OSV.dev / NIST NVD) que T82 ingesta bajo demanda. |
| **Hardening** | Endurecer la configuración del sistema cerrando los FAIL detectados. |
| **MCP** | *Model Context Protocol* — estándar para exponer herramientas a clientes de IA. T82 lo sirve en `:3030` read-only. |
| **RAG** | *Retrieval-Augmented Generation* — responder con datos recuperados de una base local en vez de memoria del modelo. |
| **Local-first** | Todo el dato vive en tu máquina (SQLite); ninguna telemetría ni nube obligatoria. |

## ❓ FAQ

- **¿El motor modifica mi sistema?** No. Read-only estricto; las remediaciones
  son *vistas previas* que tú aplicas manualmente.
- **¿Funciona sin Internet?** Sí: motor, scoring, informes, MCP y asistente
  (si el backend de IA está configurado). Solo la ingesta OSV/NVD/KEV necesita red.
- **¿Dónde están mis datos?** En un único SQLite (`/var/lib/vulncheck-t82` modo
  sistema, `./data` portable, `%ProgramData%\VULNCHECK-T82` en Windows,
  `~/Library/Application Support` en macOS).
- **¿Por qué mi nota baja con cobertura parcial?** No está baja *por* la
  cobertura — pero revisa los NOT_EVALUATED antes de comparar con otra máquina.
- **¿Puedo auditar Windows/macOS hoy?** Consulta la
  [matriz de compatibilidad](PLATFORM_COMPATIBILITY_MATRIX.md): el catálogo
  completo está activo en Linux; Windows/macOS progresan por fases (roadmap).

## 🔗 Fuentes de inteligencia (oficiales)

- OSV.dev — https://osv.dev
- NVD (NIST) — https://nvd.nist.gov
- CISA KEV — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
