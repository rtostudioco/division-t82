# 📋 Changelog — DIVISION T82

Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) ·
Versionado: SemVer (`MAJOR.MINOR.PATCH`).

## [Sin publicar]

### Security · P0 — hardening de red local-first
- **Loopback por defecto en toda la plataforma** — la web ya no escucha en
  `0.0.0.0` en ninguna instalación: servicio systemd (`install.sh`,
  `vulncheck-t82.service`), runtime empaquetado (`start.sh`), LaunchAgent
  macOS (plist) y docker-compose (puerto del host publicado solo en
  `127.0.0.1`). Windows ya lo estaba (NSIS + arranque portable).
- **Guard de mutaciones en la API local** — toda petición POST/PATCH/DELETE
  exige el header `x-t82-client: t82-web` y misma origen cuando hay `Origin`;
  sin `Origin` solo se aceptan `Host` de loopback (o los listados en
  `T82_TRUSTED_HOSTS`). Bloquea CSRF clásico y DNS-rebinding contra la app
  local. Lecturas (GET) no se bloquean.
- **Servidor MCP endurecido** — bind explícito a `127.0.0.1`, rechazo de
  `Host` no local y de `Origin` cruzados (recomendación del transporte
  streamable-HTTP de MCP), rate limit de 60 req/min y cuerpo máximo 256 KB.
- **Evaluaciones resilientes** — una sola evaluación activa por instancia
  (409 si hay otra en curso); los fallos inesperados marcan el job como
  `failed` con motivo persistido (`errorReason`) y los scans interrumpidos
  por un reinicio se recuperan al arrancar el servidor.

### Added · licencia
- **Licencia MIT** — DIVISION T82 es open source: archivo `LICENSE` en la raíz,
  badge y sección Licencia en el README y campo `license` en package.json.

### Removed · repo
- `Caddyfile` retirado del repositorio público — infraestructura de desarrollo
  del sandbox, no forma parte del producto distribuido.
- **Historial de git reescrito a un commit único y limpio** — purga del
  histórico público los artefactos de runtime y archivos de configuración local
  que existieron en commits anteriores (`.env`, `db/custom.db`, `dist/`,
  `agent-ctx/`, `tool-results/`).

### Changed · marca
- El proyecto pasa a llamarse oficialmente **DIVISION T82** — el descriptor
  «VULNCHECK UNIVERSAL» se retira del naming visible (título de la app,
  Ajustes → Acerca de, prompts del Asistente T82, cabecera de los informes PDF
  y toda la documentación). El motor sigue siendo T82 v1.1.
- **Firma de autoría** en toda la plataforma — footer de la app, Ajustes,
  informes PDF, README y banner: *Creado por Ramón Taboada Olivella — RTO Studio*.

## [0.2.1] — 2026-11-17

### Added · plataforma
- Motor de evaluación T82 v1.1 (solo lectura) con **20 controles `VC-LNX-xxxx`**
  y evidencia versionada `vc_evidence/v1`.
- **Puntuación explicable** con fórmula pública (pesos por severidad, créditos
  PASS/WARNING/FAIL) y **cobertura separada** — lo no evaluado nunca infla la nota.
- 12 vistas: Resumen, Inventario, Evaluación, Hallazgos, Exposición de Red,
  Inteligencia de Vulnerabilidades, Hardening Studio, Amenazas, Conocimiento,
  Informes, Historial, Integraciones y Ajustes.
- **Inteligencia OSV / NVD / CISA-KEV**: ingesta on-demand y programada, KEV primero.
- **Hardening Studio**: vistas previas de remediación (advisory-only, sin ejecutar).
- **Asistente T82 (IA interna)**: grounded en la última evaluación, advisory-only,
  bilingüe ES/EN, con reintento transparente ante fallos del backend.
- **Servidor MCP local** (`:3030`, streamable HTTP, read-only) con 5 herramientas:
  `t82_latest_posture`, `t82_control_search`, `t82_top_cves`, `t82_knowledge_search`, `t82_ask`.
- **Informes exportables** (PDF/JSON/CSV) con resumen ejecutivo y evidencia referenciada.
- i18n ES/EN completo, temas claro/oscuro, command palette ⌘K, notificaciones.

### Added · distribución
- **Centro de descargas integrado** (Informes): genera y sirve instaladores con sha256.
- **Linux**: `install.sh` (sistema systemd endurecido o portable sin root) +
  paquete `.deb` (Architecture: all, compila al instalar) + tarball fuente portable.
- **Windows**: instalador NSIS `win64-setup.exe` con **servicio Windows** (WinSW),
  datos en `%ProgramData%\VULNCHECK-T82`, runtime Node incluido.
- **macOS**: `.dmg` portable (.app que arranca el servidor y abre el navegador) y
  `.pkg` de sistema con LaunchDaemon.
- **CI GitHub Actions** (`build-installers.yml`): matriz Linux/Windows/macOS que
  publica los 5 artefactos en un Release con el tag `v*`.
- **Scaffold Tauri 2** opcional (shell de escritorio con sidecar Node) para
  bundles `.msi`/`.exe`/`.dmg`/`.deb`/`.rpm`/`.AppImage`.

### Docs
- Portada de GitHub animada con capturas reales; specs
  (arquitectura/API/roadmap/compatibilidad), How-To paso a paso, wiki con
  glosario, SECURITY y este changelog.

## [0.2.0] — base histórica del proyecto
- Primera versión estructurada de la plataforma (motor, UI base, modelo Prisma).

[0.2.1]: ../../releases/tag/v0.2.1
