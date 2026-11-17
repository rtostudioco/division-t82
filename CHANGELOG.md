# 📋 Changelog — DIVISION T82

Formato: [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) ·
Versionado: SemVer (`MAJOR.MINOR.PATCH`).

## [0.3.0] — 2026-11-17

### Security · P0/P1 — segunda tanda de hardening (motor, instaladores, IA)
- **Bind loopback en los `start.sh` generados** — `make-release.sh` y
  `build-standalone.sh` seguían empaquetando un arranque con `HOSTNAME=0.0.0.0`
  por defecto; ahora `127.0.0.1` (el ejemplo `docker run` del Dockerfile
  documenta la publicación solo en loopback).
- **Drop-ins SSH ya evaluados (precisión del motor)** — la allowlist de lectura
  exigía que los ficheros de `/etc/ssh/sshd_config.d`, `/etc/sudoers.d` y
  `/etc/apparmor.d` empezaran por punto; los nombres reales
  (`10-custom.conf`, `usr.bin.firefox`) se rechazaban en silencio y las
  reglas SSH evaluaban sin ellos. Ahora se admiten (frontera cerrada:
  un solo segmento, sin `..`, sin sufijos `~`/`#`).
- **safeStat restringido** — antes aceptaba `stat` de CUALQUIER ruta bajo
  `/etc/`; ahora obedece la misma allowlist que las lecturas.
- **Firewall por estado real** — nueva sonda runtime (`ufw status`,
  `nft list ruleset`, ambas read-only): si responde, el veredicto es del
  kernel; si requiere root y falla, se degrada a la configuración con
  `WARNING` explícito.
- **ClamAV por estado real** — además del binario, se comprueba si
  `clamav-daemon` está entre los servicios systemd activos y el detalle del
  PASS lo comunica (on-access activo vs solo on-demand).
- **LUKS por estado real** — `lsblk TYPE=crypt` prueba volúmenes mapeados
  AHORA; `/etc/crypttab` queda como fallback documentado.
- **`safeExec` se mantiene cerrado** — solo se añadieron las sondas de
  firewall read-only a la allowlist existente.
- **SHA256SUMS completos (C7)** — el release final ahora incluye el hash del
  `setup.exe` (y de los .dmg/.pkg si se activan macOS): el checksum que
  verificas cubre TODOS los artefactos publicados.
- **`prisma db push` sin pérdida silenciosa (C3)** — se retira
  `--accept-data-loss` de `install.sh`, `entrypoint.sh` (Docker), unit systemd
  y `start.sh` generados; los fallos de esquema abortan con error claro
  (NSIS hace `Abort`, Docker sale 1, Tauri muestra el error y no abre la
  webview). Los datos nunca se pierden en silencio.
- **Tauri con CSP estricta (C5)** — `csp: null` sustituido por una política
  cerrada a loopback (`default-src`/`connect-src` a `http://127.0.0.1:*`,
  `object-src 'none'`, `frame-ancestors 'none'`).
- **Privacidad del Asistente T82 (D1)** — el contexto que viaja al proveedor
  LLM ya NO incluye hostname ni nombre de usuario: solo plataforma genérica
  (SO/kernel/arquitectura), score, estados y top CVEs.
- **Rate limit honesto (D2)** — el límite del asistente usa un cubo global por
  proceso en lugar de una clave `X-Forwarded-For` falsificable.

### Docs
- **`docs/THREAT_MODEL.md`** — actores de amenaza (CSRF/DNS-rebinding, malware
  local, exfiltración, suministro), límites de confianza y mitigaciones.
- **`docs/AUDIT_STATUS.md`** — qué evalúa cada control, con qué evidencia y
  qué limita su veredicto; principio «estado real sobre configuración».
- README: sección de privacidad por minimización + enlaces a la nueva
  documentación de seguridad.

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

[0.3.0]: ../../releases/tag/v0.3.0
[0.2.1]: ../../releases/tag/v0.2.1
