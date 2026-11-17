# Modelo de amenazas — DIVISION T82

> Documento vivo. Última revisión: v0.3.0 (2026-11).
> Complementa `SECURITY.md` (divulgación) y `docs/AUDIT_STATUS.md` (honestidad del motor).

## 1. Alcance y activos

DIVISION T82 es una herramienta **local-first**: audita la máquina donde corre,
no modifica nada (read-only) y guarda todo en SQLite local. Los activos a
proteger son:

| Activo | Dónde | Riesgo si se expone |
|---|---|---|
| Resultados de evaluación (score, controles, hallazgos) | SQLite local | Mapa de debilidades del host — útil para un atacante |
| Evidencia recolectada (configs, listeners, permisos) | SQLite local | Detalles de configuración interna |
| Inventario de paquetes (nombre + versión) | SQLite local | Base para explotación dirigida |
| Conversaciones del asistente | SQLite local | Contexto de seguridad del operador |
| Hashes / secretos | **NO se almacenan** — `/etc/shadow` se reduce a estado por cuenta (`locked/EMPTY/SET`), sin hash | — |

## 2. Límites de confianza (trust boundaries)

```text
┌─────────────────────────────────────────────────────────────┐
│ HOST del operador                                           │
│                                                             │
│  ┌──────────────┐   loopback:3000   ┌────────────────────┐  │
│  │ Navegador    │◄─────────────────►│ App Next.js (T82)  │  │
│  │ del operador │  loopback:3030    │  ├─ API guard      │  │
│  └──────────────┘        ▲          │  ├─ Motor T82      │  │
│  ┌──────────────┐        │          │  └─ SQLite         │  │
│  │ Cliente MCP  │────────┘          └────────────────────┘  │
│  │ (local)      │                    ▲ solo-lectura /etc,/proc
│  └──────────────┘                    │                      │
│  ⚠ sitios web maliciosos visitados  │                      │
│    desde el navegador del operador  │                      │
└─────────────────────────────────────┼──────────────────────┘
                                      │
                     ┌────────────────┴────────────────┐
                     │  Proveedor del modelo (LLM)     │
                     │  solo resumen agregado;         │
                     │  hostname/usuario nunca salen   │
                     └─────────────────────────────────┘
                     ┌─────────────────────────────────┐
                     │  Fuentes OSV / NVD / CISA-KEV   │
                     │  solo ingesta descarga→SQLite   │
                     └─────────────────────────────────┘
```

## 3. Actores de amenaza y mitigaciones

### T1 — Sitio web malicioso que visita el operador (CSRF / DNS-rebinding)
Un `<img>` o `fetch()` desde cualquier página puede intentar golpear
`http://127.0.0.1:3000`. Con DNS-rebinding, un dominio del atacante resuelve a
`127.0.0.1` y su JS puede leer respuestas (same-origin tras el rebind).

**Mitigaciones implementadas:**
- **Guard de mutaciones** (`src/lib/api-guard.ts`): todo POST/PATCH/DELETE exige
  el header custom `x-t82-client: t82-web` (imposible cross-site sin CORS
  preflight, que la app nunca concede) + `Origin` same-origin cuando presente +
  `Host` de loopback cuando no hay `Origin` (mata el rebinding). Lecturas GET
  no exponen secretos: solo la postura que el operador ya posee.
- **Bind loopback por defecto** en TODAS las instalaciones (systemd, portable,
  LaunchAgent, NSIS/WinSW, docker-compose publica solo `127.0.0.1`).
- **MCP server**: bind explícito `127.0.0.1`, rechazo de `Host` no local y
  `Origin` cruzado, rate limit 60/min, cuerpo ≤ 256 KB.

### T2 — Malware / otro proceso local
Cualquier proceso local puede alcanzar el puerto de loopback.

**Mitigaciones:** el mismo guard de mutaciones aplica (el header custom sigue
siendo necesario para mutar). El motor ejecuta **solo binarios de una
allowlist cerrada** con argumentos prefijados (`safeExec`), lee **solo rutas de
una allowlist fija** (`safeRead`/`safeStat`) sin shell. El peor caso de un
compromiso total de la app es leer la postura del propio host — porque la app
ya no puede escribir nada fuera de su SQLite ni ejecutar nada fuera de la
allowlist.

### T3 — Exfiltración hacia servicios externos
- **LLM del asistente**: solo sale el resumen agregado (score, estados,
  top CVEs) y la plataforma genérica (SO/kernel/arquitectura). **Hostname y
  nombre de usuario nunca salen de la máquina** (minimización D1).
- **Ingesta OSV/NVD/KEV**: solo consultas de paquete+versión al hacer clic
  «Ingesta» o con el scheduler activado. Sin telemetría, sin analytics.
- Sin credenciales del SDK en el entorno, el asistente devuelve un error
  honesto y nada sale.

### T4 — Persistencia de datos corruptos o pérdida silenciosa
- `prisma db push` **sin `--accept-data-loss`** en todos los caminos de
  instalación/arranque: un cambio destructivo de esquema falla con error claro
  y **aborta** (instalador NSIS hace `Abort`; entrypoint Docker sale 1;
  Tauri muestra el error y no abre la webview). Los datos nunca se pierden en
  silencio.
- Los scans interrumpidos (crash/reinicio) se marcan `failed` con motivo al
  arrancar; nunca quedan «running» para siempre.

### T5 — Suministro (artefactos de release)
- CI publica instaladores y un **SHA256SUMS que cubre todos los artefactos**
  (tar.gz, .deb, .exe y, si se activa, .dmg/.pkg).
- Build reproducible en la máquina destino para Linux (el artefacto lleva
  fuente; la compilación ocurre allí) — el binario que ejecutas lo generas tú.

## 4. Riesgos residuales honestos

| Riesgo | Estado |
|---|---|
| Escaneo sin root: la aplicación de firewall (ufw/nft) puede no poder verificarse por sonda runtime → el control degrada a la configuración con `WARNING` explícito | Aceptado y documentado |
| Contenedores: el motor audita el `/etc` y `/proc` del contenedor, no el del host | Documentado en deploy/README.md |
| Otros EDR/antivirus no se detectan (solo ClamAV): un FAIL significa «ClamAV ausente», no «sin protección» | Nota en el propio control |
| SELinux: fuera de alcance del adaptador actual (ecosistema AppArmor) | Documentado |
| La webview Tauri carga `http://127.0.0.1:<puerto>`: CSP aplicada a los recursos empaquetados; el servidor local sirve cabeceras propias | Mitigado con CSP estricta + guard |
| El puerto 43182 de Tauri y 3030 de MCP están en loopback; un malware local podría hablar con el MCP read-only | Riesgo aceptado: sin capacidad de escritura |

## 5. Denuncias

¿Encontraste una vulnerabilidad? Proceso en [`SECURITY.md`](../SECURITY.md).
