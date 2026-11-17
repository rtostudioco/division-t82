# 🛠 DIVISION T82 · How-To (guías paso a paso)

> **DIVISION T82** · By: Ramón Taboada Olivella — RTO Studio
> Todo lo descrito aquí es **solo lectura / solo asesoría** salvo donde se indique.

Índice: [1. Primera auditoría](#1-primera-auditoría-en-60-segundos) ·
[2. Leer la puntuación](#2-entender-la-puntuación) ·
[3. Hallazgos y remediación](#3-explorar-hallazgos-y-remediación) ·
[4. Informes](#4-exportar-informes) ·
[5. Asistente IA](#5-usar-el-asistente-t82) ·
[6. Cliente MCP](#6-conecta-un-cliente-mcp-claude-desktop-cursor) ·
[7. Inteligencia CVE](#7-inteligencia-de-vulnerabilidades-osvnvdkev) ·
[8. Instalar en otros equipos](#8-instalar-en-otros-equipos-centro-de-descargas) ·
[9. Copia de seguridad](#9-copia-de-seguridad-y-restauración) ·
[10. Actualizar](#10-actualizar-o-desinstalar) ·
[11. Problemas](#11-solución-de-problemas)

---

## 1. Primera auditoría en 60 segundos

1. Abre la app (`http://localhost:3000`).
2. Pulsa **Reevaluar** (esquina superior derecha del Resumen).
3. En segundos verás: puntuación 0–100, cobertura, riesgos por severidad y
   recomendaciones priorizadas.
4. Sin root la cobertura baja (hay controles que necesitan leer `/etc/shadow`,
   iptables, etc.). Para cobertura completa, instala el servicio de sistema
   (`sudo ./install.sh`) y reevalúa.

> El motor **nunca escribe** en tu sistema. Todo lo que lee queda registrado
> como evidencia (`vc_evidence/v1`) con marca temporal.

## 2. Entender la puntuación

La fórmula es **pública** (verás la cadena `formula` en la API y en la UI):

```text
categoría = Σ(crédito·peso) / Σ(peso) × 100   sobre controles puntuables (PASS/WARNING/FAIL)
global    = media de las categorías con ≥1 control puntuable
pesos     : CRITICAL=10 · HIGH=8 · MEDIUM=5 · LOW=3 · INFO=1
créditos  : PASS=1.0 · WARNING=0.5 · FAIL=0.0
cobertura = puntuados / aplicables  (NOT_APPLICABLE excluido)
```

Reglas de oro:
- **Lo no evaluado NO penaliza** — por eso la cobertura se muestra al lado: una
  nota alta con cobertura baja no significa nada.
- `WARNING` da medio crédito: es un estado intermedio honesto, no un FAIL camuflado.

## 3. Explorar hallazgos y remediación

- **Hallazgos**: lista priorizada por severidad con el control implicado
  (`VC-LNX-xxxx`), el detalle y la evidencia.
- **Evaluación de Seguridad**: el catálogo completo con estado por control y su
  explicación.
- **Hardening Studio**: vistas previas de remediación — te muestran *qué cambiaría*
  (comando/config) **sin ejecutarlo**. Copia, revisa y aplica tú mismo.
- **Exposición de Red**: puertos en escucha y superficie visible.

## 4. Exportar informes

Vista **Informes** → elige formato. El informe incluye resumen ejecutivo,
cobertura, hallazgos, evidencia referenciada y limitaciones — pensado para
adjuntar a un informe de auditoría formal.

## 5. Usar el Asistente T82

Botón flotante «Abrir el asistente de seguridad» (o los *chips* de sugerencia).

- Preguntas útiles: *«Resume mi postura»*, *«¿Qué riesgo atiendo primero?»*,
  *«Explica el control VC-LNX-0101»*.
- El asistente **solo recibe el resumen agregado** de tu última evaluación —
  nunca evidencia cruda, hashes ni secretos.
- Es **advisory-only**: no ejecuta cambios ni accede al sistema.
- Si el backend de IA no está disponible, responde con un **error honesto**
  (502) — el resto de la plataforma sigue funcionando.

## 6. Conecta un cliente MCP (Claude Desktop, Cursor)

El servidor MCP local (puerto **3030**, streamable HTTP, sin estado) expone 5
herramientas read-only:

| Tool | Qué devuelve |
|---|---|
| `t82_latest_posture` | Resumen de la última evaluación (score, cobertura, top hallazgos) |
| `t82_control_search` | Búsqueda de controles por texto/estado/severidad |
| `t82_top_cves` | Matches CVE priorizados (KEV primero) |
| `t82_knowledge_search` | Búsqueda por palabra clave en el Centro de Conocimiento |
| `t82_ask` | Pregunta al asistente interno (grounded) |

Arranque: `cd mini-services/mcp-server && bun run dev` (o su equivalente npm).

**Claude Desktop** → `claude_desktop_config.json`:

```jsonc
{ "mcpServers": { "vulncheck-t82": { "url": "http://localhost:3030/mcp" } } }
```

**Cursor** u otros: añade un servidor MCP de tipo *streamable HTTP* con esa URL.
Prueba en vivo desde la UI: **Integraciones → Prueba en vivo (JSON-RPC)**.

## 7. Inteligencia de vulnerabilidades (OSV/NVD/KEV)

1. Vista **Inteligencia de Vulnerabilidades**.
2. Activa la **ingesta** (on-demand) — la única función que consulta Internet:
   OSV, NVD y CISA-KEV.
3. El cruce paquete↔CVE prioriza **KEV** (vulnerabilidades explotadas
   activamente) y ordena por CVSS.
4. Opcional: programa la ingesta periódica desde la propia vista.

## 8. Instalar en otros equipos (Centro de descargas)

**Informes → Centro de descargas → Generar instaladores** produce en `dist/`:

- `vulncheck-t82-<v>-source-<arch>.tar.gz` — portable (compila al instalar)
- `vulncheck-t82_<v>_all.deb` — Debian/Ubuntu
- `vulncheck-t82-<v>-win64-setup.exe` — Windows (si se generó en Windows/CI)
- `vulncheck-t82-<v>-macos-<arch>.dmg` / `.pkg` — macOS (si se generó en macOS/CI)

Cada artefacto se sirve con su **sha256** para verificación
(`sha256sum -c SHA256SUMS`).

## 9. Copia de seguridad y restauración

```bash
# parar el servicio (Linux) o detener la app; luego:
cp /var/lib/vulncheck-t82/vulncheck.db  /ruta/segura/vulncheck-$(date +%F).db
# restaurar = volver a copiar el .db en su sitio y arrancar
```

Portable: el `.db` vive en `./data/`. Nada más que copiar — todo está en SQLite.

## 10. Actualizar o desinstalar

```bash
sudo ./install.sh update      # recompila y reinicia el servicio (conserva BD)
sudo ./install.sh uninstall   # desinstala el servicio y la app (conserva BD)
```

Windows: desinstalar desde Panel de control (conserva `%ProgramData%\VULNCHECK-T82`).
macOS `.pkg`: sobrescribir con el nuevo `.pkg`; borrar LaunchDaemon si quieres salir.

## 11. Solución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| Puerto 3000 ocupado | otra instancia | `PORT=8080 ./start.sh` |
| Cobertura 0% / muy baja | sin privilegios | instala el servicio de sistema y reevalúa |
| Asistente: error 502 | backend IA no disponible | reintenta; el resto funciona igual |
| MCP «no disponible» | servicio 3030 parado | arranca `mini-services/mcp-server` |
| `.deb` no compila | falta Node 20+ | `sudo ./install.sh --install-node && sudo apt -f install` |
| `.dmg` bloqueado por Gatekeeper | sin firma de desarrollador | clic derecho → Abrir, o `xattr -cr 'DIVISION T82.app'` |

¿Falta algo? [Wiki](docs/WIKI.md) · [Especificación](docs/ARCHITECTURE_PROPOSAL.md) ·
[Contrato de API](docs/API_CONTRACT.md)
