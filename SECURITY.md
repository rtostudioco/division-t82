# 🔏 Política de seguridad — DIVISION T82

**By: Ramón Taboada Olivella — RTO Studio**

## Alcance

Aplica a la plataforma **DIVISION T82** (app Next.js, motor de evaluación,
servidor MCP local y los instaladores de Windows/macOS/Linux distribuidos en los
Releases de este repositorio).

## Reportar una vulnerabilidad

1. **No abras un Issue público** con detalles explotables.
2. Escribe a **RTO Studio** con el asunto `[T82-SECURITY]` incluyendo:
   - descripción y afectación estimada,
   - pasos de reproducción o PoC mínimo,
   - versión/commit afectado y entorno (OS, modo de instalación).
3. Acorde de respuesta inicial: **72 h**; triage y plan de corrección: **7 días**
   para criticidad alta, **30 días** para el resto.

## Política de divulgación

- Divulgación coordinada: publicamos el fix y el crédito del reportero
  (si lo deseas) en el changelog tras lanzar la versión corregida.
- No perseguimos la investigación de buena fe ni las demostraciones locales.

## Modelo de amenazas asumido

- La plataforma es **local-first** y **solo lectura**: el modelo de riesgo
  principal es el acceso no autorizado al equipo del operador, no el servicio
  remoto (no expone superficie pública por defecto: escucha en `127.0.0.1`).
- El servidor MCP solo acepta clientes del propio host.
- Las únicas salidas de red son las fuentes OSV/NVD/CISA-KEV cuando el operador
  activa la ingesta.

## Declaración de honestidad

Los resultados son **advisory-only**. La plataforma no ejecuta remediaciones y
toda puntuación se acompaña de su cobertura — interpretarla sin la cobertura es
un error de uso, no de la herramienta.
