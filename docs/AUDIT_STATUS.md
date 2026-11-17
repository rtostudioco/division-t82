# Estado de auditoría — honestidad del motor (AUDIT_STATUS)

> Este documento dice, sin adornos, **qué evalúa cada control, con qué
> evidencia y qué limita su veredicto**. Regla de oro del proyecto: lo que no
> se puede verificar se reporta como `WARNING` o `NOT_ASSESSED` — nunca como
> PASS inventado.

## 1. Principios

1. **Read-only absoluto** — el motor nunca modifica el sistema (ni un `chmod`).
2. **Evidencia trazable** — cada veredicto lleva su fragmento de evidencia
   (comando/archivo leído + dato observado) almacenado en SQLite.
3. **Degradación honesta** — un collector que falla deja el campo `null`/`*Error`
   y el control degrada a `NOT_ASSESSED` o `WARNING`; nunca inventa.
4. **Estado real sobre configuración** — cuando un binario/permiso lo permite,
   se consulta el estado de ejecución (`ufw status`, `nft list ruleset`,
   `lsblk TYPE=crypt`, servicios systemd activos); si la sonda requiere root y
   falla, se cae a la configuración con `WARNING` explícito.

## 2. Mapa de evidencia (adaptador Linux · 20 controles VC-LNX)

| Dominio | Evidencia | Fuente | Estado |
|---|---|---|---|
| OS / kernel | `/etc/os-release`, `uname -r` | runtime | sólido |
| Cuentas | `/etc/passwd` (usuarios) | runtime | sólido |
| Cuentas | estado por cuenta de `/etc/shadow` (`locked/EMPTY/SET` — sin hashes) | requiere root | sólido con root |
| sudo | `/etc/sudoers` (NOPASSWD), listado de `/etc/sudoers.d` solo con ficheros que sudoers lee (sin `.`, sin `~/#`) | requiere root para contenido | sólido con root |
| Política de contraseñas | `/etc/login.defs` | runtime | sólido |
| SSH | `/etc/ssh/sshd_config` **fusionado con `/etc/ssh/sshd_config.d/*.conf`** con semántica first-wins de sshd(8) | runtime | sólido (drop-ins ya cubiertos) |
| Sockets en escucha | `ss -tulnH` | runtime | sólido |
| Sysctl kernel/red | `/proc/sys/...` | runtime | sólido |
| systemd | `systemctl is-system-running` + `list-units --state=running` | runtime | sólido |
| **Firewall** | **sonda runtime `ufw status` / `nft list ruleset`**; fallback a `/etc/ufw/ufw.conf ENABLED` con WARNING si la sonda necesita root | runtime primero | sólido con ufw activo; honesto en el resto |
| Parches | `dpkg-query -W`, `apt-get -s upgrade` (simulado, nunca aplica), unattended-upgrades config | runtime | sólido |
| **Antimalware** | binario `clamscan`/`clamd` **+ `clamav-daemon` entre servicios activos** | runtime | instalado→PASS con detalle del daemon |
| **LSM / AppArmor** | `/sys/kernel/security/lsm` | runtime | sólido (SELinux reporta FAIL por diseño del adaptador) |
| **Cifrado en reposo** | **`lsblk TYPE=crypt` (volúmenes LUKS mapeados AHORA)**; fallback `/etc/crypttab` | runtime primero | sólido |
| Permisos ficheros | `stat` de passwd/shadow/group/login.defs | runtime | sólido |
| Swap | `lsblk` | runtime | sólido |
| Vulnerabilidades | matches exactos OSV + CVSS/CVRF NVD + CISA-KEV sobre el inventario | ingesta explícita | depende de la ingesta |

## 3. Limitaciones conocidas (honestidad ante todo)

- **Sin root**, no se puede leer `/etc/shadow` ni `/etc/sudoers` (contenidos) ni
  aplicar las sondas de firewall → esos controles degradan con `NOT_ASSESSED` o
  `WARNING` y así se muestran en la UI.
- **Contenedores**: se audita el `/etc` y `/proc` del contenedor. Para auditar
  el host real usa la instalación de sistema (ver `deploy/README.md`).
- **EDR distintos de ClamAV no se detectan** — FAIL significa «ClamAV ausente»,
  no «sin protección».
- **SELinux** fuera de alcance del adaptador actual (ecosistema AppArmor
  Debian/Ubuntu).
- **Adaptadores Windows/macOS**: los instaladores existen y la app funciona,
  pero el catálogo de controles `VC-WIN-*` / `VC-MAC-*` está en diseño (ver
  `docs/PLATFORM_COMPATIBILITY_MATRIX.md`).
- **SBOM y firma de artefactos**: en el roadmap (los checksums SHA256 ya cubren
  todos los artefactos del release).

## 4. Qué NO hace DIVISION T82

- No instala, corrige ni ejecuta remediaciones — Hardening Studio solo genera
  vistas previas (advisory-only) que tú revisas y aplicas a mano.
- No manda nada a la nube salvo: consultas OSV/NVD/KEV (solo paquete+versión)
  y el resumen agregado del asistente (sin hostname ni usuario).
- No corre como daemon de vigilancia continua: evalúa cuando tú lo pides.

## 5. Verificación

Cada commit pasa lint + build. El flujo E2E recomendado tras cambios de motor:

```bash
bun run lint
# arranque y evaluación manual desde la UI (Resumen → Iniciar evaluación)
```
