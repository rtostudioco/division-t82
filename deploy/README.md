# DIVISION T82 · Guía de instaladores y despliegue

Autoría: **By: Ramón Taboada Olivella - RTO Studio**

Esta guía cubre las rutas de empaquetado, de la más rápida a la más completa.
Todas parten del build **standalone** de Next.js (`output: "standalone"` ya
configurado), que produce un `server.js` autocontenido sin `node_modules`.

---

## Matriz de instaladores por plataforma

| SO | Instalador | Modelo | Cómo se genera |
|---|---|---|---|
| Linux (Debian/Ubuntu) | `.deb` | fuente, compila en destino | `deploy/scripts/make-release.sh` (o el botón de la UI) |
| Linux / macOS (portable) | `.tar.gz` | fuente, compila en destino | `deploy/scripts/make-release.sh` (o el botón de la UI) |
| Windows 10/11 x64 | `vulncheck-t82-<v>-win64-setup.exe` | build compilado + servicio | `deploy/windows/build-installer.ps1` (en Windows) o CI |
| macOS (portable) | `vulncheck-t82-<v>-macos-<arch>.dmg` | build compilado, .app | `deploy/macos/build-app.sh` (en macOS) o CI |
| macOS (sistema) | `vulncheck-t82-<v>-macos-<arch>.pkg` | build compilado + LaunchDaemon | `deploy/macos/build-pkg.sh` (en macOS) o CI |
| Todas (opcional) | shell de escritorio | Tauri 2 | `deploy/tauri` + `.github/workflows/build-installers.yml` |

Los tres se generan de golpe por CI: `git tag v<versión> && git push --tags`
(workflow `build-installers.yml`: ubuntu + windows + macos y release con todos
los artefactos). Lo que aparezca en `dist/` lo sirve el Centro de descargas.

---

## Ruta 0 — Centro de descargas integrado (la forma directa)

La propia app genera y sirve los instaladores. En la UI:
**Informes → Centro de descargas → «Generar instaladores» → Descargar**.

- Empaqueta el árbol fuente + `install.sh` en:
  - `dist/vulncheck-t82-<versión>-source-<arch>.tar.gz` (portable)
  - `dist/vulncheck-t82_<versión>_all.deb` (Debian/Ubuntu, `Architecture: all`)
  - `dist/SHA256SUMS` (verificación de integridad)
- Los artefactos NO contienen binarios compilados: el build ocurre en la
  máquina destino durante la instalación (`npm install + next build`, 2–4 min).
  A cambio son agnósticos de plataforma y nunca caducan por versión de Node
  de la máquina de build.
- Instalación destino: `sudo ./install.sh` (sistema, `/opt` + systemd) o
  `./install.sh --no-service` (portable sin root). Ver `README-INSTALL.md` incluido.

API equivalente: `GET/POST /api/download` (catálogo y generación) y
`GET /api/download/file?name=…` (descarga con allow-list estricto).

---

## Ruta 1 — Portable (tar.gz): cualquier Linux/macOS con Node 20+

```bash
./deploy/scripts/build-standalone.sh
# → dist/vulncheck-t82-<version>-<arch>.tar.gz
```

En la máquina destino (no necesita git, solo Node ≥ 20 y acceso a la red la
primera vez para el push de Prisma vía npx):

```bash
tar -xzf vulncheck-t82-*.tar.gz && cd vulncheck-t82
./start.sh                 # sirve en http://localhost:3000
```

Variables útiles: `PORT=8080 ./start.sh`, `DATABASE_URL=file:/ruta/datos.db`.

---

## Ruta 2 — Servicio systemd (Linux de servidor)

1. Genera el paquete portable (Ruta 1) y descomprímelo en `/opt/vulncheck-t82`.
2. Ajusta usuario/rutas en `deploy/vulncheck-t82.service` (`User=`,
   `WorkingDirectory=`, `DATABASE_URL=`).
3. Instala el servicio:

```bash
sudo cp deploy/vulncheck-t82.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vulncheck-t82
journalctl -u vulncheck-t82 -f        # logs
```

El unit incluye endurecimiento básico (`ProtectSystem=strict`,
`NoNewPrivileges`, `PrivateTmp`): solo puede escribir en el directorio de la BD.

---

## Ruta 3 — Paquete .deb (Debian/Ubuntu)

```bash
./deploy/scripts/make-deb.sh
# → dist/vulncheck-t82_<version>_<arch>.deb
```

```bash
sudo dpkg -i dist/vulncheck-t82_*.deb
sudo systemctl start vulncheck-t82     # enable ya queda hecho por postinst
```

Qué instala:
- `/opt/vulncheck-t82` — app standalone + `start.sh`
- `/var/lib/vulncheck-t82` — base de datos SQLite persistente
- servicio systemd habilitado, usuario de sistema `t82`

Para RPM, análogo con `fpm -s dir -t rpm` sobre el mismo árbol.

---

## Ruta 4 — Docker / Compose

```bash
docker compose -f deploy/docker-compose.yml up -d --build
# web: http://localhost:3000 · datos en volumen vulncheck-data:/data
```

La imagen es multi-stage (builder → runtime alpine), con healthcheck sobre
`/api/engine/status` y entrypoint que aplica el esquema Prisma al primer
arranque.

> Nota honesta: la plataforma audita el sistema de archivos que ve el proceso.
> En un contenedor lee el `/etc` y `/proc` del contenedor. Para auditar el
> host real, la opción de largo plazo es desplegar vía systemd/Ruta 2 sobre el
> propio host, o montar `/etc` y `/proc` de solo lectura y adaptar los
> collectors (el compose lo documenta).

---

## Ruta 5 — Shell de escritorio unificada (Tauri 2)

Scaffold completo en `deploy/tauri/` (ver su README): lanza el servidor standalone
como sidecar de Node y abre una webview nativa a `http://127.0.0.1:<puerto>`.
Con un solo código fuente produce los instaladores "doble clic" de las tres
plataformas (`.msi`/`.exe` en Windows, `.dmg` en macOS, `.deb`/`.rpm`/`.AppImage`
en Linux), con firma, icono y auto-update opcional (`tauri-plugin-updater`).

```bash
cd deploy/tauri && cargo tauri build      # por plataforma, en su propio SO
# o deja que el CI lo haga: .github/workflows/build-installers.yml
```

---

## Ruta 6 — Instaladores nativos por plataforma (Windows y macOS)

Los instaladores **nativos** llevan el build ya compilado (instalación rápida,
sin npm en destino). Se construyen EN su plataforma — o por CI, que es la vía
recomendada:

### Windows 10/11 · `vulncheck-t82-<v>-win64-setup.exe` (NSIS 3 + WinSW)

```powershell
# en Windows (requiere Node 20+ y NSIS 3: winget install NSIS.NSIS)
./deploy/windows/build-installer.ps1            # → dist/vulncheck-t82-<v>-win64-setup.exe
```

Qué hace el instalador:
- Copia la app a `%PROGRAMFILES64%\DIVISION T82` con runtime Node incluido.
- Datos SQLite en `%ProgramData%\VULNCHECK-T82` (ACL para usuarios, logs incluidos).
- Registra el servicio Windows **VulncheckT82** (WinSW, arranque automático y
  reinicio en fallo) y aplica `prisma db push` en cada arranque (prestart).
- Escucha en `127.0.0.1:3000` (postura local-first; sin reglas de firewall).
- Desinstalador (Panel de control) que conserva la base de datos.
- Modo portable: `start-vulncheck.bat` en el Menú de inicio.

### macOS · `.dmg` portable y `.pkg` de sistema

```bash
# en macOS (requiere Node 20+ y Xcode CLT)
./deploy/macos/build-app.sh    # → dist/vulncheck-t82-<v>-macos-<arch>.dmg  (.app portable)
./deploy/macos/build-pkg.sh    # → dist/vulncheck-t82-<v>-macos-<arch>.pkg  (sistema)
```

- `.dmg`: doble clic en la .app → servidor en `127.0.0.1:3000`, datos en
  `~/Library/Application Support/VULNCHECK-T82`, abre el navegador. Sin firma
  de desarrollador, macOS pide clic derecho → Abrir (o `xattr -cr 'DIVISION T82.app'`).
- `.pkg`: instala en `/opt/vulncheck-t82`, datos en `/var/lib/vulncheck-t82` y
  LaunchDaemon de sistema `com.vulncheck.t82` (arranque al inicio, KeepAlive).

### CI (recomendado para tener los tres a la vez)

```bash
git tag v0.2.1 && git push --tags
# → Actions construye Linux/Windows/macOS y crea un Release con los instaladores
```

---

## Qué hace cada pieza al arrancar

| Pieza | Comportamiento |
|---|---|
| `prisma db push` | Aplica el esquema a `DATABASE_URL` (idempotente). |
| `node server.js` | Sirve la app standalone en `PORT` (por defecto 3000). |
| `instrumentation.ts` | Arranca el scheduler de ingesta OSV/NVD/KEV (si está activado en la UI). |
| Datos | Todo en SQLite local: sin telemetría, sin servicios externos salvo las fuentes de inteligencia cuando tú lo pides. |

## Nota sobre el Asistente T82 (IA interna)

El asistente usa el SDK incluido (`z-ai-web-dev-sdk`) **en el backend**. En este
entorno sandbox funciona sin configuración adicional; al desplegar fuera,
comprueba los requisitos del SDK en tu máquina (variables/credenciales que el
SDK espere). Si el modelo no está disponible, el chat devuelve un error 502
honrado — el resto de la plataforma funciona igual.
