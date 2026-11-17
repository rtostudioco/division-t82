# DIVISION T82 — Shell de escritorio Tauri 2 (instaladores "doble clic")

Autoría: **By: Ramón Taboada Olivella - RTO Studio**

Esta carpeta es el **scaffold Tauri 2** que envuelve el servidor Next.js standalone
como *sidecar*: una ventana webview nativa apunta a `http://127.0.0.1:<puerto>`
y al cerrarla se detiene el servidor. Con UNA base de código obtienes los
instaladores de las tres plataformas:

| Plataforma | `tauri build` produce | Comando |
|---|---|---|
| Windows 10/11 | `.msi` (WiX) + `.exe` (NSIS) | `cargo tauri build --bundles msi,nsis` |
| macOS 12+ | `.dmg` + `.app` | `cargo tauri build --bundles dmg` |
| Linux | `.deb` + `.rpm` + `.AppImage` | `cargo tauri build --bundles deb,rpm,appimage` |

> Cada instalador se compila EN su plataforma (Tauri no hace cross-compile de
> bundles). Usa el workflow `.github/workflows/build-installers.yml`, que ejecuta
> la matriz `windows-latest / macos-latest / ubuntu-latest` y publica todo.

## Preparar el payload (una vez, en cualquier SO con Node 20+)

```bash
# desde la raíz del repositorio
npm ci && npx prisma generate && npx next build
mkdir -p deploy/tauri/payload/vulncheck-t82
cp -R .next/standalone/ deploy/tauri/payload/vulncheck-t82/app/
cp -R .next/static deploy/tauri/payload/vulncheck-t82/app/.next/static
cp -R public deploy/tauri/payload/vulncheck-t82/app/public
mkdir -p deploy/tauri/payload/vulncheck-t82/prisma
cp prisma/schema.prisma deploy/tauri/payload/vulncheck-t82/prisma/
npm install --prefix deploy/tauri/payload/vulncheck-t82/tools/prisma-cli prisma
```

## Sidecar `node-runtime`

Tauri exige binarios nombrados por triple de destino en `src-tauri/binaries/`:

```
binaries/node-runtime-x86_64-pc-windows-msvc.exe   ← node.exe de node-vX-win-x64.zip
binaries/node-runtime-x86_64-apple-darwin          ← bin/node de node-vX-darwin-arm64/x86_64
binaries/node-runtime-aarch64-apple-darwin
binaries/node-runtime-x86_64-unknown-linux-gnu
```

En CI esto lo hace el workflow automáticamente. Local, descarga el zip/tarball
de https://nodejs.org/dist, extrae `node(.exe)` y renómbralo como arriba
(`chmod +x` en UNIX).

## Compilar

```bash
cd deploy/tauri
cargo install tauri-cli --version '^2'
cargo tauri build          # sobre este SO: todos los bundles disponibles
# o por bundle: cargo tauri build --bundles msi
```

Requisitos por plataforma: Rust 1.77+ · Windows: WebView2 (auto) + MSVC Build
Tools · macOS: Xcode CLT · Linux: libwebkit2gtk-4.1-dev, libgtk-3-dev.

## Notas de diseño

- `tauri.conf.json`: `resources` copia `app/` (standalone + static + public),
  `prisma/` y `tools/prisma-cli/` dentro del bundle; `externalBin` declara el
  runtime Node como sidecar.
- `src/main.rs`: hace `prisma db push` (idempotente), arranca `server.js` con
  `DATABASE_URL` en el directorio de datos local de la app, espera el puerto
  (45 s) y abre la webview. Mantiene el child vivo y lo mata al destruirse.
- Iconos: coloca `icons/icon.png|.ico|.icns` (32px mínimo 512px) — sin ellos
  `tauri build` falla en el paso de bundling.
- Esta ruta es OPCIONAL: los instaladores "de sistema" nativos (NSIS/WinSW para
  Windows, `.dmg`/`.pkg` para macOS) viven en `deploy/windows` y `deploy/macos`
  sin dependencia de Rust. Tauri añade ventana propia, firma y auto-update
  (`tauri-plugin-updater`).
