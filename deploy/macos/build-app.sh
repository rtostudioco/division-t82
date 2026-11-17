#!/usr/bin/env bash
# DIVISION T82 · Constructor macOS (.app + .dmg)
#
# Ejecutar EN macOS (Apple Silicon o Intel):
#   ./deploy/macos/build-app.sh
#
# Requisitos: Node.js >= 20 (brew install node), Xcode CLT (codesign/hdiutil).
#
# Qué produce:
#   dist/vulncheck-t82-<versión>-macos-<arch>.dmg
#     → DIVISION T82.app: servidor local en 127.0.0.1:3000,
#       datos en ~/Library/Application Support/VULNCHECK-T82,
#       abre el navegador al arrancar (doble clic = app portable).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(node -p 'require("./package.json").version')"
ARCH="$(uname -m)"                       # arm64 | x86_64
APP_NAME="vulncheck-t82"
OUT="$ROOT/dist"
STAGE="$OUT/macos-stage"
APPROOT="$STAGE/DIVISION T82.app"
NODE_VER="${NODE_VER:-22.14.0}"
DATA_HINT="$HOME/Library/Application Support/VULNCHECK-T82"

log() { printf '\033[1;36m[T82-mac]\033[0m %s\n' "$*"; }

# ─── [1/6] Compilar la app (standalone) ──────────────────────────────────────
log "[1/6] npm ci + prisma generate + next build (v$VERSION)…"
[ -d node_modules ] || npm ci --no-audit --no-fund
npx prisma generate
npx next build

# ─── [2/6] Esqueleto del .app ─────────────────────────────────────────────────
log "[2/6] Creando el bundle DIVISION T82.app…"
rm -rf "$STAGE"
mkdir -p "$APPROOT/Contents/MacOS" "$APPROOT/Contents/Resources"

cat > "$APPROOT/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>DIVISION T82</string>
  <key>CFBundleDisplayName</key><string>DIVISION T82</string>
  <key>CFBundleIdentifier</key><string>studio.rto.vulncheck-t82</string>
  <key>CFBundleExecutable</key><string>vulncheck-t82</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict>
</plist>
EOF

# ─── [3/6] Launcher + payload ─────────────────────────────────────────────────
log "[3/6] Launcher y payload de la app…"
cat > "$APPROOT/Contents/MacOS/vulncheck-t82" <<EOF
#!/bin/bash
# DIVISION T82 · launcher macOS
RES="\$(cd "\$(dirname "\$0")/../Resources" && pwd)"
DATA="\$HOME/Library/Application Support/VULNCHECK-T82"
mkdir -p "\$DATA"
export DATABASE_URL="file:\$DATA/vulncheck.db"
export PORT="\${PORT:-3000}"
export HOSTNAME="127.0.0.1"
export NODE_ENV="production"
LOG="\$DATA/server.log"
echo "[\$(date '+%F %T')] DIVISION T82 v$VERSION · http://127.0.0.1:\$PORT" >> "\$LOG"
"\$RES/prisma-cli/node_modules/prisma/build/index.js" db push --skip-generate >> "\$LOG" 2>&1 || true
( sleep 4; open "http://127.0.0.1:\$PORT" ) &
exec "\$RES/runtime/node" "\$RES/app/server.js" >> "\$LOG" 2>&1
EOF
chmod +x "$APPROOT/Contents/MacOS/vulncheck-t82"

RES="$APPROOT/Contents/Resources"
mkdir -p "$RES/app" "$RES/prisma" "$RES/runtime" "$RES/prisma-cli"
cp -R "$ROOT/.next/standalone/" "$RES/app/"
cp -R "$ROOT/.next/static" "$RES/app/.next/static"
[ -d "$ROOT/public" ] && cp -R "$ROOT/public" "$RES/app/public"
cp "$ROOT/prisma/schema.prisma" "$RES/prisma/"
cp "$ROOT/deploy/macos/com.vulncheck.t82.plist" "$RES/" 2>/dev/null || true

cat > "$RES/LEEME.txt" <<EOF
DIVISION T82 v$VERSION
By: Ramón Taboada Olivella - RTO Studio

· Doble clic en «DIVISION T82» → servidor en http://127.0.0.1:3000
  (se abre el navegador; log en: $DATA_HINT/server.log)
· Datos: $DATA_HINT/vulncheck.db (SQLite local, sin telemetría)
· Servicio de usuario (opcional):
    cp "$RES/com.vulncheck.t82.plist" ~/Library/LaunchAgents/
    launchctl bootstrap gui/\$(id -u) ~/Library/LaunchAgents/com.vulncheck.t82.plist
· Desinstalar: mover la .app a la papelera y
    launchctl bootout gui/\$(id -u)/studio.rto.vulncheck-t82 2>/dev/null; true
EOF

# ─── [4/6] Runtime Node para macOS ────────────────────────────────────────────
log "[4/6] Runtime Node v$NODE_VER ($ARCH)…"
NODE_TGZ="node-v${NODE_VER}-darwin-${ARCH}.tar.gz"
NODE_URL="https://nodejs.org/dist/v${NODE_VER}/${NODE_TGZ}"
if [ -n "${NODE_TARBALL:-}" ]; then cp "$NODE_TARBALL" "$OUT/$NODE_TGZ"; else
  curl -fsSL "$NODE_URL" -o "$OUT/$NODE_TGZ"
fi
tar -xzf "$OUT/$NODE_TGZ" -C "$OUT"
cp "$OUT/node-v${NODE_VER}-darwin-${ARCH}/bin/node" "$RES/runtime/node"
chmod +x "$RES/runtime/node"
rm -rf "$OUT/node-v${NODE_VER}-darwin-${ARCH}"

# ─── [5/6] CLI de Prisma + firma ad-hoc ──────────────────────────────────────
log "[5/6] CLI de Prisma y firma ad-hoc…"
PRISMA_DEP="$(node -p 'require("./package.json").dependencies.prisma')"
npm install --prefix "$RES/prisma-cli" --no-audit --no-fund --loglevel=error "prisma@${PRISMA_DEP#^}"
codesign --force --deep --sign - "$APPROOT" 2>/dev/null || log "Aviso: codesign no disponible (instalación dev)"

# ─── [6/6] .dmg ───────────────────────────────────────────────────────────────
DMG="$OUT/${APP_NAME}-${VERSION}-macos-${ARCH}.dmg"
log "[6/6] Creando $DMG…"
rm -f "$DMG"
hdiutil create -volname "DIVISION T82" -srcfolder "$STAGE" -ov -format UDZO "$DMG"

# Checksums (append idempotente)
cd "$OUT"
NEW_HASH="$(shasum -a 256 "${APP_NAME}-${VERSION}-macos-${ARCH}.dmg" | awk '{print $1}')"
if [ -f SHA256SUMS ]; then grep -v "${APP_NAME}-${VERSION}-macos-${ARCH}.dmg" SHA256SUMS > SHA256SUMS.tmp || true; mv SHA256SUMS.tmp SHA256SUMS; fi
echo "$NEW_HASH  ${APP_NAME}-${VERSION}-macos-${ARCH}.dmg" >> SHA256SUMS
rm -rf "$STAGE" "$OUT/$NODE_TGZ"

log "LISTO: dist/${APP_NAME}-${VERSION}-macos-${ARCH}.dmg"
log "Nota: sin firma de desarrollador, macOS pedirá clic derecho → Abrir (o: xattr -cr 'DIVISION T82.app')"
