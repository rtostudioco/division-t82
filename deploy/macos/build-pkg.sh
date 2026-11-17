#!/usr/bin/env bash
# DIVISION T82 · Constructor macOS (.pkg de sistema)
#
# Ejecutar EN macOS:
#   ./deploy/macos/build-pkg.sh
#
# Qué produce:
#   dist/vulncheck-t82-<versión>-macos-<arch>.pkg
#     · Instala en /opt/vulncheck-t82 (app + runtime Node + CLI Prisma)
#     · Datos en /var/lib/vulncheck-t82
#     · Servicio de sistema LaunchDaemon: com.vulncheck.t82 (127.0.0.1:3000)
#       Arranque al inicio + reinicio automático.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(node -p 'require("./package.json").version')"
ARCH="$(uname -m)"
APP_NAME="vulncheck-t82"
OUT="$ROOT/dist"
STAGE="$OUT/pkg-stage"
NODE_VER="${NODE_VER:-22.14.0}"

log() { printf '\033[1;36m[T82-pkg]\033[0m %s\n' "$*"; }

# ─── [1/4] Compilar la app ────────────────────────────────────────────────────
log "[1/4] npm ci + prisma generate + next build (v$VERSION)…"
[ -d node_modules ] || npm ci --no-audit --no-fund
npx prisma generate
npx next build

# ─── [2/4] Árbol de instalación /opt/vulncheck-t82 ────────────────────────────
log "[2/4] Preparando /opt/vulncheck-t82…"
PKGROOT="$STAGE/root"
mkdir -p "$PKGROOT/opt/$APP_NAME" "$STAGE/scripts"
cp -R "$ROOT/.next/standalone/" "$PKGROOT/opt/$APP_NAME/app/"
cp -R "$ROOT/.next/static" "$PKGROOT/opt/$APP_NAME/app/.next/static"
[ -d "$ROOT/public" ] && cp -R "$ROOT/public" "$PKGROOT/opt/$APP_NAME/app/public"
mkdir -p "$PKGROOT/opt/$APP_NAME/prisma"
cp "$ROOT/prisma/schema.prisma" "$PKGROOT/opt/$APP_NAME/prisma/"

# Runtime Node
NODE_TGZ="node-v${NODE_VER}-darwin-${ARCH}.tar.gz"
if [ -n "${NODE_TARBALL:-}" ]; then cp "$NODE_TARBALL" "$OUT/$NODE_TGZ"; else
  curl -fsSL "https://nodejs.org/dist/v${NODE_VER}/${NODE_TGZ}" -o "$OUT/$NODE_TGZ"
fi
tar -xzf "$OUT/$NODE_TGZ" -C "$OUT"
cp "$OUT/node-v${NODE_VER}-darwin-${ARCH}/bin/node" "$PKGROOT/opt/$APP_NAME/node"
chmod +x "$PKGROOT/opt/$APP_NAME/node"

# CLI de Prisma (db push sin npm en destino)
PRISMA_DEP="$(node -p 'require("./package.json").dependencies.prisma')"
npm install --prefix "$PKGROOT/opt/$APP_NAME/prisma-cli" --no-audit --no-fund --loglevel=error "prisma@${PRISMA_DEP#^}"

cat > "$PKGROOT/opt/$APP_NAME/start.sh" <<'EOF'
#!/bin/sh
# DIVISION T82 — arranque del servicio (lo lanza el LaunchDaemon)
cd "$(dirname "$0")"
export DATABASE_URL="file:/var/lib/vulncheck-t82/vulncheck.db"
export PORT="${PORT:-3000}"
export HOSTNAME="127.0.0.1"
export NODE_ENV="production"
exec ./node app/server.js
EOF
chmod +x "$PKGROOT/opt/$APP_NAME/start.sh"

# ─── [3/4] Scripts del paquete ────────────────────────────────────────────────
log "[3/4] Scripts postinstall (datos + LaunchDaemon)…"
cat > "$STAGE/scripts/postinstall" <<'EOF'
#!/bin/bash
set -e
APP=/opt/vulncheck-t82
DATA=/var/lib/vulncheck-t82
PLIST=/Library/LaunchDaemons/com.vulncheck.t82.plist

mkdir -p "$DATA"
chown root:wheel "$DATA"

# Esquema de BD (idempotente)
"$APP/node" "$APP/prisma-cli/node_modules/prisma/build/index.js" db push \
  --skip-generate --schema "$APP/prisma/schema.prisma" \
  || echo "AVISO: db push falló; revisa /var/log/vulncheck-t82-install.log"

# LaunchDaemon de sistema
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.vulncheck.t82</string>
  <key>ProgramArguments</key>
  <array>
    <string>$APP/start.sh</string>
  </array>
  <key>WorkingDirectory</key><string>$APP</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>DATABASE_URL</key><string>file:$DATA/vulncheck.db</string>
    <key>PORT</key><string>3000</string>
    <key>HOSTNAME</key><string>127.0.0.1</string>
    <key>NODE_ENV</key><string>production</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$DATA/server.log</string>
  <key>StandardErrorPath</key><string>$DATA/server.log</string>
</dict>
</plist>
PLISTEOF

launchctl bootout system/com.vulncheck.t82 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable system/com.vulncheck.t82

echo ""
echo "DIVISION T82 instalado (By: Ramón Taboada Olivella - RTO Studio)."
echo "Web: http://127.0.0.1:3000 · Logs: $DATA/server.log"
echo "Parar/arrancar: sudo launchctl bootout system/com.vulncheck.t82 | bootstrap system $PLIST"
EOF
chmod +x "$STAGE/scripts/postinstall"

# ─── [4/4] Construir el .pkg ──────────────────────────────────────────────────
PKG="$OUT/${APP_NAME}-${VERSION}-macos-${ARCH}.pkg"
log "[4/4] pkgbuild → $PKG"
pkgbuild --identifier "studio.rto.vulncheck-t82" \
         --version "$VERSION" \
         --root "$PKGROOT" \
         --scripts "$STAGE/scripts" \
         "$PKG"

cd "$OUT"
NEW_HASH="$(shasum -a 256 "${APP_NAME}-${VERSION}-macos-${ARCH}.pkg" | awk '{print $1}')"
if [ -f SHA256SUMS ]; then grep -v "${APP_NAME}-${VERSION}-macos-${ARCH}.pkg" SHA256SUMS > SHA256SUMS.tmp || true; mv SHA256SUMS.tmp SHA256SUMS; fi
echo "$NEW_HASH  ${APP_NAME}-${VERSION}-macos-${ARCH}.pkg" >> SHA256SUMS
rm -rf "$STAGE" "$OUT/$NODE_TGZ"

log "LISTO: dist/${APP_NAME}-${VERSION}-macos-${ARCH}.pkg"
log "Instalación destino: sudo installer -pkg $PKG -target /"
