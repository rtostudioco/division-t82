#!/usr/bin/env bash
# DIVISION T82 — empaqueta el build standalone de Next.js en un tar.gz portable.
#
#   ./deploy/scripts/build-standalone.sh
#
# Resultado: dist/vulncheck-t82-<version>-<arch>.tar.gz
# Contenido: server.js + .next/static + public + prisma + scripts de arranque.
# Requiere: bun (o node+npm) instalado. Ejecutar en la máquina de build.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(grep -o '"version": *"[^"]*"' package.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
ARCH="$(uname -m)"          # x86_64 | aarch64
OUT_DIR="$ROOT/dist"
STAGE="$OUT_DIR/vulncheck-t82"

mkdir -p "$OUT_DIR" "$STAGE"

echo "[1/5] Empujando esquema a la BD local de build…"
bun run db:push || npm run db:push

echo "[2/5] Compilando (next build, salida standalone)…"
bun run build || npm run build

echo "[3/5] Preparando el paquete…"
cp -r .next/standalone/* "$STAGE"/
mkdir -p "$STAGE/.next/static" "$STAGE/public" "$STAGE/prisma" "$STAGE/data"
cp -r .next/static/* "$STAGE/.next/static"/ 2>/dev/null || true
cp -r public/* "$STAGE/public"/ 2>/dev/null || true
cp -r prisma/* "$STAGE/prisma"/
cp deploy/vulncheck-t82.service "$STAGE"/
cp deploy/README.md "$STAGE/DEPLOY.md"

cat > "$STAGE/start.sh" <<'EOF'
#!/bin/sh
# DIVISION T82 — arranque portable.
# Uso: DATABASE_URL=file:$(pwd)/data/vulncheck.db PORT=3000 ./start.sh
set -e
cd "$(dirname "$0")"
export DATABASE_URL="${DATABASE_URL:-file:$(pwd)/data/vulncheck.db}"
export PORT="${PORT:-3000}"
export HOSTNAME="${HOSTNAME:-127.0.0.1}"
export NODE_ENV=production
mkdir -p "$(dirname "${DATABASE_URL#file:}")"
# Sin --accept-data-loss ni silencio (C3): un fallo de esquema detiene el
# arranque con error visible; los datos nunca se pierden en silencio.
npx --yes prisma@6 db push --skip-generate || {
  echo "ERROR: prisma db push falló — los datos NO se han modificado; revisa el esquema."
  exit 1
}
exec node server.js
EOF
chmod +x "$STAGE/start.sh"

echo "[4/5] Comprimiendo…"
TARBALL="$OUT_DIR/vulncheck-t82-${VERSION}-${ARCH}.tar.gz"
tar -czf "$TARBALL" -C "$OUT_DIR" vulncheck-t82

echo "[5/5] Limpieza del staging…"
rm -rf "$STAGE"

echo ""
echo "✔ Paquete listo: $TARBALL"
echo "  Instalación destino:"
echo "    tar -xzf vulncheck-t82-*.tar.gz && cd vulncheck-t82"
echo "    ./start.sh          # arranque directo"
echo "    # o con systemd: ver vulncheck-t82.service y DEPLOY.md"
