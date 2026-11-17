#!/usr/bin/env bash
# DIVISION T82 — genera un .deb instalable a partir del build standalone.
#
#   ./deploy/scripts/make-deb.sh
#
# Resultado: dist/vulncheck-t82_<version>_<arch>.deb
# Instala en:
#   /opt/vulncheck-t82           — app standalone + start.sh
#   /var/lib/vulncheck-t82       — base de datos SQLite (persistente)
#   /etc/systemd/system/vulncheck-t82.service — servicio systemd
#
# Uso tras instalar:  sudo systemctl enable --now vulncheck-t82
# Web:                http://localhost:3000
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(grep -o '"version": *"[^"]*"' package.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"   # amd64 | arm64
DEB_DIR="$ROOT/dist/deb-root/vulncheck-t82_${VERSION}_${ARCH}"
OUT="$ROOT/dist/vulncheck-t82_${VERSION}_${ARCH}.deb"

echo "[1/3] Compilando paquete standalone…"
"$ROOT/deploy/scripts/build-standalone.sh"

echo "[2/3] Construyendo árbol del .deb…"
rm -rf "$ROOT/dist/deb-root"
mkdir -p \
  "$DEB_DIR/opt/vulncheck-t82" \
  "$DEB_DIR/var/lib/vulncheck-t82" \
  "$DEB_DIR/DEBIAN"

tar -xzf "$ROOT/dist/vulncheck-t82-${VERSION}-$(uname -m).tar.gz" \
    -C "$DEB_DIR/opt/vulncheck-t82" --strip-components=1

cp deploy/vulncheck-t82.service "$DEB_DIR/opt/vulncheck-t82/"
cp deploy/scripts/postinst "$DEB_DIR/DEBIAN/postinst"
chmod +x "$DEB_DIR/DEBIAN/postinst" "$DEB_DIR/opt/vulncheck-t82/start.sh"

# Dependencias: nodejs >= 20 (runtime) y prisma CLI se resuelve vía npx al arrancar.
cat > "$DEB_DIR/DEBIAN/control" <<EOF
Package: vulncheck-t82
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Ramón Taboada Olivella <RTO Studio>
Depends: nodejs (>= 20) | bun
Recommends: systemd
Description: DIVISION T82 - auditoria local-first de postura de seguridad (RTO Studio)
 Plataforma local-first de auditoría de postura de seguridad:
 evaluación read-only con evidencia trazable, puntuación explicable,
 inteligencia de vulnerabilidades OSV/NVD/CISA-KEV y asistente IA interno.
 Servida en el puerto 3000 (systemd: vulncheck-t82).
EOF

echo "[3/3] Generando $OUT…"
dpkg-deb --build --root-owner-group "$DEB_DIR" "$OUT"
rm -rf "$ROOT/dist/deb-root"

echo ""
echo "✔ Instalador listo: $OUT"
echo "  sudo dpkg -i vulncheck-t82_${VERSION}_${ARCH}.deb"
echo "  sudo systemctl enable --now vulncheck-t82"
