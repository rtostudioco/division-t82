#!/usr/bin/env bash
# DIVISION T82 · Generador de instaladores distributibles.
#
#   ./deploy/scripts/make-release.sh
#
# Genera en dist/:
#   vulncheck-t82-<versión>-source-<arch>.tar.gz   — release portable (código fuente)
#   vulncheck-t82_<versión>_all.deb                — paquete Debian/Ubuntu (fuente)
#   SHA256SUMS                                     — checksums de verificación
#
# Modelo de distribución: los artefactos llevan el CÓDIGO FUENTE y el instalador
# (install.sh). La compilación (npm install + next build) ocurre EN LA MÁQUINA
# DESTINO durante la instalación — así el artefacto es agnóstico de plataforma
# y no exige construir en una máquina de build concreta.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(node -p 'require("./package.json").version' 2>/dev/null \
  || grep -o '"version": *"[^"]*"' package.json | head -1 | sed 's/.*"\([^"]*\)"$/\1/')"
ARCH="$(uname -m)"                    # x86_64 | aarch64 | …
OUT="$ROOT/dist"
STAGE="$OUT/stage-src"
APP_NAME="vulncheck-t82"

log() { printf '\033[1;36m[release]\033[0m %s\n' "$*"; }

rm -rf "$STAGE"
mkdir -p "$STAGE/$APP_NAME"

# ─── [1/6] Staging del árbol fuente ──────────────────────────────────────────
log "[1/6] Preparando el árbol fuente (v$VERSION)…"
cp -r src prisma public deploy "$STAGE/$APP_NAME"/
for f in package.json bun.lock next.config.ts tsconfig.json tailwind.config.ts \
         postcss.config.mjs components.json eslint.config.mjs; do
  [ -f "$ROOT/$f" ] && cp "$ROOT/$f" "$STAGE/$APP_NAME/"
done
# Directorios de datos vacíos (la BD real nunca viaja en el artefacto):
mkdir -p "$STAGE/$APP_NAME/data" "$STAGE/$APP_NAME/db"
touch "$STAGE/$APP_NAME/data/.gitkeep" "$STAGE/$APP_NAME/db/.gitkeep"

cat > "$STAGE/$APP_NAME/.env.example" <<'EOF'
# DIVISION T82 — configuración mínima (SQLite local, sin telemetría).
# Ruta relativa al directorio de la app o absoluta con file:/ruta/absoluta.db
DATABASE_URL=file:./db/vulncheck.db
EOF

# ─── [2/6] start.sh portable + install.sh en la raíz ─────────────────────────
log "[2/6] Escribiendo start.sh portable y copiando install.sh a la raíz…"
cp "$ROOT/deploy/install.sh" "$STAGE/$APP_NAME/install.sh"
chmod +x "$STAGE/$APP_NAME/install.sh"
cat > "$STAGE/$APP_NAME/start.sh" <<'EOF'
#!/bin/sh
# DIVISION T82 — arranque portable (tras compilar con ./install.sh).
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
if [ ! -f .next/standalone/server.js ]; then
  echo "Falta el build de producción. Ejecuta antes:  ./install.sh install"
  exit 1
fi
exec node .next/standalone/server.js
EOF
chmod +x "$STAGE/$APP_NAME/start.sh"

# ─── [3/6] README de instalación rápida ──────────────────────────────────────
log "[3/6] Escribiendo README-INSTALL.md…"
cat > "$STAGE/$APP_NAME/README-INSTALL.md" <<'EOF'
# DIVISION T82 · Instalación rápida

Plataforma local-first de auditoría de postura de seguridad (solo lectura,
evidencia trazable, puntuación explicable). Autoría: **By: Ramón Taboada Olivella - RTO Studio**.

## Requisitos
- Linux (Debian/Ubuntu recomendado) o macOS · Node.js >= 20.9 (o bun >= 1.2) · npm
- Red la primera vez (dependencias npm + motores Prisma)
- La compilación ocurre en esta máquina durante la instalación (2–4 min)

## Instalación de sistema (recomendada en servidores Linux)
```bash
sudo ./install.sh --install-node   # con --install-node si falta Node 20+
# → /opt/vulncheck-t82 + servicio systemd activo en http://localhost:3000
```
Gestión: `systemctl status vulncheck-t82` · logs `journalctl -u vulncheck-t82 -f`

## Instalación portable (sin root, sin systemd)
```bash
./install.sh --no-service          # compila en este directorio
./start.sh                         # http://localhost:3000
```

## Comandos
| Acción | Comando |
|---|---|
| Reinstalar/recompilar (conserva BD) | `sudo ./install.sh update` |
| Desinstalar (conserva la BD) | `sudo ./install.sh uninstall` |
| Puerto/datos personalizados | `sudo ./install.sh --port 8080 --data-dir /srv/t82` |

## Notas
- Los datos viven en SQLite local (`/var/lib/vulncheck-t82` en modo sistema,
  `./data` en modo portable). Sin telemetría; sin servicios externos salvo las
  fuentes OSV/NVD/CISA-KEV cuando se activa la ingesta desde la UI.
- La plataforma audita el sistema de archivos que ve el proceso. En contenedores
  lee el `/etc` y `/proc` del contenedor, no el del host — para auditar el host
  real usa la instalación de sistema (ver `deploy/README.md` para Docker y más rutas).
- El Asistente T82 (IA interna) requiere las credenciales del SDK en el entorno;
  sin ellas devuelve un error honesto y el resto de la plataforma funciona igual.
EOF

# ─── [4/6] Tarball fuente ────────────────────────────────────────────────────
TARBALL="$OUT/${APP_NAME}-${VERSION}-source-${ARCH}.tar.gz"
log "[4/6] Empaquetando $TARBALL…"
tar -czf "$TARBALL" -C "$STAGE" "$APP_NAME"

# ─── [5/6] .deb (Architecture: all — compila al instalar) ────────────────────
log "[5/6] Construyendo el .deb (fuente, compila al instalar)…"
DEB_DIR="$OUT/deb-root/${APP_NAME}_${VERSION}_all"
rm -rf "$OUT/deb-root"
mkdir -p "$DEB_DIR/opt/${APP_NAME}" "$DEB_DIR/var/lib/${APP_NAME}" "$DEB_DIR/DEBIAN"
cp -a "$STAGE/$APP_NAME"/. "$DEB_DIR/opt/${APP_NAME}/"

cat > "$DEB_DIR/DEBIAN/control" <<EOF
Package: ${APP_NAME}
Version: ${VERSION}
Architecture: all
Maintainer: Ramón Taboada Olivella <RTO Studio>
Depends: nodejs (>= 20) | bun, npm
Recommends: systemd, curl
Description: DIVISION T82 - auditoria local-first de postura de seguridad (RTO Studio)
 Plataforma local-first de auditoría de postura de seguridad:
 evaluación read-only con evidencia trazable, puntuación explicable,
 inteligencia OSV/NVD/CISA-KEV y asistente IA interno.
 Instala en /opt/vulncheck-t82, datos en /var/lib/vulncheck-t82,
 servicio systemd vulncheck-t82 en el puerto 3000.
 La compilación se ejecuta durante la instalación (Node.js >= 20 requerido).
EOF

cat > "$DEB_DIR/DEBIAN/postinst" <<'EOF'
#!/bin/sh
# postinst vulncheck-t82 (paquete fuente): compila en destino y registra el servicio.
set -e
APP=/opt/vulncheck-t82
DATA=/var/lib/vulncheck-t82

if ! id t82 >/dev/null 2>&1; then
  adduser --system --group --no-create-home --home "$APP" t82 || true
fi
mkdir -p "$DATA"
chown -R t82:t82 "$DATA"

if ! command -v node >/dev/null 2>&1; then
  echo "AVISO: falta Node.js >= 20. Instálalo y ejecuta:  cd $APP && sudo ./install.sh update"
  exit 0   # no romper dpkg: la compilación puede reintentarse manualmente
fi

LOG=/var/log/${APP}-install.log
echo "Compilando vulncheck-t82 (esto tarda 2-4 min; log: $LOG)…"
if sh -c "cd $APP && ./install.sh build --data-dir $DATA" >"$LOG" 2>&1; then
  chown -R t82:t82 "$APP"
  if command -v systemctl >/dev/null 2>&1; then
    cd "$APP" && ./install.sh install-service >/dev/null 2>&1 || true
  fi
  echo "vulncheck-t82 instalado."
  echo "Web: http://localhost:3000  ·  Logs del servicio: journalctl -u vulncheck-t82 -f"
  echo "Si el servicio no arrancó:  sudo systemctl start vulncheck-t82"
else
  echo "AVISO: la compilación falló (ver $LOG)."
  echo "Reintenta cuando corrijas los requisitos:  cd $APP && sudo ./install.sh update"
fi
EOF
chmod +x "$DEB_DIR/DEBIAN/postinst" "$DEB_DIR/opt/${APP_NAME}/install.sh" \
         "$DEB_DIR/opt/${APP_NAME}/start.sh"

DEB_OUT="$OUT/${APP_NAME}_${VERSION}_all.deb"
dpkg-deb --build --root-owner-group "$DEB_DIR" "$DEB_OUT" >/dev/null
rm -rf "$OUT/deb-root"

# ─── [6/6] Checksums + limpieza ──────────────────────────────────────────────
log "[6/6] Generando SHA256SUMS…"
cd "$OUT"
sha256sum "${APP_NAME}-${VERSION}-source-${ARCH}.tar.gz" "${APP_NAME}_${VERSION}_all.deb" > SHA256SUMS
rm -rf "$STAGE"

echo ""
log "Artefactos listos en dist/:"
ls -lh "${APP_NAME}-${VERSION}-source-${ARCH}.tar.gz" "${APP_NAME}_${VERSION}_all.deb" SHA256SUMS
echo ""
echo "  Instalación destino (tarball):  tar -xzf ${APP_NAME}-*.tar.gz && cd ${APP_NAME} && sudo ./install.sh"
echo "  Instalación destino (.deb):     sudo dpkg -i ${APP_NAME}_${VERSION}_all.deb"
