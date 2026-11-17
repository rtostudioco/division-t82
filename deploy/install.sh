#!/usr/bin/env bash
# DIVISION T82 · Instalador en la máquina destino.
#
# Uso:
#   sudo ./install.sh                      # instalación de sistema (/opt + systemd)
#   sudo ./install.sh update               # recompila y reinicia (conserva la BD)
#   sudo ./install.sh uninstall            # detiene, deshabilita y elimina /opt (conserva la BD)
#   ./install.sh --no-service              # instalación portable en el directorio actual
#
# Opciones:
#   --port N            puerto del servidor (defecto 3000)
#   --data-dir RUTA     directorio de la base SQLite (defecto /var/lib/vulncheck-t82)
#   --install-node      instala Node.js 22 LTS vía NodeSource (solo Debian/Ubuntu + root)
#   --no-service        no crea el servicio systemd (portable)
#
# Requisitos: Node.js >= 20.9 (o bun >= 1.2), npm, acceso a red la primera vez
# (dependencias npm + motores Prisma). La compilación ocurre EN ESTA MÁQUINA.
set -euo pipefail

APP="vulncheck-t82"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="${1:-install}"

PORT=3000
DATA_DIR=""
NO_SERVICE=0
INSTALL_NODE=0
APP_DIR="/opt/${APP}"
SYS_USER="t82"

# ─── Parseo de opciones ──────────────────────────────────────────────────────
shift_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --port)        PORT="$2"; shift 2 ;;
    --data-dir)    DATA_DIR="$2"; shift 2 ;;
    --no-service)  NO_SERVICE=1; shift ;;
    --install-node) INSTALL_NODE=1; shift ;;
    install|update|uninstall|build|install-service) shift_args+=("$1"); shift ;;
    *) echo "Opción desconocida: $1"; exit 1 ;;
  esac
done
[ ${#shift_args[@]} -gt 0 ] && MODE="${shift_args[0]}"

IS_ROOT=0
[ "$(id -u)" = "0" ] && IS_ROOT=1

log()  { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[aviso]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

# ─── Node.js / bun ───────────────────────────────────────────────────────────
node_ok() {
  command -v node >/dev/null 2>&1 || return 1
  local major; major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [ "${major:-0}" -ge 20 ]
}

ensure_runtime() {
  if node_ok || command -v bun >/dev/null 2>&1; then
    node_ok && log "Node.js $(node --version) detectado." || log "bun detectado: $(bun --version)."
    return 0
  fi
  if [ "$INSTALL_NODE" = "1" ]; then
    [ "$IS_ROOT" = "1" ] || die "--install-node requiere root."
    log "Instalando Node.js 22 LTS (NodeSource)…"
    command -v curl >/dev/null 2>&1 || apt-get update && apt-get install -y curl ca-certificates
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
    node_ok || die "La instalación de Node.js falló."
  else
    die "Falta Node.js >= 20.9 (o bun). Instálalo y reintenta, o usa: sudo ./install.sh --install-node"
  fi
}

# ─── Compilación en el destino ───────────────────────────────────────────────
do_build() {
  local dir="$1"
  cd "$dir"
  export DATABASE_URL="file:${DATA_DIR}/vulncheck.db"
  export NEXT_TELEMETRY_DISABLED=1
  mkdir -p "$DATA_DIR"
  log "Instalando dependencias…"
  if command -v bun >/dev/null 2>&1; then
    bun install --frozen-lockfile || npm install --no-audit --no-fund
  else
    npm install --no-audit --no-fund
  fi
  log "Generando cliente Prisma…"
  npx prisma generate
  log "Aplicando esquema a la base de datos…"
  npx prisma db push --accept-data-loss
  log "Compilando la aplicación (next build, salida standalone)…"
  npm run build
  log "Compilación completada."
}

# ─── Servicio systemd ────────────────────────────────────────────────────────
write_unit() {
  local node_bin; node_bin="$(command -v node || echo /usr/bin/node)"
  cat > "/etc/systemd/system/${APP}.service" <<EOF
[Unit]
Description=DIVISION T82 (postura de seguridad local-first)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SYS_USER}
WorkingDirectory=${APP_DIR}
Environment=NODE_ENV=production
Environment=PORT=${PORT}
# local-first: la web solo escucha en loopback — no accesible desde la red.
Environment=HOSTNAME=127.0.0.1
Environment=DATABASE_URL=file:${DATA_DIR}/vulncheck.db
Environment=NEXT_TELEMETRY_DISABLED=1
ExecStart=${node_bin} .next/standalone/server.js
Restart=on-failure
RestartSec=5
# Endurecimiento: solo escritura en el directorio de datos.
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}
PrivateTmp=true
ProtectHome=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
}

install_service() {
  [ "$IS_ROOT" = "1" ] || die "El servicio systemd requiere root (usa --no-service para modo portable)."
  write_unit
  systemctl daemon-reload
  systemctl enable --now "${APP}" >/dev/null 2>&1 || systemctl restart "${APP}"
  log "Servicio systemd instalado y activo: ${APP} (puerto ${PORT})."
  log "Web: http://localhost:${PORT}   ·   Logs: journalctl -u ${APP} -f"
}

# ─── Modos ───────────────────────────────────────────────────────────────────
case "$MODE" in
  install)
    ensure_runtime
    if [ "$IS_ROOT" = "1" ] && [ "$NO_SERVICE" = "0" ]; then
      DATA_DIR="${DATA_DIR:-/var/lib/${APP}}"
      log "Instalación de sistema en ${APP_DIR}…"
      [ -d "$APP_DIR" ] && warn "${APP_DIR} ya existe — se actualizará el código, la BD se conserva."
      mkdir -p "$APP_DIR" "$DATA_DIR"
      cp -a "$SRC"/. "$APP_DIR"/
      cd "$APP_DIR"
      # La BD del paquete fuente no debe sobreescribir datos reales:
      rm -rf "$APP_DIR/data"
      if ! id "$SYS_USER" >/dev/null 2>&1; then
        useradd --system --group --no-create-home --home "$APP_DIR" "$SYS_USER" || true
      fi
      do_build "$APP_DIR"
      chown -R "$SYS_USER":"$SYS_USER" "$APP_DIR" "$DATA_DIR"
      install_service
    else
      # Modo portable: instala y compila en el propio directorio fuente.
      DATA_DIR="${DATA_DIR:-$SRC/data}"
      log "Instalación portable en $SRC (sin servicio systemd)."
      do_build "$SRC"
      log "Listo. Arranca con:  ./start.sh   (puerto ${PORT})"
      log "  DATABASE_URL=${DATA_DIR}/vulncheck.db"
    fi
    ;;

  update)
    APP_DIR="${APP_DIR_OVERRIDE:-$APP_DIR}"
    [ -d "$APP_DIR/.next" ] || die "No parece una instalación en $APP_DIR — ejecuta install.sh allí."
    ensure_runtime
    DATA_DIR="${DATA_DIR:-/var/lib/${APP}}"
    [ -d "$DATA_DIR" ] || DATA_DIR="$SRC/data"
    do_build "$APP_DIR"
    if [ "$IS_ROOT" = "1" ] && [ -f "/etc/systemd/system/${APP}.service" ]; then
      chown -R "$SYS_USER":"$SYS_USER" "$APP_DIR" "$DATA_DIR" 2>/dev/null || true
      systemctl restart "$APP"
      log "Actualizado y reiniciado."
    else
      log "Actualizado. Arranca con: ./start.sh"
    fi
    ;;

  uninstall)
    if [ "$IS_ROOT" = "1" ]; then
      systemctl disable --now "$APP" 2>/dev/null || true
      rm -f "/etc/systemd/system/${APP}.service"
      systemctl daemon-reload
      rm -rf "$APP_DIR"
      log "Desinstalado. La base de datos se conserva en: ${DATA_DIR:-/var/lib/${APP}}"
    else
      die "uninstall requiere root."
    fi
    ;;

  build)
    # Solo compila (sin copiar, sin servicio). Útil tras editar el código.
    ensure_runtime
    DATA_DIR="${DATA_DIR:-$SRC/data}"
    do_build "$SRC"
    log "Compilado. Arranca con: ./start.sh"
    ;;

  install-service)
    # Registra solo el servicio systemd (lo usa el postinst del .deb).
    DATA_DIR="${DATA_DIR:-/var/lib/${APP}}"
    install_service
    ;;

  *)
    die "Modo desconocido: $MODE (usa install | update | uninstall | build)."
    ;;
esac
