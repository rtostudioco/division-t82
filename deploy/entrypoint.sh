#!/bin/sh
# DIVISION T82 — entrypoint del contenedor.
# 1. Empuja el esquema Prisma a la BD en /data (idempotente).
# 2. Arranca el servidor standalone.
set -e

DB_PATH="${DATABASE_URL#file:}"
if [ -n "$DB_PATH" ] && [ ! -f "$DB_PATH" ]; then
  echo "[entrypoint] inicializando base de datos en $DB_PATH"
fi
npx --yes prisma@6 db push --skip-generate --accept-data-loss >/dev/null

exec "$@"
