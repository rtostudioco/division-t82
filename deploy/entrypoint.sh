#!/bin/sh
# DIVISION T82 — entrypoint del contenedor.
# 1. Empuja el esquema Prisma a la BD en /data (idempotente).
# 2. Arranca el servidor standalone.
set -e

DB_PATH="${DATABASE_URL#file:}"
if [ -n "$DB_PATH" ] && [ ! -f "$DB_PATH" ]; then
  echo "[entrypoint] inicializando base de datos en $DB_PATH"
fi
# Sin --accept-data-loss (C3): un cambio destructivo de esquema falla con error
# visible y el contenedor se detiene — nunca se pierden datos en silencio.
npx --yes prisma@6 db push --skip-generate || {
  echo "[entrypoint] ERROR: prisma db push falló — revisa el esquema; los datos NO se han tocado."
  exit 1
}

exec "$@"
