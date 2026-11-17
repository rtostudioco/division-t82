# DIVISION T82
# Imagen contenedora multi-stage (linux/amd64 · linux/arm64).
#
#   docker build -t vulncheck-t82 -f deploy/Dockerfile .
#   docker run -d --name vulncheck -p 127.0.0.1:3000:3000 \
#     -v vulncheck-data:/data \
#     -e DATABASE_URL="file:/data/vulncheck.db" \
#     vulncheck-t82
#
# El contenedor enlaza a 0.0.0.0 INTERNAMENTE (requisito de Docker para
# publicar el puerto); la postura local-first se aplica en la publicación:
# usa -p 127.0.0.1:3000:3000 (docker-compose.yml ya lo hace así).
#
# La plataforma audita EL HOST donde corre: dentro de un contenedor lee /proc
# y /etc del propio contenedor. Para auditar el host real, montalo de solo
# lectura (ver deploy/docker-compose.yml, perfil "host-audit").

# ─── Stage 1: dependencias + build ───────────────────────────────────────────
FROM node:22-alpine AS builder
WORKDIR /app

# Bun acelera la instalacion; si no esta disponible, npm ci tambien vale.
RUN apk add --no-cache libc6-compat
COPY package.json bun.lock* package-lock.json* ./
RUN if command -v bun >/dev/null 2>&1; then bun install --frozen-lockfile; \
    elif [ -f package-lock.json ]; then npm ci; \
    else npm install; fi

COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# Prisma genera el cliente para la plataforma del builder; alpine usa musl.
RUN npx prisma generate || bunx prisma generate
RUN npm run build

# ─── Stage 2: runtime standalone ─────────────────────────────────────────────
FROM node:22-alpine AS runner
WORKDIR /app
RUN apk add --no-cache openssl libc6-compat \
 && addgroup -S t82 && adduser -S t82 -G t82 \
 && mkdir -p /data && chown t82:t82 /data

ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    DATABASE_URL=file:/data/vulncheck.db

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
COPY --from=builder /app/prisma ./prisma

# Aplica el esquema al primer arranque y luego arranca el servidor.
COPY deploy/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER t82
VOLUME /data
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD wget -qO- http://127.0.0.1:3000/api/engine/status >/dev/null 2>&1 || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["node", "server.js"]
