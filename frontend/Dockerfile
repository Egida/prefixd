# Build stage
FROM oven/bun:1.4.3@sha256:ec06c3b6cea04192ae6770c434f668ca41d343ad19fa6472216c7b48be39c598 AS builder

WORKDIR /app

# Copy package files
COPY package.json bun.lock ./

# Install the committed resolution with the same Bun version as CI.
RUN bun install --frozen-lockfile

# Copy source
COPY . .

# Build
ENV NEXT_TELEMETRY_DISABLED=1
# Next subtracts one from CIRCLE_NODE_TOTAL; keep build workers at three.
RUN CIRCLE_NODE_TOTAL=4 RAYON_NUM_THREADS=3 TOKIO_WORKER_THREADS=3 \
    UV_THREADPOOL_SIZE=3 bun run build

# Production stage
FROM oven/bun:1.4.3-slim@sha256:14a223fa35747ec728bce300ef85888bc5f7958164d15bbba6a54b22b52a3288 AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Create non-root user (bun image is distroless-like, use numeric IDs)
RUN echo "nextjs:x:1001:1001::/app:/sbin/nologin" >> /etc/passwd && \
    echo "nodejs:x:1001:" >> /etc/group || true

# Copy built assets
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["bun", "server.js"]
