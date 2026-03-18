# Install dependencies with Bun (fast)
FROM oven/bun:latest AS deps

WORKDIR /app
COPY package.json bun.lock ./
RUN bun install

# Build with Node to avoid Bun segfault during next build finalization
# See: https://github.com/oven-sh/bun/issues/24397
FROM node:22-slim AS builder

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
RUN npx next build

# Production stage — Bun runtime
FROM oven/bun:latest AS runner

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
