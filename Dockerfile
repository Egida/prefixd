# Build stage
FROM rust:1.99.1-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a AS builder

WORKDIR /app
ARG CARGO_BUILD_JOBS=3

# Install protobuf compiler for gRPC
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY proto ./proto
COPY benches ./benches

# Create dummy src to cache dependencies
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/prefixdctl.rs && \
    echo "" > src/lib.rs

# Build dependencies only (skip benchmarks for faster builds)
RUN cargo build --locked --release --bins && rm -rf src

# Copy actual source code
COPY src ./src
COPY migrations ./migrations

# Build the application
RUN touch src/lib.rs src/main.rs src/bin/prefixdctl.rs && \
    cargo build --locked --release --bins

# Runtime stage - use same base as rust image for glibc compatibility
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries
COPY --from=builder /app/target/release/prefixd /usr/local/bin/
COPY --from=builder /app/target/release/prefixdctl /usr/local/bin/

# Copy migrations (needed for postgres)
COPY --from=builder /app/migrations ./migrations

# Named volumes are initialized by a short-lived root service; the daemon is unprivileged.
RUN groupadd --system --gid 999 prefixd \
    && useradd --system --uid 999 --gid 999 --home-dir /data --shell /usr/sbin/nologin prefixd \
    && mkdir -p /data /etc/prefixd /run/rustbgpd \
    && chown 999:999 /data /etc/prefixd /run/rustbgpd

COPY configs/ /usr/local/share/prefixd/configs/
COPY scripts/init-config.sh /usr/local/bin/prefixd-init
RUN chmod 755 /usr/local/bin/prefixd-init

USER 999:999

# Default config directory
ENV PREFIXD_CONFIG=/etc/prefixd

EXPOSE 8080 9090

ENTRYPOINT ["prefixd"]
CMD ["--config", "/etc/prefixd"]
