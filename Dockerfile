# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM rust:slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency builds: copy manifests first
COPY Cargo.toml Cargo.lock ./
COPY crates/arkd-core/Cargo.toml crates/arkd-core/Cargo.toml
COPY crates/arkd-wallet/Cargo.toml crates/arkd-wallet/Cargo.toml
COPY crates/arkd-api/Cargo.toml crates/arkd-api/Cargo.toml
COPY crates/arkd-db/Cargo.toml crates/arkd-db/Cargo.toml
COPY crates/arkd-bitcoin/Cargo.toml crates/arkd-bitcoin/Cargo.toml

# Create dummy source files so cargo can resolve the workspace
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && for crate in arkd-core arkd-wallet arkd-api arkd-db arkd-bitcoin; do \
         mkdir -p crates/$crate/src && echo '' > crates/$crate/src/lib.rs; \
       done

# Pre-build dependencies (cached layer)
RUN cargo build --release 2>/dev/null || true

# Copy actual source code
COPY . .

# Touch source files to invalidate the dummy builds
RUN find src crates -name '*.rs' -exec touch {} +

# Build the release binary
RUN cargo build --release --bin arkd

# =============================================================================
# Stage 2: Runtime
# =============================================================================
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies (TLS certificates)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash arkd

# Copy the release binary
COPY --from=builder /build/target/release/arkd /usr/local/bin/arkd

# Create data directory
RUN mkdir -p /data && chown arkd:arkd /data

# Switch to non-root user
USER arkd
WORKDIR /home/arkd

# Default configuration
ENV RUST_LOG=info
ENV ARKD_CONFIG=/etc/arkd/config.toml

# Expose ports
EXPOSE 7070 7071 8080 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:9090/health || exit 1

ENTRYPOINT ["arkd"]
