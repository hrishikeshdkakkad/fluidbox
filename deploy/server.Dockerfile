# fluidbox control plane. Build context = repo root:
#   docker build -t fluidbox-server -f deploy/server.Dockerfile .
#
# Migrations are embedded in the binary (sqlx::migrate!); the policies/ seed
# directory is baked in because the boot seeder reads ./policies from cwd.
FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY migrations ./migrations
COPY policies ./policies
RUN cargo build --release -p fluidbox-server

FROM debian:bookworm-slim
# git: control-plane-side workspace fetches (credentials ride GIT_CONFIG_* env,
# never argv or on-disk config). ca-certificates: TLS to Neon/GitHub/LiteLLM.
# curl: the compose healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/fluidbox-server /usr/local/bin/fluidbox-server
COPY policies ./policies

# The server orchestrates sibling sandbox containers over the mounted Docker
# socket, so it is inherently daemon-privileged in this deployment — it runs
# as root to reach the socket. Isolation comes from the sandboxes themselves
# (cap_drop=ALL, no-new-privileges, egress-free), not from this process's uid.
ENV FLUIDBOX_BIND=0.0.0.0:8787 \
    FLUIDBOX_DATA_DIR=/var/lib/fluidbox
EXPOSE 8787
CMD ["fluidbox-server"]
