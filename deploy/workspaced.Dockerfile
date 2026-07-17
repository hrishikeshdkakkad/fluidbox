# fluidbox in-pod workspace collector. Build context = repo root:
#   docker build -t fluidbox-workspaced -f deploy/workspaced.Dockerfile .
#
# Runs as the sandbox Pod's init container (archive fetch + unpack + pristine
# baseline) and its long-lived collector container (diff-out over pods/exec).
# git: the scrubbed diff invocation. ca-certificates: TLS for the archive GET.
# Non-root numeric uid; no shell/curl/coreutils are required by the binary
# (tar/gzip are Rust-native), only git + certs.
FROM rust:1.96-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --release -p workspaced

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/workspaced /usr/local/bin/workspaced
# Numeric non-root uid (kubelet cannot prove a named USER is non-root); matches
# the Pod securityContext runAsUser default.
USER 10001:10001
ENTRYPOINT ["workspaced"]
