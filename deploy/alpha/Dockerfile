# syntax=docker/dockerfile:1.7
FROM rust:1.88.0-bookworm AS builder

# Keep the pinned Rust/Bookworm base current with Debian security updates;
# exact apt revision pins would make routine patched rebuilds fail.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends clang cmake perl pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN --mount=type=cache,id=exocord-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=exocord-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=exocord-cargo-target,target=/src/target \
    find apps crates vendor -type f \( -name '*.rs' -o -name 'Cargo.toml' \) \
      -exec touch {} + \
    && \
    CARGO_PROFILE_RELEASE_LTO=false \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=4 \
    cargo build --locked --release --package exo-monolith \
    && install -D -m 0755 /src/target/release/exo-monolith /out/exo-monolith \
    && strip /out/exo-monolith

FROM debian:bookworm-slim AS runtime

# The runtime base is rebuilt against current Bookworm security revisions.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 exocord \
    && useradd --system --uid 10001 --gid exocord --home /var/lib/exocord exocord \
    && install -d -o exocord -g exocord /var/lib/exocord

COPY --from=builder --chown=exocord:exocord \
    /out/exo-monolith /usr/local/bin/exo-monolith

USER exocord
WORKDIR /var/lib/exocord
EXPOSE 4100
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/exo-monolith"]
