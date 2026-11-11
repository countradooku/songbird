# syntax=docker/dockerfile:1.7
# Builds one Songbird binary from source and packages it in a distroless, non-root image.
#   docker build -f deploy/docker/Dockerfile --build-arg BIN=songbird-delivery -t songbird-delivery .
# Used by CI (every push) and local development. Releases use runtime.Dockerfile with the
# reproducible, verified binaries from `cargo xtask release --verify`.
# Base images are pinned by digest (docs/DECISIONS.md D-0007).

FROM rust:1.99.1-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS build
ARG BIN
WORKDIR /songbird
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/songbird/target,sharing=locked \
    test -n "${BIN}" && \
    cargo build --release --locked --bin "${BIN}" && \
    cp "target/release/${BIN}" /app

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cc66d222f0a7ec996b78a99fe76a969bc80b539a5016ad866c14d1949bc6d0ab
COPY --from=build /app /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
