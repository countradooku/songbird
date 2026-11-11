# syntax=docker/dockerfile:1.7
# Packages a verified release binary (built and checked by `cargo xtask release --verify`).
#   docker build -f deploy/docker/runtime.Dockerfile --build-arg BIN=songbird-delivery target/dist/<v>/<triple>
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cc66d222f0a7ec996b78a99fe76a969bc80b539a5016ad866c14d1949bc6d0ab
ARG BIN
COPY --chmod=0555 ${BIN} /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
