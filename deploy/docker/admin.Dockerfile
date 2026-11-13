# syntax=docker/dockerfile:1.7
# songbird-admin with the reference `age` tool, for the backup timer and the restore verification
# (D-0040). The binary is the verified release binary, as in runtime.Dockerfile; age is the
# upstream release, pinned by version and SHA-256 (the same pin as deploy/bin/install-tools).
#   docker build -f deploy/docker/admin.Dockerfile target/dist/<v>/<triple>
FROM rust:1.99.1-trixie@sha256:8a4e90c7946b74626488b1446f712c0fe0ed1a596cbd3d871684bc9c5433ae07 AS age
ARG AGE_VERSION=1.3.2
ARG AGE_SHA256=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10
RUN curl -fsSL --proto '=https' --tlsv1.2 -o /age.tgz \
      "https://github.com/FiloSottile/age/releases/download/v${AGE_VERSION}/age-v${AGE_VERSION}-linux-amd64.tar.gz" && \
    echo "${AGE_SHA256}  /age.tgz" | sha256sum -c - && \
    tar -xzf /age.tgz -C / age/age

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:cc66d222f0a7ec996b78a99fe76a969bc80b539a5016ad866c14d1949bc6d0ab
COPY --from=age --chmod=0555 /age/age /usr/local/bin/age
COPY --chmod=0555 songbird-admin /app
USER nonroot:nonroot
ENTRYPOINT ["/app"]
