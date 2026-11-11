# Build with buildx --platform linux/amd64,linux/arm64; each stage runs
# on its target architecture (native builders or QEMU), avoiding cross-linkers.
# The release workflow passes --build-arg BINARIES=prebuilt to package the
# binaries it already built instead of compiling again.
ARG BINARIES=build

FROM rust:1.99-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS build
RUN apk add --no-cache musl-dev build-base ca-certificates
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
RUN cargo build --locked --release && cp target/release/sopedu-dns /sopedu-dns
# The state directory for the final image, created here because `scratch` has
# no shell. Its owner is applied by the COPY --chown below. Mode 0770 with
# group 0 lets uid 65532 (owner) and root without CAP_DAC_OVERRIDE (group 0)
# both write it.
RUN mkdir -p /rootfs/var/lib/sopedu-dns && chmod 0770 /rootfs/var/lib/sopedu-dns

# Test stage: the whole suite on Linux, so the
# `#[cfg(target_os = "linux")]` batched UDP path is actually compiled and
# exercised. Build explicitly with `docker build --target test .`; this stage
# is not part of the production image.
FROM rust:1.99-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS test
RUN apk add --no-cache musl-dev build-base ca-certificates
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
COPY tests ./tests
COPY examples ./examples
COPY config.example.toml ./
COPY deploy ./deploy
RUN cargo test --locked

# Benchmark stage: the same musl release binary in a Debian userland that
# has dnsperf and python3. Build explicitly with
# `docker build --target bench -t sopedu-dns-bench .`.
FROM rust:1.99-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS bench-build
RUN apk add --no-cache musl-dev build-base
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
COPY examples ./examples
RUN cargo build --locked --release && cargo build --locked --release --example dns_mock

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS bench
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates dnsperf python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=bench-build /build/target/release/sopedu-dns /usr/local/bin/sopedu-dns
COPY --from=bench-build /build/target/release/examples/dns_mock /usr/local/bin/dns_mock
WORKDIR /bench
CMD ["sh"]

# Allocator comparison: three release binaries from the same source
# (default musl malloc, mimalloc, jemalloc) collected in one Debian userland
# with dnsperf. Build explicitly with
# `docker build --target alloc-bench -t sopedu-dns-alloc-bench .`; the
# production `scratch` image below is unchanged.
FROM bench-build AS alloc-build
RUN mkdir -p /out \
 && cp target/release/sopedu-dns /out/sopedu-dns-default \
 && cp target/release/examples/dns_mock /out/dns_mock \
 && cargo build --locked --release --features mimalloc \
 && cp target/release/sopedu-dns /out/sopedu-dns-mimalloc \
 && cargo build --locked --release --features jemalloc \
 && cp target/release/sopedu-dns /out/sopedu-dns-jemalloc

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS alloc-bench
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates dnsperf python3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=alloc-build /out/sopedu-dns-default /usr/local/bin/sopedu-dns-default
COPY --from=alloc-build /out/sopedu-dns-mimalloc /usr/local/bin/sopedu-dns-mimalloc
COPY --from=alloc-build /out/sopedu-dns-jemalloc /usr/local/bin/sopedu-dns-jemalloc
COPY --from=alloc-build /out/dns_mock /usr/local/bin/dns_mock
WORKDIR /bench
CMD ["sh"]

# Release images: the static binaries from the release workflow, laid out as
# dist/amd64/sopedu-dns and dist/arm64/sopedu-dns. Runs on the build host only.
FROM --platform=$BUILDPLATFORM rust:1.99-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS prebuilt
ARG TARGETARCH
RUN apk add --no-cache ca-certificates
COPY dist /dist
RUN mkdir -p /rootfs/var/lib/sopedu-dns && chmod 0770 /rootfs/var/lib/sopedu-dns \
 && install -m 0755 "/dist/$TARGETARCH/sopedu-dns" /sopedu-dns

FROM ${BINARIES} AS binaries

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/dkhalizov/sopedu-dns" \
      org.opencontainers.image.description="Caching DNS-over-HTTPS forwarder with blocklists" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
COPY --from=binaries /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=binaries /sopedu-dns /sopedu-dns
COPY deploy/docker.toml /etc/sopedu-dns/config.toml
# Copy the parent so the directory keeps its 0770 mode; COPY of a directory
# itself would create the destination with the default 0755.
COPY --from=binaries --chown=65532:0 /rootfs/var/lib /var/lib
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 65532:65532
# Cached blocklists. A named volume inherits this directory's owner and mode.
VOLUME /var/lib/sopedu-dns
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/sopedu-dns"]
CMD ["/etc/sopedu-dns/config.toml"]
