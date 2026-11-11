# Static benchmark upstream image: docker build -t upstream-mock:bench bench/upstream-mock
FROM rust:1.99-alpine@sha256:44819b27be4c97b0e4d7203bd2e02c4820f97700211b6a37fb4c246a2de59383 AS build
RUN apk add --no-cache musl-dev
WORKDIR /b
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && cp target/release/upstream-mock /upstream-mock

FROM scratch
COPY --from=build /upstream-mock /upstream-mock
ENTRYPOINT ["/upstream-mock"]
