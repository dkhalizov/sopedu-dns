# Static benchmark upstream image: docker build -t upstream-mock:bench bench/upstream-mock
FROM rust:1.99-alpine@sha256:27cd9befd4a05d6f6eb407c3e28365f5092f008bfc5946207cca76ae5179ef23 AS build
RUN apk add --no-cache musl-dev
WORKDIR /b
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && cp target/release/upstream-mock /upstream-mock

FROM scratch
COPY --from=build /upstream-mock /upstream-mock
ENTRYPOINT ["/upstream-mock"]
