# Static benchmark upstream image: docker build -t upstream-mock:bench bench/upstream-mock
FROM rust:1.100-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS build
RUN apk add --no-cache musl-dev
WORKDIR /b
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && cp target/release/upstream-mock /upstream-mock

FROM scratch
COPY --from=build /upstream-mock /upstream-mock
ENTRYPOINT ["/upstream-mock"]
