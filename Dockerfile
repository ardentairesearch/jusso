FROM rust:1.88.0-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --locked --release --bin jusso-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home jusso

COPY --from=builder /build/target/release/jusso-server /usr/local/bin/jusso-server

USER jusso
ENV HOST=0.0.0.0 \
    PORT=8080 \
    RUST_LOG=info
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/jusso-server"]
