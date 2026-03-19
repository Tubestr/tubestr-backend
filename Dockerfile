FROM rust:1.90-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY rust ./rust

RUN cargo build --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/target/release/tubestr-backend /usr/local/bin/tubestr-backend
COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /docker-entrypoint.sh \
    && mkdir -p /data

EXPOSE 8080
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["tubestr-backend"]
