# Quantum Shield PayPal — reproducible multi-stage build
FROM docker.io/library/rust:1.98-bookworm AS builder
WORKDIR /src
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake \
 && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web ./web
COPY third_party ./third_party
RUN cargo build --release --locked --bin qsctl

FROM docker.io/library/debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --home-dir /data qshield
COPY --from=builder /src/target/release/qsctl /usr/local/bin/qsctl
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh \
 && mkdir -p /data/.local/share /data/.local/state \
 && chown -R qshield:qshield /data
USER qshield
ENV HOME=/data XDG_DATA_HOME=/data/.local/share QS_KEY_DIR=/data/.local/state/quantum-shield/payment-pq-keys
EXPOSE 18090
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:18090/api/health >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["qsctl", "payment-serve", "--listen", "0.0.0.0:18090", "--allow-public-listener"]
