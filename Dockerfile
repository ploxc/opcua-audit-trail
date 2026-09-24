FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked && mkdir -p /out/data

# distroless/cc: glibc + libgcc only, no shell, runs as non-root (65532).
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/opcua-audit-gateway /usr/local/bin/opcua-audit-gateway
# Template for /data/config.toml, copied there on first start.
COPY docker/config.toml /etc/opcua-audit-gateway/config.toml
# The data directory must belong to the non-root user, or a fresh volume
# would be root-owned and read-only for the gateway.
COPY --from=build --chown=65532:65532 /out/data /data
ENV OPCUA_GATEWAY_CONFIG=/data/config.toml
VOLUME ["/data"]
EXPOSE 8080 4841
ENTRYPOINT ["/usr/local/bin/opcua-audit-gateway"]
CMD ["run", "--create-config-from", "/etc/opcua-audit-gateway/config.toml"]
