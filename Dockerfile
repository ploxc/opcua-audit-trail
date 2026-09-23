FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# distroless/cc: glibc + libgcc only, no shell, runs as non-root.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/opcua-audit-gateway /usr/local/bin/opcua-audit-gateway
COPY docker/config.toml /etc/opcua-audit-gateway/config.toml
ENV OPCUA_GATEWAY_CONFIG=/etc/opcua-audit-gateway/config.toml
VOLUME ["/data"]
EXPOSE 8080 4841
ENTRYPOINT ["/usr/local/bin/opcua-audit-gateway"]
CMD ["run"]
