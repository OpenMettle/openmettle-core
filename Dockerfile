# Docker Official Images; upstream Rust (MIT/Apache-2.0) and Debian package licences.
# Image distribution remains subject to V1-42 inventory and clearance.
FROM rust:1.100.0-slim-bookworm@sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37 AS build
WORKDIR /source
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release --locked --bin openmettle-api --bin openmettle-worker --bin openmettle-migrate --bin openmettle-admin

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
STOPSIGNAL SIGTERM

# One-shot schema migration Job image; API and worker images contain no migration binary.
FROM runtime AS migrate
COPY --from=build /source/target/release/openmettle-migrate /usr/local/bin/openmettle-migrate
ENTRYPOINT ["/usr/local/bin/openmettle-migrate"]

FROM runtime AS admin
COPY --from=build /source/target/release/openmettle-admin /usr/local/bin/openmettle-admin
ENTRYPOINT ["/usr/local/bin/openmettle-admin"]

FROM runtime AS api
COPY --from=build /source/target/release/openmettle-api /usr/local/bin/openmettle-api
ENV OPENMETTLE_API_BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/openmettle-api"]

FROM runtime AS worker
COPY --from=build /source/target/release/openmettle-worker /usr/local/bin/openmettle-worker
ENV OPENMETTLE_WORKER_BIND=0.0.0.0:8081
EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/openmettle-worker"]
