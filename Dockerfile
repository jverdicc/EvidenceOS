# EvidenceOS daemon container

FROM rust:1.78-bookworm AS builder
WORKDIR /app

# Pre-copy manifests for better caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY proto ./proto

RUN cargo build --release -p evidenceos-daemon

FROM debian:bookworm-slim
RUN useradd -m -u 10001 evidenceos
WORKDIR /home/evidenceos

COPY --from=builder /app/target/release/evidenceos-daemon /usr/local/bin/evidenceos-daemon

USER evidenceos
EXPOSE 50051
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/evidenceos-daemon"]
CMD ["--listen", "0.0.0.0:50051", "--etl-path", "/data/etl.log"]
