# Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
# SPDX-License-Identifier: Apache-2.0

FROM rust:stable-bookworm AS builder
WORKDIR /app

COPY . .
RUN cargo build --release -p evidenceos-daemon

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app

COPY --from=builder /app/target/release/evidenceos-daemon /usr/local/bin/evidenceos-daemon

EXPOSE 50051 8081 9464
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/evidenceos-daemon"]
CMD ["--listen", "0.0.0.0:50051", "--data-dir", "/data", "--preflight-http-listen", "0.0.0.0:8081", "--metrics-listen", "0.0.0.0:9464"]
