# syntax = docker/dockerfile-upstream:master-labs
FROM rust:1.89 AS builder
WORKDIR /usr/src/polytune
COPY . .
RUN cargo install --path ./crates/polytune-server --locked

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/polytune-api-integration /usr/local/bin/polytune-api-integration
COPY --from=builder /usr/src/polytune/crates/polytune-server /usr/src/polytune/crates/polytune-server
RUN apt update && apt install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

EXPOSE 8000
WORKDIR /usr/src/polytune/crates/polytune-server
CMD ["polytune-server", "--addr=0.0.0.0", "--port=8000"]
