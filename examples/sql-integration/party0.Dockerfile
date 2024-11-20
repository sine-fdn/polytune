# syntax = docker/dockerfile-upstream:master-labs
FROM rust:1.82 AS builder
WORKDIR /usr/src/parlay
COPY . .
RUN cargo install --path ./examples/sql-integration

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/parlay-sql-integration /usr/local/bin/parlay-sql-integration
COPY --from=builder /usr/src/parlay/examples/sql-integration /usr/src/parlay/examples/sql-integration
RUN apt update && apt install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

EXPOSE 8000
WORKDIR /usr/src/parlay/examples/sql-integration
CMD ["parlay-sql-integration", "--addr=0.0.0.0", "--port=8000", "--config=./policy0.json"]
