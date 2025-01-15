# syntax = docker/dockerfile-upstream:master-labs
FROM rust:1.82 AS builder
WORKDIR /usr/src/polytune
COPY . .
RUN cargo install --path ./examples/sql-integration

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/polytune-sql-integration /usr/local/bin/polytune-sql-integration
COPY --from=builder /usr/src/polytune/examples/sql-integration /usr/src/polytune/examples/sql-integration
RUN apt update && apt install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

EXPOSE 8001
WORKDIR /usr/src/polytune/examples/sql-integration
CMD ["polytune-sql-integration", "--addr=0.0.0.0", "--port=8001", "--config=./policy1.json"]
