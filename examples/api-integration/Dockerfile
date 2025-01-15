# syntax = docker/dockerfile-upstream:master-labs
FROM rust:1.82 AS builder
WORKDIR /usr/src/polytune
COPY . .
RUN cargo install --path ./examples/api-integration

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/polytune-api-integration /usr/local/bin/polytune-api-integration
COPY --from=builder /usr/src/polytune/examples/api-integration /usr/src/polytune/examples/api-integration
RUN apt update && apt install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

EXPOSE 8000
WORKDIR /usr/src/polytune/examples/api-integration
CMD ["polytune-api-integration", "--addr=0.0.0.0", "--port=8000"]
