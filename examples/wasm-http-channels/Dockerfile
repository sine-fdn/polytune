# syntax = docker/dockerfile-upstream:master-labs
FROM rust:1.85 AS builder
WORKDIR /usr/src/polytune
COPY . .
RUN cargo install --features="bin" --path ./examples/wasm-http-channels

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/broker /usr/local/bin/broker
COPY --from=builder /usr/src/polytune/examples/wasm-http-channels /usr/src/polytune/examples/wasm-http-channels
RUN apt update && apt install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

EXPOSE 8080
WORKDIR /usr/src/polytune/examples/wasm-http-channels
CMD ["broker", "--addr=0.0.0.0", "--port=8080"]
