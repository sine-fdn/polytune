FROM rust:1.91 AS builder
WORKDIR /usr/src/polytune
COPY . .
RUN cargo build --release --package polytune-http-server

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /usr/src/polytune/target/release/polytune-http-server /app/polytune-http-server
RUN mkdir /app/tmp
RUN apt update && apt install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN update-ca-certificates

ENV SERVER_ADDR="0.0.0.0:8000"
ENV POLYTUNE_LOG="info"
ENV SERVER_CONCURRENCY="2"
ENV SERVER_TMP_DIR="/app/tmp"

CMD ["/app/polytune-http-server"]
