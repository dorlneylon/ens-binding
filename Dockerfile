FROM rust:1.75-slim AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./

RUN mkdir src
COPY src/main.rs ./src/
RUN cargo build --release

RUN rm -f target/release/deps/ccip_read_server*
COPY src ./src

RUN cargo build --release
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/ccip-read-server /usr/local/bin/ccip-read-server

COPY .env .env

EXPOSE 3000

CMD ["ccip-read-server"]
