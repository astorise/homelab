FROM rust:1.74 as builder
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /src/target/release/env-dev /usr/local/bin/env-dev
CMD ["/usr/local/bin/env-dev"]
