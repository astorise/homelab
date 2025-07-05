FROM rust:1.74 as builder
WORKDIR /src
COPY . .
RUN cargo build --release

FROM alpine:3.20
RUN apk add --no-cache curl bash iptables ip6tables \
COPY --from=builder /src/target/release/env-dev /usr/local/bin/env-dev
CMD ["/usr/local/bin/env-dev"]
