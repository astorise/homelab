FROM rust:1.74 as builder
WORKDIR /src
COPY . .
RUN cargo build --release

FROM alpine:3.20
RUN apk add --no-cache curl bash openrc \
    && INSTALL_K3S_SKIP_START=true INSTALL_K3S_SKIP_ENABLE=true \
    curl -sfL https://get.k3s.io | sh -
COPY --from=builder /src/target/release/env-dev /usr/local/bin/env-dev
CMD ["/usr/local/bin/env-dev"]
