# ---- glibc overlay stage ----
FROM debian:bookworm-slim AS glibc-overlay

RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6 \
    libgcc-s1 \
    libstdc++6 \
    zlib1g \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p \
      /glibc-overlay/lib/x86_64-linux-gnu \
      /glibc-overlay/lib64 \
      /glibc-overlay/usr/lib/x86_64-linux-gnu \
      /glibc-overlay/etc; \
    cp -av /lib/x86_64-linux-gnu/libc.so.6 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libdl.so.2 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libm.so.6 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libpthread.so.0 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/librt.so.1 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libresolv.so.2 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libnss_dns.so.2 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libnss_files.so.2 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libgcc_s.so.1 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libz.so.1 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /glibc-overlay/usr/lib/x86_64-linux-gnu/; \
    cp -av /lib64/ld-linux-x86-64.so.2 /glibc-overlay/lib64/; \
    printf 'passwd: files\n' > /glibc-overlay/etc/nsswitch.conf; \
    printf 'group: files\n' >> /glibc-overlay/etc/nsswitch.conf; \
    printf 'shadow: files\n' >> /glibc-overlay/etc/nsswitch.conf; \
    printf 'gshadow: files\n' >> /glibc-overlay/etc/nsswitch.conf; \
    printf 'hosts: files dns\n' >> /glibc-overlay/etc/nsswitch.conf; \
    printf 'networks: files\n' >> /glibc-overlay/etc/nsswitch.conf

# ---- CA bundle stage ----
FROM alpine:3.23 AS ca-certs
RUN apk add --no-cache ca-certificates

# ---- BusyBox image ----
FROM busybox:1.37.0-musl

# Ensure BusyBox provides required network utilities
RUN mkdir -p /sbin \
 && ln -s /bin/busybox /sbin/ip \
 && ln -s /bin/busybox /sbin/iptables \
 && ln -s /bin/busybox /sbin/iptables-save \
 && ln -s /bin/busybox /sbin/iptables-restore

ENV WSL_ROLE=server
ENV WSL_PORT_RANGE=6443-6550

RUN mkdir -p /usr/local/bin /etc/ssl/certs

COPY --from=ca-certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN ln -sf /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem

# ---- glibc files injected into final rootfs ----
COPY --from=glibc-overlay /glibc-overlay/lib /lib
COPY --from=glibc-overlay /glibc-overlay/lib64 /lib64
COPY --from=glibc-overlay /glibc-overlay/usr/lib /usr/lib
COPY --from=glibc-overlay /glibc-overlay/etc/nsswitch.conf /etc/nsswitch.conf

# Copy initialization scripts and environment
COPY docker-image/k3s-env /etc/k3s-env
COPY docker-image/wsl.conf /etc/wsl.conf
COPY docker-image/fstab /etc/fstab
COPY docker-image/mount_all.sh /usr/local/bin/mount_all.sh
COPY docker-image/k3s-init.sh /usr/local/bin/k3s-init.sh

RUN chmod +x /usr/local/bin/mount_all.sh /usr/local/bin/k3s-init.sh

# Script de démarrage auto
RUN mkdir -p /etc/local.d \
 && printf '#!/bin/sh\nexec sh /usr/local/bin/k3s-init.sh\n' > /etc/local.d/k3s.start \
 && chmod +x /etc/local.d/k3s.start

ENTRYPOINT ["/bin/sh", "/usr/local/bin/k3s-init.sh"]
