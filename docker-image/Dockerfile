# ---- BusyBox image  ----
FROM busybox:1.36.1-musl

# Ensure BusyBox provides required network utilities
RUN mkdir -p /sbin \
    && ln -s /bin/busybox /sbin/ip \
    && ln -s /bin/busybox /sbin/iptables \
    && ln -s /bin/busybox /sbin/iptables-save \
    && ln -s /bin/busybox /sbin/iptables-restore

ENV WSL_ROLE=server
ENV WSL_PORT_RANGE=6443-6550

RUN mkdir -p /usr/local/bin

# Copy initialization scripts and environment
COPY docker-image/k3s-env /etc/k3s-env
COPY docker-image/fstab /etc/fstab
COPY docker-image/mount_all.sh /usr/local/bin/mount_all.sh
COPY docker-image/k3s-init.sh /usr/local/bin/k3s-init.sh
RUN chmod +x /usr/local/bin/mount_all.sh /usr/local/bin/k3s-init.sh

# Script de démarrage auto
RUN mkdir -p /etc/local.d \
    && printf '#!/bin/sh\n/usr/local/bin/k3s-init.sh\n' > /etc/local.d/k3s.start \
    && chmod +x /etc/local.d/k3s.start

ENTRYPOINT ["/usr/local/bin/k3s-init.sh"]