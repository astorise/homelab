# ---- Étape 1 : Récupérer K3s ----
FROM rancher/k3s:latest AS k3s-src

# ---- Étape 2 : Récupérer les bibliothèques CUDA depuis l'image NVIDIA officielle ----
FROM nvidia/cuda:12.9.1-cudnn-runtime-ubuntu24.04 AS cuda-libs

# ---- Étape 3 : Base Alpine ----
FROM alpine:3.22

RUN apk add --no-cache \
    bash \
    curl \
    ca-certificates \
    libc6-compat \
    util-linux \
    iptables \
    iproute2 \
    eudev \
    openrc

# Copier K3s
COPY --from=k3s-src /bin/k3s /usr/local/bin/k3s
RUN chmod +x /usr/local/bin/k3s

# Copier uniquement les bibliothèques CUDA nécessaires
COPY --from=cuda-libs /usr/local/cuda/lib64 /usr/local/cuda/lib64
COPY --from=cuda-libs /usr/lib/x86_64-linux-gnu/libcuda* /usr/lib/x86_64-linux-gnu/

# Configurer les libs
ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64
RUN echo "/usr/local/cuda/lib64" >> /etc/ld.so.conf && ldconfig

# Préparer WSL
RUN mkdir -p /etc && touch /etc/fstab

# Variables configurables
ENV WSL_ROLE=server
ENV WSL_PORT_RANGE=6443-6550

# Script d'auto-start
RUN mkdir -p /etc/local.d
RUN echo '#!/bin/sh\n\
ROLE=${WSL_ROLE:-server}\n\
PORT_RANGE=${WSL_PORT_RANGE:-6443-6550}\n\
if [ "$ROLE" = "server" ]; then\n\
  /usr/local/bin/k3s server --https-listen-port $(echo $PORT_RANGE | cut -d"-" -f1) --disable traefik &\n\
else\n\
  /usr/local/bin/k3s agent --server https://<WSL_SERVER_IP>:$(echo $PORT_RANGE | cut -d"-" -f1) &\n\
fi\n' > /etc/local.d/k3s.start \
    && chmod +x /etc/local.d/k3s.start

# Activer openrc
RUN rc-update add local default

ENTRYPOINT ["/sbin/init"]
