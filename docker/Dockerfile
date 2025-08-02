# ---- Étape 1 : Debian avec CUDA installé ----
FROM debian:12-slim AS cuda_build

# Préparer apt et installer CUDA runtime
RUN apt-get update && apt-get install -y wget gnupg ca-certificates && \
    wget https://developer.download.nvidia.com/compute/cuda/repos/debian12/x86_64/cuda-keyring_1.1-1_all.deb && \
    dpkg -i cuda-keyring_1.1-1_all.deb && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        cuda-libraries-12-9 \
    && rm -rf /var/lib/apt/lists/*

# ---- Étape 2 : Alpine finale ----
FROM alpine:3.22

# Installer outils de base
RUN apk add --no-cache bash curl ca-certificates libc6-compat util-linux iptables iproute2 eudev openrc

# Créer répertoire CUDA et copier uniquement les libs
RUN mkdir -p /usr/local/cuda/lib64
COPY --from=cuda_build /usr/local/cuda/lib64 /usr/local/cuda/lib64

ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64

# ---- Config WSL ----
ENV WSL_ROLE=server
ENV WSL_PORT_RANGE=6443-6550

# Script de démarrage auto
RUN mkdir -p /etc/local.d && \
    echo '#!/bin/sh\n\
ROLE=${WSL_ROLE:-server}\n\
PORT_RANGE=${WSL_PORT_RANGE:-6443-6550}\n\
API_PORT=$(echo $PORT_RANGE | cut -d"-" -f1)\n\
if [ "$ROLE" = "server" ]; then\n\
  /usr/local/bin/k3s server --https-listen-port $API_PORT --disable traefik &\n\
else\n\
  if [ -z "$K3S_URL" ]; then echo "[ERREUR] K3S_URL manquant pour agent"; exit 1; fi\n\
  /usr/local/bin/k3s agent --server "$K3S_URL" &\n\
fi\n' > /etc/local.d/k3s.start && chmod +x /etc/local.d/k3s.start

RUN rc-update add local default
ENTRYPOINT ["/sbin/init"]
