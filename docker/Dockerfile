FROM alpine:3.22

# Dépendances de base
RUN apk add --no-cache \
    bash curl ca-certificates libc6-compat util-linux iptables iproute2 eudev openrc xz

# Créer le dossier CUDA
RUN mkdir -p /usr/local/cuda/lib64

# Télécharger et extraire uniquement le runtime (≈200 Mo)
RUN curl -fsSL https://developer.download.nvidia.com/compute/cuda/redist/cuda_runtime/linux-x86_64/cuda_runtime-linux-x86_64-12.9.105-archive.tar.xz \
    | tar -xJ --strip-components=1 -C /usr/local/cuda

# (Optionnel) cuDNN : ajouter seulement si nécessaire
RUN curl -fsSL https://developer.download.nvidia.com/compute/redist/cudnn/v9.5.0/local_installers/12.9/cudnn-linux-x86_64-9.5.0.50_cuda12-archive.tar.xz \
    | tar -xJ --strip-components=1 -C /usr/local/cuda

# Chemin des libs
ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64

# Ajouter K3s
ADD https://github.com/k3s-io/k3s/releases/latest/download/k3s /usr/local/bin/k3s
RUN chmod +x /usr/local/bin/k3s

# Variables
ENV WSL_ROLE=server
ENV WSL_PORT_RANGE=6443-6550

# Script d'auto‑start
RUN mkdir -p /etc/local.d && \
    echo '#!/bin/sh\n\
[ -f /etc/k3s-env ] && . /etc/k3s-env\n\
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
