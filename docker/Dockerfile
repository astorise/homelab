# ---- Étape 1 : Debian slim pour installer CUDA ----
FROM debian:12-slim AS cuda_build

# Installer wget et dpkg
RUN apt-get update && apt-get install -y wget dpkg xz-utils && rm -rf /var/lib/apt/lists/*

# Télécharger le package CUDA runtime .deb
RUN wget -O /tmp/cuda.deb https://developer.download.nvidia.com/compute/cuda/12.9.1/local_installers/cuda-repo-ubuntu2404-12-9-local_12.9.1-1_amd64.deb

# Extraire les fichiers
RUN dpkg-deb -x /tmp/cuda.deb /tmp/cuda

# ---- Étape 2 : Image finale Alpine ----
FROM alpine:3.22

# Installer outils minimaux
RUN apk add --no-cache bash curl ca-certificates libc6-compat util-linux iptables iproute2 eudev openrc

# Créer arborescence CUDA et copier seulement les libs nécessaires
RUN mkdir -p /usr/local/cuda/lib64
COPY --from=cuda_build /tmp/cuda/usr/local/cuda/lib64/libcuda*.so* /usr/local/cuda/lib64/
COPY --from=cuda_build /tmp/cuda/usr/local/cuda/lib64/libcudart*.so* /usr/local/cuda/lib64/
COPY --from=cuda_build /tmp/cuda/usr/local/cuda/lib64/libcublas*.so* /usr/local/cuda/lib64/
COPY --from=cuda_build /tmp/cuda/usr/local/cuda/lib64/libcudnn*.so* /usr/local/cuda/lib64/

ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64

# ---- K3s ----
ADD https://github.com/k3s-io/k3s/releases/latest/download/k3s /usr/local/bin/k3s
RUN chmod +x /usr/local/bin/k3s

# Variables WSL
ENV WSL_ROLE=server
ENV WSL_PORT_RANGE=6443-6550

# Script auto-start K3s
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
