# ---- Étape 1 : Récupérer K3s ----
FROM rancher/k3s:latest AS k3s_stage

# ---- Étape 2 : Récupérer CUDA ----
FROM nvidia/cuda:12.9.1-cudnn-runtime-ubuntu24.04 AS cuda_stage

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

# Créer l’arborescence CUDA
RUN mkdir -p /usr/local/cuda/lib64

# Copier uniquement les bibliothèques nécessaires
COPY --from=cuda_stage /usr/local/cuda/lib64/libcuda*.so* /usr/local/cuda/lib64/
COPY --from=cuda_stage /usr/local/cuda/lib64/libcudart*.so* /usr/local/cuda/lib64/
COPY --from=cuda_stage /usr/local/cuda/lib64/libcublas*.so* /usr/local/cuda/lib64/
COPY --from=cuda_stage /usr/local/cuda/lib64/libcudnn*.so* /usr/local/cuda/lib64/

# Copier K3s
COPY --from=k3s_stage /bin/k3s /usr/local/bin/k3s
RUN chmod +x /usr/local/bin/k3s

# Variables d'environnement
ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64
ENV WSL_ROLE=server
ENV WSL_PORT_RANGE=6443-6550

# Script d'auto-start
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
fi\n' > /etc/local.d/k3s.start && \
    chmod +x /etc/local.d/k3s.start

# Activer openrc
RUN rc-update add local default

ENTRYPOINT ["/sbin/init"]
