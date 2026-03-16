# ---- glibc overlay stage ----
# Debian 11 est dans les plateformes officiellement testées par NVIDIA Container Toolkit.
FROM debian:bullseye-slim AS glibc-overlay

RUN apt-get update && apt-get install -y --no-install-recommends \
    libc6 \
    libgcc-s1 \
    libstdc++6 \
    zlib1g \
    libcap2 \
    libseccomp2 \
    libtirpc3 \
    libjansson4 \
    libelf1 \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p \
      /glibc-overlay/lib/x86_64-linux-gnu \
      /glibc-overlay/lib64 \
      /glibc-overlay/usr/lib/x86_64-linux-gnu \
      /glibc-overlay/etc \
      /glibc-overlay/etc/ssl/certs; \
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
    cp -av /lib/x86_64-linux-gnu/libcap.so.2 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libseccomp.so.2 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libtirpc.so.3 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libjansson.so.4 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /lib/x86_64-linux-gnu/libelf.so.1 /glibc-overlay/lib/x86_64-linux-gnu/; \
    cp -av /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /glibc-overlay/usr/lib/x86_64-linux-gnu/; \
    cp -av /lib64/ld-linux-x86-64.so.2 /glibc-overlay/lib64/; \
    cp -av /etc/ssl/certs/ca-certificates.crt /glibc-overlay/etc/ssl/certs/; \
    printf 'passwd: files\n' > /glibc-overlay/etc/nsswitch.conf; \
    printf 'group: files\n' >> /glibc-overlay/etc/nsswitch.conf; \
    printf 'shadow: files\n' >> /glibc-overlay/etc/nsswitch.conf; \
    printf 'gshadow: files\n' >> /glibc-overlay/etc/nsswitch.conf; \
    printf 'hosts: files dns\n' >> /glibc-overlay/etc/nsswitch.conf; \
    printf 'networks: files\n' >> /glibc-overlay/etc/nsswitch.conf

# ---- NVIDIA toolkit stage ----
# On prend une base Debian 11, compatible avec les instructions apt officielles NVIDIA.
FROM debian:bullseye-slim AS nvidia-toolkit

ARG NVIDIA_CONTAINER_TOOLKIT_VERSION=1.19.0-1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg2 \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
      | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg; \
    curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
      | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
      > /etc/apt/sources.list.d/nvidia-container-toolkit.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      nvidia-container-toolkit=${NVIDIA_CONTAINER_TOOLKIT_VERSION} \
      nvidia-container-toolkit-base=${NVIDIA_CONTAINER_TOOLKIT_VERSION} \
      libnvidia-container-tools=${NVIDIA_CONTAINER_TOOLKIT_VERSION} \
      libnvidia-container1=${NVIDIA_CONTAINER_TOOLKIT_VERSION}; \
    rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p \
      /nvidia-overlay/usr/bin \
      /nvidia-overlay/usr/lib/x86_64-linux-gnu \
      /nvidia-overlay/etc/nvidia-container-runtime \
      /nvidia-overlay/etc/nvidia-container-toolkit \
      /nvidia-overlay/usr/share; \
    for bin in \
      /usr/bin/nvidia-container-runtime \
      /usr/bin/nvidia-container-runtime-hook \
      /usr/bin/nvidia-container-cli \
      /usr/bin/nvidia-ctk; \
    do \
      [ -f "$bin" ] && cp -av "$bin" /nvidia-overlay/usr/bin/; \
    done; \
    if [ -d /etc/nvidia-container-runtime ]; then \
      cp -a /etc/nvidia-container-runtime/. /nvidia-overlay/etc/nvidia-container-runtime/; \
    fi; \
    if [ -d /etc/nvidia-container-toolkit ]; then \
      cp -a /etc/nvidia-container-toolkit/. /nvidia-overlay/etc/nvidia-container-toolkit/; \
    fi; \
    if [ -d /usr/share/nvidia-container-toolkit ]; then \
      mkdir -p /nvidia-overlay/usr/share/nvidia-container-toolkit; \
      cp -a /usr/share/nvidia-container-toolkit/. /nvidia-overlay/usr/share/nvidia-container-toolkit/; \
    fi

# Copie récursive des dépendances ELF réelles des binaires NVIDIA.
RUN set -eux; \
    bins="/usr/bin/nvidia-container-runtime /usr/bin/nvidia-container-runtime-hook /usr/bin/nvidia-container-cli /usr/bin/nvidia-ctk"; \
    for bin in $bins; do \
      if [ -f "$bin" ]; then \
        ldd "$bin" \
          | awk '/=> \// { print $3 } /^\// { print $1 }' \
          | sort -u \
          | while read -r lib; do \
              [ -n "$lib" ] || continue; \
              dest="/nvidia-overlay$(dirname "$lib")"; \
              mkdir -p "$dest"; \
              cp -av "$lib" "$dest/"; \
            done; \
      fi; \
    done

# ---- CA bundle stage ----
FROM alpine:3.23 AS ca-certs
RUN apk add --no-cache ca-certificates

# ---- BusyBox final rootfs ----
FROM busybox:1.37.0-musl

ENV WSL_ROLE=server
ENV WSL_PORT_RANGE=6443-6550

# Utilitaires réseau BusyBox nécessaires à k3s et à l'init.
RUN mkdir -p /sbin /usr/local/bin /etc/ssl/certs /etc/profile.d \
 && ln -sf /bin/busybox /sbin/ip \
 && ln -sf /bin/busybox /sbin/iptables \
 && ln -sf /bin/busybox /sbin/iptables-save \
 && ln -sf /bin/busybox /sbin/iptables-restore

# CA bundle
COPY --from=ca-certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN ln -sf /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem

# ---- glibc minimal ----
COPY --from=glibc-overlay /glibc-overlay/lib /lib
COPY --from=glibc-overlay /glibc-overlay/lib64 /lib64
COPY --from=glibc-overlay /glibc-overlay/usr/lib /usr/lib
COPY --from=glibc-overlay /glibc-overlay/etc/nsswitch.conf /etc/nsswitch.conf
COPY --from=glibc-overlay /glibc-overlay/etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# ---- NVIDIA runtime minimal ----
COPY --from=nvidia-toolkit /nvidia-overlay/usr/bin /usr/bin
COPY --from=nvidia-toolkit /nvidia-overlay/usr/lib /usr/lib
COPY --from=nvidia-toolkit /nvidia-overlay/etc/nvidia-container-runtime /etc/nvidia-container-runtime
COPY --from=nvidia-toolkit /nvidia-overlay/etc/nvidia-container-toolkit /etc/nvidia-container-toolkit
COPY --from=nvidia-toolkit /nvidia-overlay/usr/share /usr/share

# Wrappers glibc pour les binaires NVIDIA
RUN set -eux; \
    cat > /usr/local/bin/nvidia-container-runtime <<'EOF' \
#!/bin/sh
exec /lib64/ld-linux-x86-64.so.2 \
  --library-path /usr/lib/wsl/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib64 \
  /usr/bin/nvidia-container-runtime "$@"
EOF
RUN chmod +x /usr/local/bin/nvidia-container-runtime

RUN set -eux; \
    cat > /usr/local/bin/nvidia-container-cli <<'EOF' \
#!/bin/sh
exec /lib64/ld-linux-x86-64.so.2 \
  --library-path /usr/lib/wsl/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib64 \
  /usr/bin/nvidia-container-cli "$@"
EOF
RUN chmod +x /usr/local/bin/nvidia-container-cli

RUN set -eux; \
    cat > /usr/local/bin/nvidia-ctk <<'EOF' \
#!/bin/sh
exec /lib64/ld-linux-x86-64.so.2 \
  --library-path /usr/lib/wsl/lib:/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:/lib64 \
  /usr/bin/nvidia-ctk "$@"
EOF
RUN chmod +x /usr/local/bin/nvidia-ctk

RUN set -eux; \
    cat > /usr/local/bin/nvidia-smi <<'EOF' \
#!/bin/sh
exec /usr/lib/wsl/lib/nvidia-smi "$@"
EOF
RUN chmod +x /usr/local/bin/nvidia-smi

# Alias simple pour que le runtime soit visible de façon évidente dans le PATH
RUN ln -sf /usr/local/bin/nvidia-container-runtime /usr/local/bin/nvidia

# S'assure que /usr/lib/wsl/lib est dans le PATH interactif
RUN printf 'export PATH="/usr/lib/wsl/lib:$PATH"\n' > /etc/profile.d/wsl-nvidia.sh

# Config NVIDIA runtime minimale
RUN mkdir -p /etc/nvidia-container-runtime /etc/nvidia-container-toolkit
RUN if [ ! -f /etc/nvidia-container-runtime/config.toml ]; then \
      printf '%s\n' \
        'disable-require = false' \
        '[nvidia-container-cli]' \
        'environment = []' \
        'ldconfig = "@/sbin/ldconfig.real"' \
        'load-kmods = false' \
        'debug = "/var/log/nvidia-container-toolkit.log"' \
        '' \
        '[nvidia-container-runtime]' \
        'log-level = "info"' \
        'mode = "auto"' \
      > /etc/nvidia-container-runtime/config.toml; \
    fi

# K3s/containerd template v3 : on n'utilise pas nvidia-ctk pendant le build,
# on prépare directement le runtime nvidia pour containerd embarqué par k3s.
RUN mkdir -p /var/lib/rancher/k3s/agent/etc/containerd
RUN cat > /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl <<'EOF'
{{ template "base" . }}

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia']
  runtime_type = "io.containerd.runc.v2"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.'nvidia'.options]
  BinaryName = "/usr/local/bin/nvidia-container-runtime"
  SystemdCgroup = false
EOF

# Petit script de smoke test
RUN cat > /usr/local/bin/nvidia-wsl-smoke.sh <<'EOF'
#!/bin/sh
set -eu
echo "== WSL GPU files =="
ls -l /dev/dxg || true
ls -l /usr/lib/wsl/lib || true
echo "== nvidia-smi =="
/usr/local/bin/nvidia-smi || true
echo "== nvidia-container-cli info =="
/usr/local/bin/nvidia-container-cli info || true
echo "== K3s containerd template =="
cat /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl || true
EOF
RUN chmod +x /usr/local/bin/nvidia-wsl-smoke.sh

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
