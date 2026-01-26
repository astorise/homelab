#!/bin/sh
set -e

log_info() {
    echo "[INFO] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

# Load environment overrides if present
[ -f /etc/k3s-env ] && . /etc/k3s-env

# Mount all filesystems defined in /etc/fstab
/usr/local/bin/mount_all.sh

ROLE=${WSL_ROLE:-server}
PORT_RANGE=${PORT_RANGE:-6443-6550}
API_PORT=$(echo "$PORT_RANGE" | cut -d"-" -f1)
BOOTSTRAP_ONLY=${BOOTSTRAP_ONLY:-0}
BOOTSTRAP_TIMEOUT=${BOOTSTRAP_TIMEOUT:-180}
BOOTSTRAP_INTERVAL=${BOOTSTRAP_INTERVAL:-3}

log_info "Role: $ROLE"
log_info "Port range: $PORT_RANGE"

ensure_server_config() {
    mkdir -p /etc/rancher/k3s
    if [ ! -f /etc/rancher/k3s/config.yaml ]; then
        log_info "Creating /etc/rancher/k3s/config.yaml"
        cat <<EOF > /etc/rancher/k3s/config.yaml
write-kubeconfig-mode: "0644"
node-ip: $(ip -4 addr show | awk '/inet / {print $2}' | head -n1 | cut -d/ -f1)
node-port-range: $PORT_RANGE
EOF
    fi
}

sync_kubeconfig() {
    if [ ! -f /etc/rancher/k3s/k3s.yaml ]; then
        return 1
    fi

    mkdir -p /root/.kube
    install -m 0600 /etc/rancher/k3s/k3s.yaml /root/.kube/config
    log_info "kubeconfig synced to /root/.kube/config"
    return 0
}

if [ "$ROLE" = "server" ]; then
    ensure_server_config
    sync_kubeconfig || true

    if [ "$BOOTSTRAP_ONLY" = "1" ]; then
        log_info "Bootstrap mode enabled, starting k3s server to generate kubeconfig"
        /usr/local/bin/k3s server --https-listen-port "$API_PORT" --disable traefik &
        K3S_PID=$!

        trap 'kill "$K3S_PID" 2>/dev/null || true' INT TERM
        trap 'kill "$K3S_PID" 2>/dev/null || true' EXIT

        elapsed=0
        generated=0
        while [ "$elapsed" -lt "$BOOTSTRAP_TIMEOUT" ]; do
            if sync_kubeconfig; then
                generated=1
                break
            fi

            if ! kill -0 "$K3S_PID" 2>/dev/null; then
                log_error "k3s server exited before kubeconfig was generated"
                wait "$K3S_PID" || true
                exit 1
            fi

            sleep "$BOOTSTRAP_INTERVAL"
            elapsed=$((elapsed + BOOTSTRAP_INTERVAL))
        done

        if [ "$generated" -ne 1 ]; then
            log_error "kubeconfig not generated after ${BOOTSTRAP_TIMEOUT}s"
            kill "$K3S_PID" 2>/dev/null || true
            wait "$K3S_PID" || true
            exit 1
        fi

        log_info "kubeconfig generated successfully"
        kill "$K3S_PID" 2>/dev/null || true
        wait "$K3S_PID" || true
        trap - INT TERM EXIT
        exit 0
    fi

    log_info "Starting k3s server on port $API_PORT"
    exec /usr/local/bin/k3s server --https-listen-port "$API_PORT" --disable traefik
else
    if [ -z "$K3S_URL" ]; then
        log_error "K3S_URL environment variable is required for agent role."
        exit 1
    fi
    log_info "Starting k3s agent targeting $K3S_URL"
    exec /usr/local/bin/k3s agent --server "$K3S_URL"
fi
