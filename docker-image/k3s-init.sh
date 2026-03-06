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
ENABLE_TRAEFIK=${ENABLE_TRAEFIK:-1}
BOOTSTRAP_ONLY=${BOOTSTRAP_ONLY:-0}
BOOTSTRAP_TIMEOUT=${BOOTSTRAP_TIMEOUT:-180}
BOOTSTRAP_INTERVAL=${BOOTSTRAP_INTERVAL:-3}
K3S_LOCK_DIR=${K3S_LOCK_DIR:-/run/k3s-init.lock}
K3S_RESTART_BASE_DELAY=${K3S_RESTART_BASE_DELAY:-2}
K3S_RESTART_MAX_DELAY=${K3S_RESTART_MAX_DELAY:-30}
K3S_MIN_UPTIME=${K3S_MIN_UPTIME:-20}

log_info "Role: $ROLE"
log_info "Port range: $PORT_RANGE"
log_info "Traefik enabled: $ENABLE_TRAEFIK"

LOCK_HELD=0
cleanup_lock() {
    if [ "$LOCK_HELD" = "1" ] && [ -d "$K3S_LOCK_DIR" ]; then
        rm -rf "$K3S_LOCK_DIR"
    fi
}

acquire_lock_or_exit() {
    if mkdir "$K3S_LOCK_DIR" 2>/dev/null; then
        LOCK_HELD=1
        echo "$$" > "$K3S_LOCK_DIR/pid"
        trap cleanup_lock EXIT INT TERM
        return 0
    fi

    if [ -f "$K3S_LOCK_DIR/pid" ]; then
        lock_pid=$(cat "$K3S_LOCK_DIR/pid" 2>/dev/null || true)
        if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
            log_info "Another k3s-init instance is already running (pid=$lock_pid), exiting."
            exit 0
        fi
    fi

    log_info "Removing stale k3s-init lock and retrying."
    rm -rf "$K3S_LOCK_DIR"
    if mkdir "$K3S_LOCK_DIR" 2>/dev/null; then
        LOCK_HELD=1
        echo "$$" > "$K3S_LOCK_DIR/pid"
        trap cleanup_lock EXIT INT TERM
        return 0
    fi

    log_error "Unable to acquire k3s-init lock at $K3S_LOCK_DIR."
    exit 1
}

detect_node_ip() {
    # Prefer the primary WSL interface and always ignore loopback/link-local.
    line=$(ip -4 addr show dev eth0 2>/dev/null | grep 'inet ' | head -n1 || true)
    if [ -n "$line" ]; then
        candidate=$(echo "$line" | tr -s ' ' | cut -d' ' -f3 | cut -d/ -f1)
        case "$candidate" in
            127.*|169.254.*|'')
                ;;
            *)
                echo "$candidate"
                return 0
                ;;
        esac
    fi

    ip -4 addr show 2>/dev/null \
        | grep 'inet ' \
        | tr -s ' ' \
        | cut -d' ' -f3 \
        | cut -d/ -f1 \
        | while IFS= read -r candidate; do
            case "$candidate" in
                127.*|169.254.*|'')
                    ;;
                *)
                    echo "$candidate"
                    break
                    ;;
            esac
        done
}

ensure_server_config() {
    NODE_IP=$(detect_node_ip)
    if [ -z "$NODE_IP" ]; then
        log_error "Unable to determine a non-loopback IPv4 address for node-ip."
        exit 1
    fi

    mkdir -p /etc/rancher/k3s
    if [ ! -f /etc/rancher/k3s/config.yaml ]; then
        log_info "Creating /etc/rancher/k3s/config.yaml with node-ip $NODE_IP"
        cat <<EOF > /etc/rancher/k3s/config.yaml
write-kubeconfig-mode: "0644"
node-ip: $NODE_IP
node-port-range: $PORT_RANGE
EOF
        return
    fi

    CURRENT_NODE_IP=$(grep '^node-ip:' /etc/rancher/k3s/config.yaml 2>/dev/null | head -n1 | cut -d':' -f2 | tr -d '[:space:]')
    if [ -z "$CURRENT_NODE_IP" ]; then
        log_info "Adding node-ip $NODE_IP to /etc/rancher/k3s/config.yaml"
        printf '\nnode-ip: %s\n' "$NODE_IP" >> /etc/rancher/k3s/config.yaml
        return
    fi

    if [ "$CURRENT_NODE_IP" != "$NODE_IP" ]; then
        log_info "Updating node-ip in /etc/rancher/k3s/config.yaml: $CURRENT_NODE_IP -> $NODE_IP"
        sed -i "s/^node-ip:.*/node-ip: $NODE_IP/" /etc/rancher/k3s/config.yaml
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

run_k3s_server() {
    if [ "$ENABLE_TRAEFIK" = "1" ]; then
        log_info "Starting k3s with packaged Traefik (v3 on recent K3s)."
        /usr/local/bin/k3s server --https-listen-port "$API_PORT"
    else
        log_info "Starting k3s with Traefik disabled."
        /usr/local/bin/k3s server --https-listen-port "$API_PORT" --disable traefik
    fi
}

run_k3s_server_supervised() {
    delay=$K3S_RESTART_BASE_DELAY
    while true; do
        started_at=$(date +%s)
        run_k3s_server
        rc=$?
        ended_at=$(date +%s)
        uptime=$((ended_at - started_at))

        # Exit cleanly on explicit stop signals propagated as shell-friendly codes.
        if [ "$rc" -eq 0 ] || [ "$rc" -eq 130 ] || [ "$rc" -eq 143 ]; then
            log_info "k3s server exited with code $rc, stopping supervisor."
            return "$rc"
        fi

        if [ "$uptime" -ge "$K3S_MIN_UPTIME" ]; then
            delay=$K3S_RESTART_BASE_DELAY
        else
            delay=$((delay * 2))
            if [ "$delay" -gt "$K3S_RESTART_MAX_DELAY" ]; then
                delay=$K3S_RESTART_MAX_DELAY
            fi
        fi

        log_error "k3s server exited with code $rc after ${uptime}s, restarting in ${delay}s."
        sleep "$delay"
    done
}

if [ "$ROLE" = "server" ]; then
    acquire_lock_or_exit
    ensure_server_config
    sync_kubeconfig || true

    if [ "$BOOTSTRAP_ONLY" = "1" ]; then
        log_info "Bootstrap mode enabled, starting k3s server to generate kubeconfig"
        run_k3s_server &
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

    log_info "Starting supervised k3s server on port $API_PORT"
    run_k3s_server_supervised
else
    if [ -z "$K3S_URL" ]; then
        log_error "K3S_URL environment variable is required for agent role."
        exit 1
    fi
    log_info "Starting k3s agent targeting $K3S_URL"
    exec /usr/local/bin/k3s agent --server "$K3S_URL"
fi
