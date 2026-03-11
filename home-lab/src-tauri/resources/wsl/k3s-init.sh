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
CONTAINERD_STREAM_PORT=${CONTAINERD_STREAM_PORT:-}
CONTAINERD_STREAM_ADDRESS=${CONTAINERD_STREAM_ADDRESS:-127.0.0.1}
CONTAINERD_STREAM_PATCH_TIMEOUT=${CONTAINERD_STREAM_PATCH_TIMEOUT:-30}
K3S_LB_SERVER_PORT=${K3S_LB_SERVER_PORT:-}
K3S_KUBELET_PORT=${K3S_KUBELET_PORT:-}
K3S_KUBELET_HEALTHZ_PORT=${K3S_KUBELET_HEALTHZ_PORT:-}
K3S_KUBE_CONTROLLER_MANAGER_SECURE_PORT=${K3S_KUBE_CONTROLLER_MANAGER_SECURE_PORT:-}
K3S_KUBE_CLOUD_CONTROLLER_MANAGER_SECURE_PORT=${K3S_KUBE_CLOUD_CONTROLLER_MANAGER_SECURE_PORT:-}
K3S_KUBE_SCHEDULER_SECURE_PORT=${K3S_KUBE_SCHEDULER_SECURE_PORT:-}
K3S_TLS_SANS=${K3S_TLS_SANS:-}
K3S_RUNTIME_BIN_DIR=${K3S_RUNTIME_BIN_DIR:-/var/lib/rancher/k3s/data/current/bin}
K3S_RUNTIME_AUX_BIN_DIR=${K3S_RUNTIME_AUX_BIN_DIR:-$K3S_RUNTIME_BIN_DIR/aux}
CONTAINERD_STREAM_PATCH_PID=

log_info "Role: $ROLE"
log_info "Port range: $PORT_RANGE"
log_info "Traefik enabled: $ENABLE_TRAEFIK"
if [ -n "$K3S_LB_SERVER_PORT" ]; then
    log_info "Local k3s port plan: lb=$K3S_LB_SERVER_PORT kubelet=$K3S_KUBELET_PORT kubelet-healthz=$K3S_KUBELET_HEALTHZ_PORT controller-manager=$K3S_KUBE_CONTROLLER_MANAGER_SECURE_PORT cloud-controller-manager=$K3S_KUBE_CLOUD_CONTROLLER_MANAGER_SECURE_PORT scheduler=$K3S_KUBE_SCHEDULER_SECURE_PORT"
fi

LOCK_HELD=0
cleanup_lock() {
    if [ "$LOCK_HELD" = "1" ] && [ -d "$K3S_LOCK_DIR" ]; then
        rm -rf "$K3S_LOCK_DIR"
    fi
}

lock_pid_is_k3s_init() {
    candidate_pid="$1"
    if [ -z "$candidate_pid" ] || [ ! -r "/proc/$candidate_pid/cmdline" ]; then
        return 1
    fi

    candidate_cmdline=$(tr '\000' ' ' < "/proc/$candidate_pid/cmdline" 2>/dev/null || true)
    case "$candidate_cmdline" in
        "sh /usr/local/bin/k3s-init.sh"*|"/bin/sh /usr/local/bin/k3s-init.sh"*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
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
        if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null && lock_pid_is_k3s_init "$lock_pid"; then
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
    desired_config=$(mktemp)
    {
    cat <<EOF
write-kubeconfig-mode: "0644"
node-ip: $NODE_IP
https-listen-port: $API_PORT
service-node-port-range: $PORT_RANGE
EOF
    if [ -n "$K3S_TLS_SANS" ]; then
        printf '%s\n' "tls-san:"
        old_ifs=$IFS
        IFS=','
        set -- $K3S_TLS_SANS
        IFS=$old_ifs
        for san in "$@"; do
            san_trimmed=$(printf '%s' "$san" | tr -d '[:space:]')
            if [ -n "$san_trimmed" ]; then
                printf '  - %s\n' "$san_trimmed"
            fi
        done
    fi
    } > "$desired_config"

    if [ ! -f /etc/rancher/k3s/config.yaml ] || ! cmp -s "$desired_config" /etc/rancher/k3s/config.yaml; then
        log_info "Writing /etc/rancher/k3s/config.yaml with node-ip $NODE_IP and api port $API_PORT"
        mv "$desired_config" /etc/rancher/k3s/config.yaml
    else
        rm -f "$desired_config"
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

wait_for_kubeconfig_sync() {
    elapsed=0
    while [ "$elapsed" -lt "$BOOTSTRAP_TIMEOUT" ]; do
        if sync_kubeconfig; then
            return 0
        fi

        sleep "$BOOTSTRAP_INTERVAL"
        elapsed=$((elapsed + BOOTSTRAP_INTERVAL))
    done

    return 1
}

rewrite_internal_server_kubeconfigs() {
    if [ -z "$API_PORT" ]; then
        return 0
    fi

    for kubeconfig in /var/lib/rancher/k3s/server/cred/*.kubeconfig; do
        [ -f "$kubeconfig" ] || continue
        sed -i "s#server: https://127.0.0.1:[0-9][0-9]*#server: https://127.0.0.1:$API_PORT#" "$kubeconfig" 2>/dev/null || true
    done
}

start_containerd_stream_patch_watcher() {
    if [ -z "$CONTAINERD_STREAM_PORT" ]; then
        return 0
    fi

    (
        config_file="/var/lib/rancher/k3s/agent/etc/containerd/config.toml"
        deadline=$(( $(date +%s) + CONTAINERD_STREAM_PATCH_TIMEOUT ))

        while [ ! -f "$config_file" ]; do
            if [ "$(date +%s)" -ge "$deadline" ]; then
                log_error "containerd config not generated after ${CONTAINERD_STREAM_PATCH_TIMEOUT}s"
                exit 0
            fi
            sleep 0.05
        done

        while [ -f "$config_file" ]; do
            sed -i "s#^  stream_server_address = .*#  stream_server_address = \"$CONTAINERD_STREAM_ADDRESS\"#" "$config_file" 2>/dev/null || true
            sed -i "s#^  stream_server_port = .*#  stream_server_port = \"$CONTAINERD_STREAM_PORT\"#" "$config_file" 2>/dev/null || true
            sleep 0.05
        done
    ) &
    CONTAINERD_STREAM_PATCH_PID=$!
}

stop_containerd_stream_patch_watcher() {
    if [ -n "$CONTAINERD_STREAM_PATCH_PID" ] && kill -0 "$CONTAINERD_STREAM_PATCH_PID" 2>/dev/null; then
        kill "$CONTAINERD_STREAM_PATCH_PID" 2>/dev/null || true
        wait "$CONTAINERD_STREAM_PATCH_PID" 2>/dev/null || true
    fi
    CONTAINERD_STREAM_PATCH_PID=
}

ensure_k3s_runtime_path() {
    case ":$PATH:" in
        *":$K3S_RUNTIME_AUX_BIN_DIR:"*) ;;
        *) PATH="$K3S_RUNTIME_AUX_BIN_DIR:$PATH" ;;
    esac
    case ":$PATH:" in
        *":$K3S_RUNTIME_BIN_DIR:"*) ;;
        *) PATH="$K3S_RUNTIME_BIN_DIR:$PATH" ;;
    esac
    export PATH
}

run_k3s_server() {
    start_containerd_stream_patch_watcher
    ensure_k3s_runtime_path
    set -- /usr/local/bin/k3s server --https-listen-port "$API_PORT"

    if [ -n "$K3S_LB_SERVER_PORT" ]; then
        set -- "$@" --lb-server-port "$K3S_LB_SERVER_PORT"
    fi
    if [ -n "$K3S_KUBELET_PORT" ]; then
        set -- "$@" --kubelet-arg "port=$K3S_KUBELET_PORT"
    fi
    if [ -n "$K3S_KUBELET_HEALTHZ_PORT" ]; then
        set -- "$@" --kubelet-arg "healthz-port=$K3S_KUBELET_HEALTHZ_PORT"
    fi
    if [ -n "$K3S_KUBE_CONTROLLER_MANAGER_SECURE_PORT" ]; then
        set -- "$@" --kube-controller-manager-arg "secure-port=$K3S_KUBE_CONTROLLER_MANAGER_SECURE_PORT"
    fi
    if [ -n "$K3S_KUBE_CLOUD_CONTROLLER_MANAGER_SECURE_PORT" ]; then
        set -- "$@" --kube-cloud-controller-manager-arg "secure-port=$K3S_KUBE_CLOUD_CONTROLLER_MANAGER_SECURE_PORT"
    fi
    if [ -n "$K3S_KUBE_SCHEDULER_SECURE_PORT" ]; then
        set -- "$@" --kube-scheduler-arg "secure-port=$K3S_KUBE_SCHEDULER_SECURE_PORT"
    fi

    if [ "$ENABLE_TRAEFIK" = "1" ]; then
        log_info "Starting k3s with packaged Traefik (v3 on recent K3s)."
    else
        log_info "Starting k3s with Traefik disabled."
        set -- "$@" --disable traefik
    fi

    set +e
    "$@"
    rc=$?
    set -e
    stop_containerd_stream_patch_watcher
    return "$rc"
}

run_k3s_server_supervised() {
    delay=$K3S_RESTART_BASE_DELAY
    while true; do
        started_at=$(date +%s)
        # k3s can exit non-zero during transient failures; don't let `set -e`
        # kill the supervisor loop before we can apply restart policy.
        set +e
        run_k3s_server
        rc=$?
        set -e
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
    rewrite_internal_server_kubeconfigs
    sync_kubeconfig || true

    if [ "$BOOTSTRAP_ONLY" = "1" ]; then
        if pgrep -f '^/usr/local/bin/k3s server( |$)' >/dev/null 2>&1; then
            log_info "Bootstrap mode enabled, reusing existing k3s server to sync kubeconfig"
            if wait_for_kubeconfig_sync; then
                log_info "kubeconfig generated successfully from existing k3s server"
                exit 0
            fi

            log_error "kubeconfig not generated after ${BOOTSTRAP_TIMEOUT}s while reusing existing k3s server"
            exit 1
        fi

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
