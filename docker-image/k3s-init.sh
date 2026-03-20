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
K3S_INGRESS_HTTP_PORT=${K3S_INGRESS_HTTP_PORT:-}
K3S_INGRESS_HTTPS_PORT=${K3S_INGRESS_HTTPS_PORT:-}
K3S_GIT_SSH_PORT=${K3S_GIT_SSH_PORT:-}
ENABLE_NVIDIA_TOOLKIT=${ENABLE_NVIDIA_TOOLKIT:-0}
K3S_RUNTIME_BIN_DIR=${K3S_RUNTIME_BIN_DIR:-/var/lib/rancher/k3s/data/current/bin}
K3S_RUNTIME_AUX_BIN_DIR=${K3S_RUNTIME_AUX_BIN_DIR:-$K3S_RUNTIME_BIN_DIR/aux}
NVIDIA_CONTAINERD_TEMPLATE_SOURCE=${NVIDIA_CONTAINERD_TEMPLATE_SOURCE:-/usr/share/home-lab/nvidia/config-v3.toml.tmpl}
NVIDIA_CONTAINERD_TEMPLATE_TARGET=${NVIDIA_CONTAINERD_TEMPLATE_TARGET:-/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl}
CONTAINERD_STREAM_PATCH_PID=

log_info "Role: $ROLE"
log_info "Port range: $PORT_RANGE"
log_info "Traefik enabled: $ENABLE_TRAEFIK"
if [ -n "$K3S_LB_SERVER_PORT" ]; then
    log_info "Local k3s port plan: lb=$K3S_LB_SERVER_PORT kubelet=$K3S_KUBELET_PORT kubelet-healthz=$K3S_KUBELET_HEALTHZ_PORT controller-manager=$K3S_KUBE_CONTROLLER_MANAGER_SECURE_PORT cloud-controller-manager=$K3S_KUBE_CLOUD_CONTROLLER_MANAGER_SECURE_PORT scheduler=$K3S_KUBE_SCHEDULER_SECURE_PORT"
fi
if [ -n "$K3S_INGRESS_HTTP_PORT" ] || [ -n "$K3S_INGRESS_HTTPS_PORT" ] || [ -n "$K3S_GIT_SSH_PORT" ]; then
    log_info "Ingress port plan: http=$K3S_INGRESS_HTTP_PORT https=$K3S_INGRESS_HTTPS_PORT git-ssh=$K3S_GIT_SSH_PORT"
fi
if [ "$ENABLE_NVIDIA_TOOLKIT" = "1" ]; then
    log_info "NVIDIA runtime requested for this instance."
fi

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

ensure_server_config() {
    mkdir -p /etc/rancher/k3s
    desired_config=$(mktemp)
    cat <<EOF > "$desired_config"
write-kubeconfig-mode: "0644"
https-listen-port: $API_PORT
service-node-port-range: $PORT_RANGE
EOF

    if [ ! -f /etc/rancher/k3s/config.yaml ] || ! cmp -s "$desired_config" /etc/rancher/k3s/config.yaml; then
        log_info "Writing /etc/rancher/k3s/config.yaml with api port $API_PORT"
        mv "$desired_config" /etc/rancher/k3s/config.yaml
    else
        rm -f "$desired_config"
    fi
}

ensure_traefik_config() {
    if [ "$ENABLE_TRAEFIK" != "1" ]; then
        return 0
    fi
    if [ -z "$K3S_INGRESS_HTTP_PORT" ] || [ -z "$K3S_INGRESS_HTTPS_PORT" ]; then
        return 0
    fi

    mkdir -p /var/lib/rancher/k3s/server/manifests
    desired_config=$(mktemp)
    cat <<EOF > "$desired_config"
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    # Keep Traefik internal to the cluster; localhost exposure is handled by
    # the explicit loopback bridge below.
    service:
      type: ClusterIP
    ports:
      web:
        expose:
          default: true
        exposedPort: $K3S_INGRESS_HTTP_PORT
      websecure:
        expose:
          default: true
        exposedPort: $K3S_INGRESS_HTTPS_PORT
        tls:
          enabled: true
    additionalArguments:
      - --entryPoints.web.http.redirections.entryPoint.to=websecure
      - --entryPoints.web.http.redirections.entryPoint.scheme=https
      - --entryPoints.web.http.redirections.entryPoint.permanent=true
EOF

    if [ ! -f /var/lib/rancher/k3s/server/manifests/traefik-config.yaml ] || ! cmp -s "$desired_config" /var/lib/rancher/k3s/server/manifests/traefik-config.yaml; then
        log_info "Writing Traefik HelmChartConfig with http=$K3S_INGRESS_HTTP_PORT https=$K3S_INGRESS_HTTPS_PORT"
        mv "$desired_config" /var/lib/rancher/k3s/server/manifests/traefik-config.yaml
    else
        rm -f "$desired_config"
    fi
}

write_traefik_loopback_forwarder() {
    listen_port="$1"
    service_port="$2"
    wrapper="/usr/local/bin/traefik-loopback-$listen_port.sh"
    cat <<EOF > "$wrapper"
#!/bin/sh
set -eu
child_pid=
cleanup() {
    if [ -n "\$child_pid" ]; then
        kill "\$child_pid" 2>/dev/null || true
        wait "\$child_pid" 2>/dev/null || true
    fi
}
trap cleanup INT TERM EXIT
while true; do
    if ! KUBECONFIG=/etc/rancher/k3s/k3s.yaml /usr/local/bin/k3s kubectl -n kube-system get service traefik >/dev/null 2>&1; then
        sleep 1
        continue
    fi
    KUBECONFIG=/etc/rancher/k3s/k3s.yaml /usr/local/bin/k3s kubectl -n kube-system port-forward --address 127.0.0.1 service/traefik $listen_port:$service_port &
    child_pid=\$!
    wait "\$child_pid" || true
    child_pid=
    sleep 1
done
EOF
    chmod 0755 "$wrapper"
    echo "$wrapper"
}

start_traefik_loopback_listener() {
    listen_port="$1"
    service_port="$2"

    if [ -z "$listen_port" ]; then
        return 0
    fi

    wrapper=$(write_traefik_loopback_forwarder "$listen_port" "$service_port")
    log_file="/var/log/traefik-loopback-$listen_port.log"
    cmd="sh $wrapper"

    if pgrep -f "$cmd" >/dev/null 2>&1; then
        return 0
    fi

    pkill -f "kubectl -n kube-system port-forward --address 127.0.0.1 service/traefik $listen_port:$service_port" 2>/dev/null || true
    pkill -f "nc -lk .* -p $listen_port " 2>/dev/null || true
    pkill -f "$cmd" 2>/dev/null || true
    nohup sh -c "exec $cmd" >> "$log_file" 2>&1 &
}

ensure_traefik_loopback_proxy() {
    if [ "$ENABLE_TRAEFIK" != "1" ]; then
        return 0
    fi

    mkdir -p /var/log
    if [ -n "$K3S_INGRESS_HTTP_PORT" ]; then
        start_traefik_loopback_listener "$K3S_INGRESS_HTTP_PORT" "$K3S_INGRESS_HTTP_PORT"
    fi
    if [ -n "$K3S_INGRESS_HTTPS_PORT" ]; then
        start_traefik_loopback_listener "$K3S_INGRESS_HTTPS_PORT" "$K3S_INGRESS_HTTPS_PORT"
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

remove_nvidia_containerd_templates() {
    rm -f /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl
    rm -f /var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl
}

ensure_nvidia_toolkit() {
    if [ "$ENABLE_NVIDIA_TOOLKIT" != "1" ]; then
        remove_nvidia_containerd_templates
        return 0
    fi

    if [ ! -x /usr/local/bin/nvidia-container-runtime ]; then
        log_error "NVIDIA runtime requested but /usr/local/bin/nvidia-container-runtime is missing."
        return 0
    fi

    if [ ! -f "$NVIDIA_CONTAINERD_TEMPLATE_SOURCE" ]; then
        log_error "NVIDIA runtime requested but template source is missing: $NVIDIA_CONTAINERD_TEMPLATE_SOURCE"
        return 0
    fi

    mkdir -p "$(dirname "$NVIDIA_CONTAINERD_TEMPLATE_TARGET")"
    if [ ! -f "$NVIDIA_CONTAINERD_TEMPLATE_TARGET" ] || ! cmp -s "$NVIDIA_CONTAINERD_TEMPLATE_SOURCE" "$NVIDIA_CONTAINERD_TEMPLATE_TARGET"; then
        cp "$NVIDIA_CONTAINERD_TEMPLATE_SOURCE" "$NVIDIA_CONTAINERD_TEMPLATE_TARGET"
    fi

    if [ -d /usr/lib/wsl/lib ]; then
        case ":$PATH:" in
            *":/usr/lib/wsl/lib:"*) ;;
            *) PATH="/usr/lib/wsl/lib:$PATH" ;;
        esac
        export PATH
    fi

    if [ -x /usr/local/bin/nvidia-smi ]; then
        /usr/local/bin/nvidia-smi >/dev/null 2>&1 || true
    fi

    log_info "NVIDIA container runtime prepared for k3s/containerd."
}

run_k3s_server() {
    ensure_nvidia_toolkit
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
    ensure_traefik_config
    ensure_traefik_loopback_proxy
    rewrite_internal_server_kubeconfigs
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
