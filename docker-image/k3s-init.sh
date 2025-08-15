#!/bin/sh
set -e

# Charger les variables si fichier présent
[ -f /etc/k3s-env ] && . /etc/k3s-env

# Mount all filesystems defined in /etc/fstab
/usr/local/bin/mount_all.sh

ROLE=${WSL_ROLE:-server}
PORT_RANGE=${PORT_RANGE:-6443-6550}
API_PORT=$(echo "$PORT_RANGE" | cut -d"-" -f1)

echo "[INFO] Rôle: $ROLE"
echo "[INFO] Plage de ports: $PORT_RANGE"

# Préparer /etc/rancher/k3s/config.yaml si absent
mkdir -p /etc/rancher/k3s
if [ ! -f /etc/rancher/k3s/config.yaml ]; then
  echo "[INFO] Génération de /etc/rancher/k3s/config.yaml"
  cat <<EOF > /etc/rancher/k3s/config.yaml
write-kubeconfig-mode: "0644"
node-ip: $(ip -4 addr show | awk '/inet / {print $2}' | head -n1 | cut -d/ -f1)
node-port-range: $PORT_RANGE
EOF
fi

# Créer le kubeconfig dans ~/.kube si absent
mkdir -p /root/.kube
if [ ! -f /root/.kube/config ] && [ -f /etc/rancher/k3s/k3s.yaml ]; then
  cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
  chmod 600 /root/.kube/config
  echo "[INFO] kubeconfig créé dans /root/.kube/config"
fi

# Lancer K3s
if [ "$ROLE" = "server" ]; then
    echo "[INFO] Démarrage de K3s server sur le port $API_PORT"
    exec /usr/local/bin/k3s server --https-listen-port "$API_PORT" --disable traefik
else
    if [ -z "$K3S_URL" ]; then
        echo "[ERREUR] Variable K3S_URL manquante pour l'agent."
        exit 1
    fi
    echo "[INFO] Démarrage de K3s agent vers $K3S_URL"
    exec /usr/local/bin/k3s agent --server "$K3S_URL"
fi
