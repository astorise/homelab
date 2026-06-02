# WSL rootfs

Ce dossier est empaqueté avec l'installateur Windows. Ajoutez-y l'archive `wsl-rootfs.tar`
produite à partir de l'image `docker-image/` du dépôt (voir `docker build` + `docker export`).
Le script `setup-wsl.ps1` s'appuie sur cette archive pour importer la distribution WSL
"home-lab-k3s" puis injecte automatiquement la dernière version du binaire `k3s`.
L'import n'est plus déclenché pendant l'installation : il est lancé à la demande depuis
l'interface Home Lab (Tauri).

## Multi-node k3s (EXPÉRIMENTAL, opt-in)

Par défaut une instance = un cluster k3s **single-node** (`NODE_COUNT=1`) : comportement
historique, inchangé. En passant `node_count > 1` (paramètre `-NodeCount` de
`setup-wsl.ps1`, champ `node_count` de l'outil MCP `wsl_import_instance`, plafonné à 5),
on obtient un cluster **multi-node dans une seule instance WSL** :

- **node 0 = serveur k3s dans le netns hôte** → l'API reste sur la loopback Windows
  (`https://{name}.wsl:<api_port>`), exactement comme en single-node. Aucun forwarder.
- **nodes 1..N-1 = agents**, chacun dans son propre *network namespace* Linux, relié par
  une paire `veth` à un **bridge privé** `k3s-br0` (`10.50.0.0/24`, passerelle `10.50.0.1`).
  Chaque agent reçoit une IP distincte (`10.50.0.11`, `10.50.0.12`, …) et rejoint le serveur
  sur `https://10.50.0.1:<api_port>` avec le token de `/var/lib/rancher/k3s/server/node-token`.
- **flannel `host-gw`** (pas de VXLAN) car tous les nodes partagent le L2 du bridge.
- Le bridge est **privé à la VM WSL** (non exposé LAN/WAN). Le routage S3 (`s3.wsl`) et
  l'ingress Traefik fonctionnent depuis tous les nodes (MASQUERADE + DNAT dans le netns hôte).

Pourquoi un netns par node : sous WSL2 toutes les distros partagent **un seul namespace
réseau**. Le netns donne à chaque node son propre jeu d'interfaces (`cni0`/`flannel.1`),
ce qu'une simple IP distincte ne suffit pas à fournir.

Dimensionnement : N nodes = N×(kubelet+containerd) dans une VM ; prévoir la RAM/CPU dans
`.wslconfig` en conséquence.

### Variante future (non implémentée) : nodes exposés LAN/VLAN

Pour rendre chaque node joignable sur le LAN réel (voire taggé VLAN), on pourrait attacher
des NIC de vSwitch Hyper-V à la VM WSL via les API HCS/HCN (principe de `WSLAttachSwitch`,
réécrit en Rust dans un service privilégié) puis déplacer chaque NIC dans le netns du node.
Cela vient **par-dessus** le netns-par-node, jamais à la place. Limites : nécessite les
droits admin, un vSwitch Hyper-V pré-créé, et l'attachement ne survit pas au redémarrage de
la VM WSL (à ré-appliquer par le service). Voir la proposition OpenSpec `node-lan-vlan-hcs-hcn`.
