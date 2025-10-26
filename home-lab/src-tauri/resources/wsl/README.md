# WSL rootfs

Ce dossier est empaqueté avec l'installateur Windows. Ajoutez-y l'archive `wsl-rootfs.tar`
produite à partir de l'image `docker-image/` du dépôt (voir `docker build` + `docker export`).
Le script `setup-wsl.ps1` s'appuie sur cette archive pour importer la distribution WSL
"home-lab-k3s" puis injecte automatiquement la dernière version du binaire `k3s`.
L'import n'est plus déclenché pendant l'installation : il est lancé à la demande depuis
l'interface Home Lab (Tauri).
