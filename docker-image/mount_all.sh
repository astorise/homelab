#!/bin/sh
set -e

# Mount all filesystems defined in /etc/fstab using busybox mount
[ -f /etc/fstab ] || exit 0

grep -Ev '^\s*#' /etc/fstab | grep -Ev '^\s*$' | while read -r src dst fstype options _; do
    # Skip empty destinations to avoid bogus mount attempts
    [ -n "$dst" ] || continue

    # Ignore already mounted targets to prevent "resource busy" errors under WSL
    if busybox mountpoint -q "$dst" 2>/dev/null; then
        echo "[INFO] $dst already mounted, skipping."
        continue
    fi

    if ! busybox mount -t "$fstype" -o "$options" "$src" "$dst"; then
        echo "[WARN] Impossible de monter $src sur $dst (type=$fstype options=$options)." >&2
    fi
done
