#!/bin/sh
set -e

# Mount all filesystems defined in /etc/fstab using busybox mount
[ -f /etc/fstab ] || exit 0

grep -Ev '^\s*#' /etc/fstab | grep -Ev '^\s*$' | while read -r src dst fstype options _; do
    busybox mount -t "$fstype" -o "$options" "$src" "$dst"
done
