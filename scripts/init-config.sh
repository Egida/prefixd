#!/bin/sh
set -eu

# These paths are named volumes, never a bind mount of the operator's checkout.
for directory in /etc/prefixd /data /run/rustbgpd; do
    mkdir -p "$directory"
    chown -hR 999:999 "$directory"
done
chmod 0700 /etc/prefixd /data /run/rustbgpd

for source in /usr/local/share/prefixd/configs/*.yaml; do
    name=${source##*/}
    # The profile mounts its selected main configuration read-only.
    case "$name" in prefixd*.yaml) continue ;; esac
    destination=/etc/prefixd/$name
    if [ ! -e "$destination" ] && [ ! -L "$destination" ]; then
        install -m 0600 -o 999 -g 999 "$source" "$destination"
    fi
done
