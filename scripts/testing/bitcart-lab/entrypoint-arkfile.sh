#!/bin/sh
# Prepare the writable key directory, then start Arkfile as the arkfile user.
set -eu

# Refuse rootful containers (initial user namespace maps all 4294967295 UIDs at 0 -> 0).
if [ -r /proc/self/uid_map ] && awk '$1 == 0 && $2 == 0 && $3 == 4294967295 { exit 0 } END { exit 1 }' /proc/self/uid_map; then
    echo "[X] Refusing to start in a rootful container (host root user namespace detected)." >&2
    echo "    Run this lab only with rootless Podman via: bash scripts/testing/bitcart-lab/paylab.sh up" >&2
    exit 1
fi

mkdir -p /opt/arkfile/etc/keys /opt/arkfile/var/home /opt/arkfile/var/log /opt/arkfile/var/lib /opt/arkfile/var/cache
chmod 0700 /opt/arkfile/etc/keys

if [ ! -s /opt/arkfile/etc/keys/user-secret-master.bin ]; then
    dd if=/dev/urandom of=/opt/arkfile/etc/keys/user-secret-master.bin bs=32 count=1 status=none
    chmod 0400 /opt/arkfile/etc/keys/user-secret-master.bin
fi
chown -R arkfile:arkfile /opt/arkfile/etc/keys /opt/arkfile/var

i=0
while [ ! -f /lab-config/generated.env ] || [ ! -f /lab-config/bitcart.env ]; do
    i=$((i + 1))
    if [ "$i" -gt 180 ]; then
        echo "timed out waiting for lab secrets and the Bitcart token" >&2
        exit 1
    fi
    sleep 2
done

set -a
# shellcheck disable=SC1091
. /lab-config/generated.env
# shellcheck disable=SC1091
. /lab-config/bitcart.env
set +a

cd /opt/arkfile
exec /usr/sbin/runuser -u arkfile -- /opt/arkfile/bin/arkfile
