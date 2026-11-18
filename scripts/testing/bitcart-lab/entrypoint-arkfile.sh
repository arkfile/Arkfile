#!/bin/sh
# Prepare the writable key directory, then start Arkfile as the arkfile user.
set -eu

mkdir -p /opt/arkfile/etc/keys /opt/arkfile/var/home /opt/arkfile/var/log /opt/arkfile/var/lib /opt/arkfile/var/cache

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
exec runuser -u arkfile -- /opt/arkfile/bin/arkfile
