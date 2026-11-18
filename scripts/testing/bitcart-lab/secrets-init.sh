#!/bin/sh
# Create lab credentials once. Later starts keep the same files until the
# lab-config volume is removed.
set -eu

# Refuse rootful containers (initial user namespace maps all 4294967295 UIDs at 0 -> 0).
if [ -r /proc/self/uid_map ] && awk '$1 == 0 && $2 == 0 && $3 == 4294967295 { exit 0 } END { exit 1 }' /proc/self/uid_map; then
    echo "[X] Refusing to start in a rootful container (host root user namespace detected)." >&2
    echo "    Run this lab only with rootless Podman via: bash scripts/testing/bitcart-lab/paylab.sh up" >&2
    exit 1
fi

if [ -f /lab-config/generated.env ] && [ -f /lab-config/rqlite-auth.json ] && [ -f /lab-config/seaweedfs-s3.json ]; then
    chmod 0600 /lab-config/generated.env
    chmod 0644 /lab-config/rqlite-auth.json /lab-config/seaweedfs-s3.json
    echo "lab secrets already present"
    exit 0
fi

apk add --no-cache openssl >/dev/null

rqlite_password=$(openssl rand -hex 24)
s3_secret=$(openssl rand -hex 24)
master_key=$(openssl rand -hex 32)

umask 077
cat > /lab-config/generated.env <<EOF
RQLITE_PASSWORD=${rqlite_password}
STORAGE_1_SECRET_KEY=${s3_secret}
ARKFILE_MASTER_KEY=${master_key}
EOF
chmod 0600 /lab-config/generated.env

# rqlite and seaweedfs drop privileges inside their containers and mount
# lab-config read-only, while generated.env and bitcart.env stay 0600 (read
# only by entrypoint-arkfile.sh before privilege drop).
cat > /lab-config/rqlite-auth.json <<EOF
[
  {
    "username": "lab-user",
    "password": "${rqlite_password}",
    "perms": ["all"]
  }
]
EOF
chmod 0644 /lab-config/rqlite-auth.json

cat > /lab-config/seaweedfs-s3.json <<EOF
{
  "identities": [
    {
      "name": "arkfile-paylab",
      "credentials": [
        {
          "accessKey": "arkfile-paylab",
          "secretKey": "${s3_secret}"
        }
      ],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}
EOF
chmod 0644 /lab-config/seaweedfs-s3.json
echo "lab secrets written"
