#!/bin/sh
# Create lab credentials once. Later starts keep the same files until the
# lab-config and bitcart-secrets volumes are removed.
set -eu

# Refuse rootful containers (initial user namespace maps all 4294967295 UIDs at 0 -> 0).
if [ -r /proc/self/uid_map ] && awk '$1 == 0 && $2 == 0 && $3 == 4294967295 { exit 0 } END { exit 1 }' /proc/self/uid_map; then
    echo "[X] Refusing to start in a rootful container (host root user namespace detected)." >&2
    echo "    Run this lab only with rootless Podman via: bash scripts/testing/bitcart-lab/paylab.sh up" >&2
    exit 1
fi

need_arkfile=0
if [ ! -f /lab-config/generated.env ] || [ ! -f /lab-config/rqlite-auth.json ] || [ ! -f /lab-config/seaweedfs-s3.json ]; then
    need_arkfile=1
fi

need_merchant=0
if [ ! -f /lab-config/merchant.env ]; then
    need_merchant=1
fi

need_bitcart=0
if [ ! -f /bitcart-secrets/pg-password ] || [ ! -f /bitcart-secrets/btc-rpc.env ] || [ ! -f /bitcart-secrets/xmr-rpc.env ] || [ ! -f /bitcart-secrets/backend-secrets.env ]; then
    need_bitcart=1
fi

if [ "$need_arkfile" -eq 0 ] && [ "$need_merchant" -eq 0 ] && [ "$need_bitcart" -eq 0 ]; then
    chmod 0600 /lab-config/generated.env /lab-config/merchant.env
    chmod 0644 /lab-config/rqlite-auth.json /lab-config/seaweedfs-s3.json
    chmod 0644 /bitcart-secrets/pg-password /bitcart-secrets/btc-rpc.env /bitcart-secrets/xmr-rpc.env /bitcart-secrets/backend-secrets.env
    echo "lab secrets already present"
    exit 0
fi

apk add --no-cache openssl >/dev/null

if [ "$need_arkfile" -eq 1 ]; then
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
    # lab-config read-only, while generated.env, merchant.env, and bitcart.env
    # stay 0600 (read only before privilege drop or by provision).
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
    echo "arkfile lab secrets written"
fi

if [ "$need_merchant" -eq 1 ]; then
    merchant_password=$(openssl rand -hex 24)
    umask 077
    cat > /lab-config/merchant.env <<EOF
MERCHANT_PASSWORD=${merchant_password}
EOF
    chmod 0600 /lab-config/merchant.env
    echo "bitcart merchant account secret written"
fi

if [ "$need_bitcart" -eq 1 ]; then
    pg_password=$(openssl rand -hex 32)
    btc_pass=$(openssl rand -hex 32)
    xmr_pass=$(openssl rand -hex 32)

    # bitcart-secrets is mounted exclusively into database, bitcoin, monero,
    # backend, and worker (never into arkfile, checkout, admin, proxy, or
    # provision). Files are mode 0644 so non-root postgres and electrum users
    # inside those containers can read them.
    printf '%s' "${pg_password}" > /bitcart-secrets/pg-password
    chmod 0644 /bitcart-secrets/pg-password

    cat > /bitcart-secrets/btc-rpc.env <<EOF
BTC_LOGIN=btc_rpc
BTC_PASSWORD=${btc_pass}
BTC_USER=btc_rpc
BTC_PASS=${btc_pass}
EOF
    chmod 0644 /bitcart-secrets/btc-rpc.env

    cat > /bitcart-secrets/xmr-rpc.env <<EOF
XMR_LOGIN=xmr_rpc
XMR_PASSWORD=${xmr_pass}
XMR_USER=xmr_rpc
XMR_PASS=${xmr_pass}
EOF
    chmod 0644 /bitcart-secrets/xmr-rpc.env

    cat > /bitcart-secrets/backend-secrets.env <<EOF
DB_USER=postgres
DB_PASSWORD=${pg_password}
DB_DATABASE=bitcart
BTC_LOGIN=btc_rpc
BTC_PASSWORD=${btc_pass}
BTC_USER=btc_rpc
BTC_PASS=${btc_pass}
XMR_LOGIN=xmr_rpc
XMR_PASSWORD=${xmr_pass}
XMR_USER=xmr_rpc
XMR_PASS=${xmr_pass}
EOF
    chmod 0644 /bitcart-secrets/backend-secrets.env
    echo "bitcart internal database and daemon RPC secrets written"
fi
