#!/bin/sh
# Mint the lab CA and the two server certificates. The CA private key is
# created under /tmp and removed before this process exits.
set -eu

# Refuse rootful containers (initial user namespace maps all 4294967295 UIDs at 0 -> 0).
if [ -r /proc/self/uid_map ] && awk '$1 == 0 && $2 == 0 && $3 == 4294967295 { exit 0 } END { exit 1 }' /proc/self/uid_map; then
    echo "[X] Refusing to start in a rootful container (host root user namespace detected)." >&2
    echo "    Run this lab only with rootless Podman via: bash scripts/testing/bitcart-lab/paylab.sh up" >&2
    exit 1
fi

if [ -f /ca-public/ca.crt ] && [ -f /ca-public/ca-bundle.crt ] \
    && [ -f /tls-arkfile/arkfile.crt ] && [ -f /tls-arkfile/arkfile.key ] \
    && [ -f /tls-bitcart/bitcart.crt ] && [ -f /tls-bitcart/bitcart.key ]; then
    chown 10001:10001 /tls-arkfile/arkfile.key
    chmod 0400 /tls-arkfile/arkfile.key /tls-bitcart/bitcart.key
    echo "lab certificates already present"
    exit 0
fi

apk add --no-cache openssl ca-certificates >/dev/null

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

cat > "$workdir/ca.cnf" <<'EOF'
[req]
distinguished_name=dn
x509_extensions=v3_ca
prompt=no
[dn]
CN=Arkfile paylab CA
[v3_ca]
basicConstraints=critical,CA:true
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
nameConstraints=critical,permitted;DNS:arkfile.lab,permitted;DNS:bitcart.lab,permitted;DNS:localhost,permitted;IP:127.0.0.1/255.255.255.255
EOF

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$workdir/ca.key" -out "$workdir/ca.crt" \
    -days 825 -config "$workdir/ca.cnf" -extensions v3_ca

issue() {
    name=$1
    cn=$2
    san=$3
    outdir=$4
    key_uid=$5
    key_gid=$6
    cat > "$workdir/${name}.cnf" <<EOF
[req]
distinguished_name=dn
req_extensions=v3_req
prompt=no
[dn]
CN=${cn}
[v3_req]
subjectAltName=${san}
basicConstraints=CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
    openssl req -newkey rsa:2048 -nodes \
        -keyout "$workdir/${name}.key" -out "$workdir/${name}.csr" \
        -config "$workdir/${name}.cnf"
    openssl x509 -req -in "$workdir/${name}.csr" \
        -CA "$workdir/ca.crt" -CAkey "$workdir/ca.key" -CAcreateserial \
        -out "$workdir/${name}.crt" -days 825 \
        -extfile "$workdir/${name}.cnf" -extensions v3_req
    install -m 0644 "$workdir/${name}.crt" "${outdir}/${name}.crt"
    install -m 0400 "$workdir/${name}.key" "${outdir}/${name}.key"
    chown "${key_uid}:${key_gid}" "${outdir}/${name}.key"
}

# arkfile drops privileges to UID/GID 10001 before reading /tls/arkfile.key;
# bitcart-proxy runs Caddy as container UID 0.
issue arkfile arkfile.lab "DNS:arkfile.lab,DNS:localhost,IP:127.0.0.1" /tls-arkfile 10001 10001
issue bitcart bitcart.lab "DNS:bitcart.lab,DNS:localhost,IP:127.0.0.1" /tls-bitcart 0 0

install -m 0644 "$workdir/ca.crt" /ca-public/ca.crt
cat /etc/ssl/certs/ca-certificates.crt /ca-public/ca.crt > /ca-public/ca-bundle.crt
chmod 0644 /ca-public/ca-bundle.crt

rm -f "$workdir/ca.key"
echo "lab certificates written"
